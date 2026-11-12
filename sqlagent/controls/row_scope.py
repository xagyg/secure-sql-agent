# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Row scope: which ROWS of each table a user may see, enforced in the SQL.
#
# The security policy (security_policy.py) declares scope dimensions -
# territory, salesperson, department - and how each applies to each table:
#
#   column     the table carries the dimension itself
#              (orders: territory_id IN (4, 5))
#   via        a row is in scope when a related row in another table is
#              (an order line when its order is; a customer when it has
#              an order in scope); chains are followed
#   unscoped   the dimension doesn't restrict this table (reference data)
#
# A grant pairs a role with a scope. When a SecurityContext is built, each
# grant's scope is compiled ONCE into a self-contained filter per table
# (compile_grant), and the filters of all the user's grants are combined
# (combine_filters): rows visible under ANY grant, and no filter at all if
# any grant on that table is unrestricted.
#
# At query time apply_row_scope() replaces every reference to a scoped
# table with a filtered version of that table:
#
#     FROM sales.customer c
#  -> FROM (SELECT * FROM sales.customer AS _t WHERE <filter>) AS c
#
# so joins (inner and outer), subqueries, CTEs and each branch of a UNION
# all read only permitted rows, and the query's meaning is otherwise
# unchanged. The result is re-parsed and checked (verify_row_scope): every
# scoped table must sit inside its exact filter, or the query is blocked.
# Anything that goes wrong raises RowScopeError; the caller blocks the
# query rather than running it unfiltered.
#
# The filters are never shown to the LLM: the agent applies them just
# before execution, and the correction and explanation steps see the
# query as the model wrote it.

import re

import sqlglot
from sqlglot import exp

from sqlagent.controls.security_utils import full_table_name


# Alias of the table inside each filtered wrapper, and prefix of the
# aliases used inside a filter's EXISTS subqueries. The leading
# underscore keeps them clear of anything the model writes.
INNER_ALIAS = "_t"
VIA_ALIAS = "_s"

_PLAIN = re.compile(r"[A-Za-z_][A-Za-z0-9_$]*")


class RowScopeError(ValueError):
    """Row scope could not be applied or verified: the query must not run."""


# ---------------------------------------------------------------------------
# Building expressions
# ---------------------------------------------------------------------------

def ident(name):
    """An identifier, quoted only when it can't be written plainly."""
    return exp.Identifier(this=name, quoted=not _PLAIN.fullmatch(name))


def table_expr(full_name, alias=None):
    """exp.Table for "schema.table" (names as the database spells them)."""
    schema, _, name = full_name.partition(".")
    table = exp.Table(this=ident(name), db=ident(schema))
    if alias:
        table.set("alias", exp.TableAlias(this=ident(alias)))
    return table


def _column(alias, name):
    return exp.Column(this=ident(name), table=ident(alias))


def _literal(value):
    if isinstance(value, bool):
        raise RowScopeError(f"scope value {value!r} is not a number or text")
    if isinstance(value, (int, float)):
        return exp.Literal.number(value)
    return exp.Literal.string(str(value))


def _false():
    return exp.EQ(this=exp.Literal.number(1), expression=exp.Literal.number(0))


# ---------------------------------------------------------------------------
# Compiling a grant's scope into per-table filters
# ---------------------------------------------------------------------------

def _dimension_filter(dimension, rules, table, values, alias, depth, seen):
    """
    The filter expression for `table` (lower-case "schema.table") in one
    dimension, with the table under `alias`. `rules` maps lower-case table
    name -> ("column", column) | ("via", parent, {column: parent_column},
    parent as spelled) | ("unscoped",). None means the dimension doesn't restrict the table.
    """
    rule = rules.get(table)
    if rule is None:
        raise RowScopeError(
            f"scope '{dimension}' has no rule for table {table}")
    kind = rule[0]
    if kind == "unscoped":
        return None
    if kind == "column":
        if not values:
            return _false()      # nothing in scope: no rows, never all rows
        return exp.In(this=_column(alias, rule[1]),
                      expressions=[_literal(v) for v in values])
    if kind == "via":
        parent, on, parent_name = rule[1], rule[2], rule[3]
        if not on:
            raise RowScopeError(
                f"scope '{dimension}': {table} via {parent} has no join")
        if parent in seen:
            raise RowScopeError(
                f"scope '{dimension}': 'via' rules form a cycle through {parent}")
        inner = f"{VIA_ALIAS}{depth}"
        parent_filter = _dimension_filter(
            dimension, rules, parent, values, inner, depth + 1, seen | {parent})
        if parent_filter is None:
            raise RowScopeError(
                f"scope '{dimension}': {table} is scoped via {parent}, "
                "which is unscoped - nothing would restrict it")
        conditions = [
            exp.EQ(this=_column(inner, parent_col), expression=_column(alias, col))
            for col, parent_col in on.items()
        ] + [parent_filter]
        where = conditions[0]
        for condition in conditions[1:]:
            where = exp.And(this=where, expression=condition)
        subquery = (exp.select(exp.Literal.number(1))
                    .from_(table_expr(parent_name, inner))
                    .where(where))
        return exp.Exists(this=subquery)
    raise RowScopeError(f"scope '{dimension}': unknown rule {kind!r} for {table}")


def compile_grant(tables, scope_values, dimensions):
    """
    Filters for one grant: {lower-case table: expression}, written against
    INNER_ALIAS. `tables` = the role's resolved table names; scope_values
    = {dimension: [values]} already resolved for this user; dimensions =
    {dimension: rules} (see _dimension_filter). A table with no filter in
    any dimension maps to None (all its rows). Several dimensions AND.
    """
    filters = {}
    for table in tables:
        key = table.lower()
        parts = []
        for dimension, values in scope_values.items():
            part = _dimension_filter(dimension, dimensions[dimension], key,
                                     values, INNER_ALIAS, 1, {key})
            if part is not None:
                parts.append(part)
        if not parts:
            filters[key] = None
            continue
        combined = parts[0]
        for part in parts[1:]:
            combined = exp.And(this=combined, expression=part)
        filters[key] = combined
    return filters


def combine_filters(grant_filters):
    """
    One filter per table from every grant that covers it: rows visible
    under ANY grant. A grant with no filter on a table (unrestricted, or
    an unscoped role) makes the whole table visible. Returns
    {lower-case table: expression}; unrestricted tables are left out.
    """
    by_table = {}
    for filters in grant_filters:
        for table, expression in filters.items():
            by_table.setdefault(table, []).append(expression)

    combined = {}
    for table, expressions in by_table.items():
        if any(e is None for e in expressions):
            continue
        unique = []
        seen = set()
        for e in expressions:
            text = e.sql()
            if text not in seen:
                seen.add(text)
                unique.append(e)
        result = unique[0]
        for e in unique[1:]:
            result = exp.Or(this=exp.Paren(this=result), expression=exp.Paren(this=e))
        combined[table] = result
    return combined


# ---------------------------------------------------------------------------
# Applying the filters to a query
# ---------------------------------------------------------------------------

def _table_key(table):
    """Lower-case "schema.table" for a table reference in a query."""
    return full_table_name(table.name, table.db).lower()


def _wrapper(table, predicate):
    """(SELECT * FROM <table> AS _t WHERE <predicate>) AS <alias>."""
    inner = table.copy()
    inner.set("alias", exp.TableAlias(this=ident(INNER_ALIAS)))
    select = exp.select(exp.Star()).from_(inner).where(predicate.copy())
    alias = table.alias or table.name
    return exp.Subquery(this=select, alias=exp.TableAlias(this=ident(alias)))


def apply_row_scope(sql, row_filters, dialect):
    """
    The query with every reference to a table in `row_filters` replaced by
    its filtered version, then verified. Returns the SQL unchanged when
    the user has no row filters. Raises RowScopeError when the rewrite or
    the check fails.
    """
    if not row_filters:
        return sql
    try:
        statements = sqlglot.parse(sql, read=dialect)
    except Exception as ex:
        raise RowScopeError(f"query could not be parsed for row scope: {ex}") from ex
    if len(statements) != 1 or statements[0] is None:
        raise RowScopeError("row scope needs exactly one statement")
    tree = statements[0]

    targets = [t for t in tree.find_all(exp.Table) if _table_key(t) in row_filters]
    for table in targets:
        if not isinstance(table.this, exp.Identifier) or table.catalog:
            raise RowScopeError(f"unsupported reference to {_table_key(table)}")
        unaliased = not table.alias
        name, schema = table.name.lower(), (table.db or "").lower()
        if unaliased and schema:
            # "sales.customer.x" no longer resolves once the table becomes
            # a derived table named "customer": drop the schema part.
            for column in tree.find_all(exp.Column):
                if (column.table.lower() == name
                        and (column.db or "").lower() == schema):
                    column.set("db", None)
                    column.set("catalog", None)
        table.replace(_wrapper(table, row_filters[_table_key(table)]))

    final = tree.sql(dialect=dialect)
    verify_row_scope(final, row_filters, dialect)
    return final


def verify_row_scope(sql, row_filters, dialect):
    """
    Check the text that will run: every reference to a scoped table must
    be the only table of a SELECT * ... AS _t whose WHERE is exactly that
    table's filter, inside a derived table. Tables inside a verified
    filter (its EXISTS subqueries) are part of the filter. Raises
    RowScopeError otherwise.
    """
    try:
        tree = sqlglot.parse_one(sql, read=dialect)
    except Exception as ex:
        raise RowScopeError(f"filtered query could not be re-parsed: {ex}") from ex

    expected = {t: f.sql(dialect=dialect) for t, f in row_filters.items()}
    verified_filters = []    # WHERE nodes of verified wrappers
    wrapped = set()          # ids of the tables those wrappers filter

    for table in tree.find_all(exp.Table):
        key = _table_key(table)
        if key not in expected or table.alias != INNER_ALIAS:
            continue
        select = table.parent.parent if isinstance(table.parent, exp.From) else None
        if (isinstance(select, exp.Select)
                and isinstance(select.parent, exp.Subquery)
                and not select.args.get("joins")
                and len(select.expressions) == 1
                and isinstance(select.expressions[0], exp.Star)
                and select.args.get("where") is not None
                and select.args["where"].this.sql(dialect=dialect) == expected[key]):
            verified_filters.append(select.args["where"])
            wrapped.add(id(table))

    def inside_filter(node):
        parent = node.parent
        while parent is not None:
            if any(parent is f for f in verified_filters):
                return True
            parent = parent.parent
        return False

    for table in tree.find_all(exp.Table):
        key = _table_key(table)
        if key in expected and id(table) not in wrapped and not inside_filter(table):
            raise RowScopeError(f"{key} is not filtered by its row scope")
