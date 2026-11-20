# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# SQL policy for model-generated queries: parse, check structure (one
# read-only SELECT), check authorisation (tables and columns against the
# SecurityContext), strip restricted columns from the SELECT list, expand
# SELECT * to authorised columns, and add the row limit.
#
# Every failure is a Reason: the message as text, plus a stable code (and,
# for an unauthorised table, the table) so callers decide what to do
# without matching on the wording.

import re
from dataclasses import dataclass, field
from functools import lru_cache

import sqlglot
from sqlglot import exp
from sqlglot.transforms import eliminate_qualify

from sqlagent.controls.security_utils import (
    contains_case_insensitive,
    full_table_name,
    get_denied_columns,
    ident,
    is_authorized_table,
)
from sqlagent.execution.engines import active_dialect
from sqlagent.settings import get_settings


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# LIMIT added to queries that have none (config/settings/query.yaml).
MAX_ROWS = get_settings().query.max_rows

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


# ---------------------------------------------------------------------------
# Failure reasons
# ---------------------------------------------------------------------------

# Reason codes. messages.block_rule() maps them to the user-facing rule.
UNPARSEABLE = "unparseable"
SINGLE_STATEMENT = "single_statement"
READ_ONLY = "read_only"
TABLE_NOT_AUTHORISED = "table_not_authorised"
COLUMN_NOT_AUTHORISED = "column_not_authorised"
POLICY = "policy"


class Reason(str):
    """
    Why a query was stopped. A str (the message for the log), plus
    `code` (one of the codes above) and, for TABLE_NOT_AUTHORISED, the
    `table` as the query wrote it.
    """

    def __new__(cls, text, code=POLICY, table=None):
        reason = super().__new__(cls, text)
        reason.code = code
        reason.table = table
        return reason


class SqlPolicyError(ValueError):
    """The SQL could not be parsed as exactly one statement; `reason` says
    which (UNPARSEABLE or SINGLE_STATEMENT)."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def reason_of(ex):
    """The Reason carried by an exception from this module (a plain
    ValueError becomes a POLICY reason)."""
    return getattr(ex, "reason", None) or Reason(str(ex))


# ---------------------------------------------------------------------------
# SQL parsing and structural safety
# ---------------------------------------------------------------------------

def parse_single_sql(sql):
    """
    Parse SQL and require exactly one statement. Raises SqlPolicyError.

    SQL is parsed structurally rather than inspected using
    keyword/string matching.
    """
    try:
        statements = sqlglot.parse(sql, read=active_dialect())
    except Exception as ex:
        # sqlglot underlines the bad token with terminal colour codes,
        # which show up as "←[4m" in a Windows console and in logs.
        message = _ANSI_ESCAPE.sub("", str(ex))
        raise SqlPolicyError(Reason(f"SQL could not be parsed: {message}",
                                    UNPARSEABLE)) from ex

    if len(statements) != 1:
        raise SqlPolicyError(Reason("Exactly one SQL statement is permitted.",
                                    SINGLE_STATEMENT))

    return statements[0]


def is_read_only_select(tree):
    """
    True only for a SELECT, or a UNION / UNION ALL of SELECTs (sqlglot's
    compound query expression, also read-only).
    """
    return isinstance(tree, (exp.Select, exp.Union))


def _union_selects(tree):
    """The SELECT branches of a UNION (nested UNIONs flattened), or
    [tree] for a plain SELECT."""
    if isinstance(tree, exp.Union):
        return _union_selects(tree.this) + _union_selects(tree.expression)
    return [tree]


# Node types that must never appear ANYWHERE in the tree, not just at the
# top level. Postgres executes data-modifying CTEs even when nothing
# references them, e.g.
#     WITH x AS (DELETE FROM orders RETURNING 1) SELECT 1
# parses as a plain SELECT, so a top-level check alone isn't enough.
# (Looked up by name so this works across sqlglot versions.)
_FORBIDDEN_NODES = tuple(
    getattr(exp, name)
    for name in (
        "Insert", "Update", "Delete", "Merge",
        "Create", "Drop", "Alter", "AlterTable", "TruncateTable",
        "Copy", "Command",
        "Lock",  # SELECT ... FOR UPDATE / FOR SHARE
        "NextValueFor",  # T-SQL NEXT VALUE FOR advances a sequence
    )
    if hasattr(exp, name)
)

# Functions that reach outside the database the agent is connected to
# (another server, a file, an OLE DB/ODBC source). Checked by name
# anywhere in the tree. SQL Server's "Ad Hoc Distributed Queries" option
# should also stay off; this does not rely on it.
_EXTERNAL_DATA_FUNCTIONS = {
    "openrowset", "openquery", "opendatasource", "openxml",
}


def _check_table_references(tree):
    """
    Every table reference must be a plain [schema.]table in the connected
    database. Rejected:

      - a database or server prefix (OtherDb.dbo.Customers,
        LinkedServer.OtherDb.dbo.Customers): authorisation works on
        schema.table, so the prefix would otherwise be ignored and
        OtherDb.dbo.Customers checked as if it were dbo.Customers;
      - a function in place of a table (OPENROWSET(...),
        dbo.SomeFunction(...), generate_series(...)): it isn't a table
        the security policy can authorise.
    """
    for table in tree.find_all(exp.Table):
        if table.catalog:
            return False, Reason(
                "Cross-database and linked-server references are not permitted.")
        if not isinstance(table.this, exp.Identifier):
            return False, Reason("Only tables and views can be queried, not functions.")
    return True, None


def _check_external_data(tree):
    for func in tree.find_all(exp.Func):
        name = (func.name if isinstance(func, exp.Anonymous) else func.sql_name())
        if name and name.lower() in _EXTERNAL_DATA_FUNCTIONS:
            return False, Reason("External data sources are not permitted.")
    return True, None


def validate_sql_structure(tree):
    """
    Validate structural SQL safety.

    This deliberately uses the parsed SQL AST rather than searching
    for dangerous words in the SQL text.
    """
    if not is_read_only_select(tree):
        return False, Reason("Only read-only SELECT queries are permitted.", READ_ONLY)

    # Data-modifying statements nested inside a SELECT (e.g. in a CTE).
    if _FORBIDDEN_NODES and tree.find(*_FORBIDDEN_NODES):
        return False, Reason(
            "Only read-only queries are permitted: "
            "data-modifying operations are not allowed.", READ_ONLY)

    # SELECT INTO creates a table and therefore isn't read-only.
    if tree.find(exp.Into):
        return False, Reason("SELECT INTO is not permitted.", READ_ONLY)

    allowed, reason = _check_external_data(tree)
    if not allowed:
        return False, reason

    allowed, reason = _check_table_references(tree)
    if not allowed:
        return False, reason

    return True, None


def is_safe_sql(sql):
    """
    Structural SQL safety check.

    This is intentionally independent of table/column authorisation.
    Authorisation is performed separately by is_authorized_sql().
    """
    try:
        tree = parse_single_sql(sql)
    except SqlPolicyError:
        return False

    allowed, _ = validate_sql_structure(tree)
    return allowed


# ---------------------------------------------------------------------------
# SQL authorisation
# ---------------------------------------------------------------------------

def build_table_alias_map(tree, security):
    """
    Build a case-insensitive mapping of SQL table names and aliases
    to authorised physical table names.
    """
    table_aliases = {}

    for table in tree.find_all(exp.Table):
        schema_name = table.db
        table_name = table.name

        if not table_name:
            return None, Reason("A referenced table could not be determined.")

        full_name = full_table_name(table_name, schema_name)

        if not is_authorized_table(security, full_name):
            return None, Reason(f"Table '{full_name}' is not authorised.",
                                TABLE_NOT_AUTHORISED, table=full_name)

        table_aliases[table_name.lower()] = full_name

        if table.alias:
            table_aliases[table.alias.lower()] = full_name

    return table_aliases, None


def _is_real_column(name, table_aliases, catalog):
    """True when `name` is a column of one of the referenced tables in the
    role's catalog. None for the catalog means unknown (False)."""
    if catalog is None:
        return False
    return any(
        contains_case_insensitive(get_authorized_columns(catalog, table), name)
        for table in set(table_aliases.values())
    )


def validate_columns(tree, table_aliases, security, catalog=None):
    """
    Validate every explicitly referenced column against the
    SecurityContext.

    Unqualified columns are checked conservatively against every
    referenced table that has a matching denied column. `catalog` (the
    role's SchemaCatalog), when given, tells a real column apart from a
    whole-row reference that happens to share its name.
    """
    for column in tree.find_all(exp.Column):
        column_name = column.name

        # Whole-row references return every column of a table as a single
        # value, bypassing per-column checks and the result policy (which
        # strips restricted columns by key name):
        #     SELECT e FROM employees e
        #     SELECT row_to_json(e) / to_jsonb(e.*) FROM employees e
        #     SELECT (e).home_phone FROM employees e
        # PostgreSQL resolves a bare name as a column first, so a name that
        # is also a column of a referenced table (customers.region beside
        # the region table) is a column, not a whole row.
        if (not column.table and column_name.lower() in table_aliases
                and not _is_real_column(column_name, table_aliases, catalog)):
            return False, Reason("Whole-row table references are not permitted.")

        if isinstance(column.this, exp.Star) and column.find_ancestor(exp.Func):
            return False, Reason("Whole-row table references are not permitted.")

        if not column_name:
            return False, Reason("Unable to determine a referenced column.")

        table_reference = column.table

        if table_reference and table_reference.lower() not in table_aliases:
            return False, Reason(
                f"Unable to determine table for "
                f"column '{table_reference}.{column_name}'."
            )

        denied_table = _table_denying_column(column, table_aliases, security)

        if denied_table:
            return False, Reason(
                f"Column '{denied_table}.{column_name}' is not authorised.",
                COLUMN_NOT_AUTHORISED)

    return True, None


def _table_denying_column(column, table_aliases, security):
    """
    The referenced table on which this column is denied, or None.

    A qualified column (c.phone) is checked against its own table; an
    unqualified one (phone) conservatively against every referenced
    table. Shared by validate_columns() and strip_denied_projection_tree().
    """
    name = column.name
    if not name:
        return None

    if column.table:
        full_table = table_aliases.get(column.table.lower())
        tables = [full_table] if full_table else []
    else:
        tables = set(table_aliases.values())

    return next(
        (
            t for t in tables
            if contains_case_insensitive(get_denied_columns(security, t), name)
        ),
        None,
    )


def is_authorized_sql(sql, security, catalog=None):
    """
    The complete security validation for model-generated SQL. Returns
    (allowed, reason), reason a Reason.

    Policy:
      - exactly one statement
      - SELECT only
      - SELECT INTO denied
      - every referenced table must be authorised
      - explicitly referenced restricted columns are denied
      - unqualified restricted columns are denied conservatively
    """
    try:
        tree = parse_single_sql(sql)
    except SqlPolicyError as ex:
        return False, ex.reason

    return validate_tree(tree, security, catalog)


def validate_tree(tree, security, catalog=None):
    """
    is_authorized_sql() for an already-parsed statement: structure, then
    tables, then columns. Returns (allowed, reason).
    """
    allowed, reason = validate_sql_structure(tree)
    if not allowed:
        return False, reason

    table_aliases, reason = build_table_alias_map(tree, security)
    if reason:
        return False, reason

    allowed, reason = validate_columns(tree, table_aliases, security, catalog)
    if not allowed:
        return False, reason

    return True, None


# ---------------------------------------------------------------------------
# SELECT * rewriting
# ---------------------------------------------------------------------------


def _select_sources(select):
    """
    The row sources this SELECT reads directly - its FROM and JOINs, in
    order - as (tables, other). tables: {"full_table", "reference"} for
    each plain table. other: the references of anything else (a derived
    table, a function such as generate_series()), whose columns can't be
    looked up in the catalog.

    Tables inside subqueries (WHERE EXISTS (...), a scalar subquery, a
    derived table's own FROM) are not this SELECT's sources: a * here
    must not expand to their columns.
    """
    from_clause = select.args.get("from_") or select.args.get("from")
    nodes = [from_clause.this] if from_clause else []
    nodes += [join.this for join in select.args.get("joins") or []]

    tables, other = [], []
    for node in nodes:
        if isinstance(node, exp.Table) and isinstance(node.this, exp.Identifier):
            tables.append({
                "full_table": full_table_name(node.name, node.db),
                "reference": node.alias or node.name,
            })
        else:
            other.append(node.alias_or_name or node.sql())
    return tables, other


def _authorised_columns_of(full_table, reference, security, catalog):
    """Column references (reference.column) for every column of
    `full_table` the role may see, in catalog order."""
    denied_columns = get_denied_columns(security, full_table)
    return [
        exp.Column(this=ident(column_name), table=ident(reference))
        for column_name in get_authorized_columns(catalog, full_table)
        if not contains_case_insensitive(denied_columns, column_name)
    ]


def rewrite_select_stars_tree(tree, security, catalog):
    """
    Replace SELECT * and SELECT alias.* with the authorised columns, in
    place; restricted columns are left out. Each branch of a UNION is
    rewritten the same way.

    Only the tables a SELECT reads directly (FROM and JOINs) are
    expanded; tables in subqueries are not. Raises ValueError for an
    alias.* whose table can't be determined, and for a * over a derived
    table or other non-table source: its columns can't be checked against
    the catalog, and left unexpanded it could return restricted columns
    (SELECT * FROM (SELECT * FROM customers) t).
    """
    for select in _union_selects(tree):
        if isinstance(select, exp.Select):
            _rewrite_select_stars(select, security, catalog)


def _rewrite_select_stars(select, security, catalog):
    tables, other_sources = _select_sources(select)
    new_expressions = []

    for expression in select.expressions:
        # SELECT *
        if isinstance(expression, exp.Star):
            if other_sources:
                raise ValueError(
                    "SELECT * over a subquery or derived table "
                    f"({', '.join(other_sources)}) can't be expanded to "
                    "authorised columns - list the columns instead."
                )
            for table_info in tables:
                new_expressions += _authorised_columns_of(
                    table_info["full_table"], table_info["reference"],
                    security, catalog)
            continue

        # SELECT alias.*
        if isinstance(expression, exp.Column) and isinstance(expression.this, exp.Star):
            reference = expression.table
            matching_table = next(
                (t for t in tables if t["reference"].lower() == reference.lower()),
                None)
            if matching_table is None:
                raise ValueError(f"Unable to determine table for '{reference}.*'.")
            new_expressions += _authorised_columns_of(
                matching_table["full_table"], reference, security, catalog)
            continue

        new_expressions.append(expression)

    select.set("expressions", new_expressions)


# ---------------------------------------------------------------------------
# Restricted columns in the SELECT list
# ---------------------------------------------------------------------------

def strip_denied_projection_tree(tree, security):
    """
    Remove restricted columns from the SELECT list, in place, so a
    question like "tell me more about Ernst Handel" is answered without
    phone/fax/address instead of being blocked outright. This matches how
    SELECT * already behaves (rewrite_select_stars_tree omits restricted
    columns).

    Only plain column outputs are removed:
        SELECT phone ...            -> removed
        SELECT c.phone AS tel ...   -> removed
    Anything else that uses a restricted column is left in place, so the
    full validation that runs afterwards still BLOCKS it:
        WHERE phone LIKE '030%'     (filtering can reveal the value)
        ORDER BY / GROUP BY / JOIN on a restricted column
        CONCAT(phone, fax), CASE ... phone ...  (derived values)

    Returns the removed column names; the tree is unchanged when nothing
    is removed (not a plain SELECT, an unauthorised table, nothing
    restricted, or nothing would be left). A UNION is never stripped:
    removing a column from one branch would misalign the others.
    """
    if not isinstance(tree, exp.Select):
        return []

    table_aliases, reason = build_table_alias_map(tree, security)
    if reason:
        return []

    kept = []
    removed = []

    for expression in tree.expressions:
        target = expression.this if isinstance(expression, exp.Alias) else expression

        if (
            isinstance(target, exp.Column)
            and not isinstance(target.this, exp.Star)
            and _table_denying_column(target, table_aliases, security)
        ):
            removed.append(target.name)
            continue

        kept.append(expression)

    if not removed or not kept:
        return []

    tree.set("expressions", kept)
    return removed


def get_authorized_columns(catalog, full_table):
    """Return columns exposed by the security-filtered schema catalog."""
    table = catalog.get_table(full_table)

    if not table:
        return []

    return [column["name"] for column in table["columns"]]


# ---------------------------------------------------------------------------
# Query limits
# ---------------------------------------------------------------------------

def apply_query_limits_tree(tree):
    """Cap the rows a parsed SELECT or UNION returns, in place: add LIMIT
    MAX_ROWS when the query has no limit, and lower a literal limit above
    MAX_ROWS (LIMIT 1000, TOP 1000, FETCH NEXT 1000 ROWS) to MAX_ROWS; a
    smaller one ("top 10") is kept. The result policy caps the rows
    anyway, but only after the database has sent them all; this also
    keeps the SQL honest, so the explanation isn't told about a limit
    that never applied."""
    limit = tree.args.get("limit")
    if limit is None:
        tree.set(
            "limit",
            exp.Limit(expression=exp.Literal.number(MAX_ROWS)),
        )
        return
    key = "count" if isinstance(limit, exp.Fetch) else "expression"
    value = limit.args.get(key)
    if isinstance(value, exp.Literal) and not value.is_string:
        try:
            if int(value.this) > MAX_ROWS:
                limit.set(key, exp.Literal.number(MAX_ROWS))
        except ValueError:
            pass


# ---------------------------------------------------------------------------
# QUALIFY
# ---------------------------------------------------------------------------
# The model sometimes writes QUALIFY (Snowflake / BigQuery: filter on a
# window function, e.g. QUALIFY ROW_NUMBER() OVER (...) <= 3). PostgreSQL
# and SQL Server have no QUALIFY, so sqlglot renders it as a subquery
# filtered outside:
#
#     SELECT a, rn FROM (SELECT a, ROW_NUMBER() ... AS rn FROM t
#                        ORDER BY a LIMIT 100) AS _t WHERE rn <= 3
#
# Left to the renderer, that happens after the row limit was added, so the
# limit (and the ORDER BY) end up INSIDE, before the filter: the database
# could cap the rows before the top-n filter and drop rows that should be
# there, and the order isn't guaranteed outside the subquery. QUALIFY runs
# before ORDER BY and LIMIT, so here the rewrite is done first and both
# move to the outer query.


@lru_cache(maxsize=None)
def _dialect_has_qualify(dialect):
    """True when the dialect renders QUALIFY as written."""
    probe = sqlglot.parse_one("SELECT a FROM t QUALIFY a = 1", read="snowflake")
    return "QUALIFY" in probe.sql(dialect=dialect).upper()


def _outer_order(inner):
    """
    The subquery's ORDER BY rewritten for the outer query, by output name.
    A term that is one of the subquery's columns (sqlglot adds those the
    QUALIFY filter uses) or a position (ORDER BY 2) is named; any other
    term is added to the subquery as _o1, _o2, ... and sorted on there.
    None for a SELECT DISTINCT whose ORDER BY isn't all selected columns:
    an added column would change which rows are distinct.
    """
    selects = inner.selects
    names = {}
    for projection in selects:
        name = projection.alias_or_name
        names[projection.sql().lower()] = name
        names[name.lower()] = name
        if isinstance(projection, exp.Alias):
            names[projection.this.sql().lower()] = name
    taken = {p.alias_or_name.lower() for p in selects}
    ordered, added = [], []
    for term in inner.args["order"].expressions:
        key = term.this
        if isinstance(key, exp.Literal) and not key.is_string \
                and key.this.isdigit() and 1 <= int(key.this) <= len(selects):
            name = selects[int(key.this) - 1].alias_or_name
        else:
            name = names.get(key.sql().lower())
        if name is None:
            n = len(added) + 1
            while f"_o{n}" in taken:
                n += 1
            name = f"_o{n}"
            taken.add(name)
            added.append(exp.alias_(key.copy(), name))
        moved = term.copy()
        moved.set("this", exp.Column(this=ident(name)))
        ordered.append(moved)
    if added and inner.args.get("distinct"):
        return None
    if added:
        inner.set("expressions", list(selects) + added)
    return exp.Order(expressions=ordered)


def eliminate_qualify_tree(tree):
    """
    A SELECT with QUALIFY rewritten, for a dialect without QUALIFY, as
    sqlglot renders it - the query in a subquery, filtered outside - but
    with the ORDER BY, LIMIT and OFFSET on the outer query (see
    _outer_order for the one case the ORDER BY stays inside). Returns the (possibly new) tree;
    anything else is returned unchanged.
    """
    if (not isinstance(tree, exp.Select) or not tree.args.get("qualify")
            or _dialect_has_qualify(active_dialect())):
        return tree
    limit, offset = tree.args.get("limit"), tree.args.get("offset")
    tree.set("limit", None)
    tree.set("offset", None)

    outer = eliminate_qualify(tree)
    inner = (outer.args.get("from_") or outer.args.get("from")).this.this
    if inner.args.get("order"):
        order = _outer_order(inner)
        if order is not None:
            inner.set("order", None)
            outer.set("order", order)
    if limit is not None:
        outer.set("limit", limit)
    if offset is not None:
        outer.set("offset", offset)
    return outer


# ---------------------------------------------------------------------------
# Preparation: parse once, transform the tree, check the final text
# ---------------------------------------------------------------------------

@dataclass
class PreparedSql:
    """
    Result of prepare_sql().

        sql            the SQL as it stands (the final, checked SQL when
                       failure_reason is None; otherwise the SQL at the
                       step that stopped it)
        withheld       restricted columns removed from the SELECT list
        stripped_sql   the SQL just after they were removed, or None
        rewritten      True when SELECT * expansion or the row limit
                       changed the SQL
        failure_reason why validation stopped it (a Reason), or None
    """
    sql: str
    withheld: list = field(default_factory=list)
    stripped_sql: str | None = None
    rewritten: bool = False
    failure_reason: Reason | None = None


def prepare_sql(sql, security, catalog):
    """
    Make model-generated SQL safe to run:

        parse
          -> drop restricted columns from the SELECT list
          -> validate (structure + authorisation)
          -> expand SELECT * to authorised columns, rewrite QUALIFY,
             add the row limit
          -> validate the FINAL TEXT again

    The statement is parsed once and every step works on that tree. The
    only re-parse is the last check, which is deliberately run on the
    exact text that will be executed rather than the in-memory tree, so
    nothing that changes in turning the tree back into SQL can slip
    past it. (execute_sql_with_sources() runs its own structural check on
    that same text as the final gate.)

    Restricted columns used anywhere other than the SELECT list (WHERE,
    JOIN, ORDER BY, inside expressions) are left in place and blocked by
    validation. Restricted columns are stripped only from a plain SELECT;
    a UNION has each branch's * expanded and the row limit added, like a
    SELECT.

    Raises ValueError when a SELECT * can't be expanded.
    """
    try:
        tree = parse_single_sql(sql)
    except SqlPolicyError as ex:
        return PreparedSql(sql=sql, failure_reason=ex.reason)

    result = PreparedSql(sql=sql)

    result.withheld = strip_denied_projection_tree(tree, security)
    if result.withheld:
        result.sql = result.stripped_sql = tree.sql(dialect=active_dialect())

    allowed, reason = validate_tree(tree, security, catalog)
    if not allowed:
        result.failure_reason = reason
        return result

    rewrite_select_stars_tree(tree, security, catalog)
    tree = eliminate_qualify_tree(tree)
    apply_query_limits_tree(tree)
    final_sql = tree.sql(dialect=active_dialect())
    if final_sql != result.sql:
        result.sql = final_sql
        result.rewritten = True

    allowed, reason = is_authorized_sql(result.sql, security, catalog)
    if not allowed:
        result.failure_reason = reason

    return result
