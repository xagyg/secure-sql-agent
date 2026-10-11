# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# SQL policy for model-generated queries: parse, check structure (one
# read-only SELECT), check authorisation (tables and columns against the
# SecurityContext), strip restricted columns from the SELECT list, expand
# SELECT * to authorised columns, and add the row limit. Split out of
# agent_controls.py.

import re
from dataclasses import dataclass, field

import sqlglot
from sqlglot import exp

from sqlagent.controls.security_utils import (
    contains_case_insensitive,
    full_table_name,
    get_denied_columns,
    is_authorized_table,
)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MAX_ROWS = 1000

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


# ---------------------------------------------------------------------------
# SQL parsing and structural safety
# ---------------------------------------------------------------------------

def parse_single_sql(sql):
    """
    Parse SQL and require exactly one statement.

    SQL is parsed structurally rather than inspected using
    keyword/string matching.
    """
    try:
        statements = sqlglot.parse(sql, read="postgres")
    except Exception as ex:
        # sqlglot underlines the bad token with terminal colour codes,
        # which show up as "←[4m" in a Windows console and in logs.
        message = _ANSI_ESCAPE.sub("", str(ex))
        raise ValueError(f"SQL could not be parsed: {message}")

    if len(statements) != 1:
        raise ValueError("Exactly one SQL statement is permitted.")

    return statements[0]


def is_read_only_select(tree):
    """
    Return True only for read-only SELECT queries.

    UNION / UNION ALL are represented by sqlglot as compound
    query expressions and are also read-only.
    """
    if isinstance(tree, exp.Select):
        return True
    if isinstance(tree, exp.Union):
        return True
    return False


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
    )
    if hasattr(exp, name)
)


def validate_sql_structure(tree):
    """
    Validate structural SQL safety.

    This deliberately uses the parsed SQL AST rather than searching
    for dangerous words in the SQL text.
    """
    if not is_read_only_select(tree):
        return False, "Only read-only SELECT queries are permitted."

    # Data-modifying statements nested inside a SELECT (e.g. in a CTE).
    if _FORBIDDEN_NODES and tree.find(*_FORBIDDEN_NODES):
        return False, (
            "Only read-only queries are permitted: "
            "data-modifying operations are not allowed."
        )

    # SELECT INTO creates a table and therefore isn't read-only.
    if tree.find(exp.Into):
        return False, "SELECT INTO is not permitted."

    return True, None


def is_safe_sql(sql):
    """
    Structural SQL safety check.

    This is intentionally independent of table/column authorisation.
    Authorisation is performed separately by is_authorized_sql().
    """
    try:
        tree = parse_single_sql(sql)
    except ValueError:
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
            return None, "A referenced table could not be determined."

        full_name = full_table_name(table_name, schema_name)

        if not is_authorized_table(security, full_name):
            return None, f"Table '{full_name}' is not authorised."

        table_aliases[table_name.lower()] = full_name

        if table.alias:
            table_aliases[table.alias.lower()] = full_name

    return table_aliases, None


def validate_columns(tree, table_aliases, security):
    """
    Validate every explicitly referenced column against the
    SecurityContext.

    Unqualified columns are checked conservatively against every
    referenced table that has a matching denied column.
    """
    for column in tree.find_all(exp.Column):
        column_name = column.name

        # Whole-row references return every column of a table as a single
        # value, bypassing per-column checks and the result policy (which
        # strips restricted columns by key name):
        #     SELECT e FROM employees e
        #     SELECT row_to_json(e) / to_jsonb(e.*) FROM employees e
        #     SELECT (e).home_phone FROM employees e
        if not column.table and column_name.lower() in table_aliases:
            return False, "Whole-row table references are not permitted."

        if isinstance(column.this, exp.Star) and column.find_ancestor(exp.Func):
            return False, "Whole-row table references are not permitted."

        if not column_name:
            return False, "Unable to determine a referenced column."

        table_reference = column.table

        if table_reference and table_reference.lower() not in table_aliases:
            return False, (
                f"Unable to determine table for "
                f"column '{table_reference}.{column_name}'."
            )

        denied_table = _table_denying_column(column, table_aliases, security)

        if denied_table:
            return False, (
                f"Column '{denied_table}.{column_name}' "
                f"is not authorised."
            )

    return True, None


def _table_denying_column(column, table_aliases, security):
    """
    The referenced table on which this column is denied, or None.

    A qualified column (c.phone) is checked against its own table; an
    unqualified one (phone) conservatively against every referenced
    table. Shared by validate_columns() and strip_denied_projection().
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


def is_authorized_sql(sql, security):
    """
    Check whether generated SQL is authorised.

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
    except ValueError as ex:
        return False, str(ex)

    return validate_tree(tree, security)


def validate_tree(tree, security):
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

    allowed, reason = validate_columns(tree, table_aliases, security)
    if not allowed:
        return False, reason

    return True, None


def validate_agent_sql(sql, security):
    """
    Perform the complete security validation for AI-generated SQL.

    is_authorized_sql() already parses the statement, runs the structural
    checks and then the authorisation checks, returning a specific reason
    at each step. (A separate is_safe_sql() pre-check used to run first,
    but it returns only a bool, which collapsed every structural failure
    into one generic message.)
    """
    return is_authorized_sql(sql, security)


# ---------------------------------------------------------------------------
# SELECT * rewriting
# ---------------------------------------------------------------------------

def rewrite_select_stars(sql, security, catalog):
    """
    Replace SELECT * and SELECT alias.* with explicit authorised columns.

    Restricted columns are omitted from the generated projection.
    """
    try:
        tree = parse_single_sql(sql)
    except ValueError as ex:
        raise ValueError(str(ex))

    if not isinstance(tree, exp.Select):
        return sql

    rewrite_select_stars_tree(tree, security, catalog)
    return tree.sql(dialect="postgres")


def rewrite_select_stars_tree(tree, security, catalog):
    """
    rewrite_select_stars() on a parsed SELECT, in place. Raises
    ValueError for an alias.* whose table can't be determined.
    """
    # ---------------------------------------------------------
    # Build table / alias map
    # ---------------------------------------------------------
    tables = []

    for table in tree.find_all(exp.Table):
        table_name = table.name
        full_table = full_table_name(table_name, table.db)

        if table.alias:
            reference = table.alias
        else:
            reference = table_name

        tables.append({
            "full_table": full_table,
            "reference": reference,
        })

    # ---------------------------------------------------------
    # Expand SELECT expressions
    # ---------------------------------------------------------
    new_expressions = []

    for expression in tree.expressions:
        # -----------------------------------------------------
        # SELECT *
        # -----------------------------------------------------
        if isinstance(expression, exp.Star):
            for table_info in tables:
                full_table = table_info["full_table"]
                reference = table_info["reference"]

                denied_columns = get_denied_columns(security, full_table)

                for column_name in get_authorized_columns(catalog, full_table):
                    if contains_case_insensitive(denied_columns, column_name):
                        continue

                    new_expressions.append(
                        exp.Column(
                            this=exp.Identifier(this=column_name, quoted=False),
                            table=exp.Identifier(this=reference, quoted=False),
                        )
                    )
            continue

        # -----------------------------------------------------
        # SELECT alias.*
        # -----------------------------------------------------
        if (
            isinstance(expression, exp.Column)
            and isinstance(expression.this, exp.Star)
        ):
            table_reference = expression.table
            matching_table = None

            for table_info in tables:
                if table_info["reference"].lower() == table_reference.lower():
                    matching_table = table_info
                    break

            if matching_table is None:
                raise ValueError(
                    f"Unable to determine table for '{table_reference}.*'."
                )

            full_table = matching_table["full_table"]
            denied_columns = get_denied_columns(security, full_table)

            for column_name in get_authorized_columns(catalog, full_table):
                if contains_case_insensitive(denied_columns, column_name):
                    continue

                new_expressions.append(
                    exp.Column(
                        this=exp.Identifier(this=column_name, quoted=False),
                        table=exp.Identifier(this=table_reference, quoted=False),
                    )
                )
            continue

        # -----------------------------------------------------
        # Normal SELECT expression
        # -----------------------------------------------------
        new_expressions.append(expression)

    tree.set("expressions", new_expressions)


# ---------------------------------------------------------------------------
# Restricted columns in the SELECT list
# ---------------------------------------------------------------------------

def _is_denied_column(column, table_aliases, security):
    """Same rule as validate_columns() (see _table_denying_column)."""
    return _table_denying_column(column, table_aliases, security) is not None


def strip_denied_projection(sql, security):
    """
    Remove restricted columns from the SELECT list, so a question like
    "tell me more about Ernst Handel" is answered without phone/fax/address
    instead of being blocked outright. This matches how SELECT * already
    behaves (rewrite_select_stars omits restricted columns).

    Only plain column outputs are removed:
        SELECT phone ...            -> removed
        SELECT c.phone AS tel ...   -> removed
    Anything else that uses a restricted column is left in place, so the
    full validation that runs afterwards still BLOCKS it:
        WHERE phone LIKE '030%'     (filtering can reveal the value)
        ORDER BY / GROUP BY / JOIN on a restricted column
        CONCAT(phone, fax), CASE ... phone ...  (derived values)

    Returns (sql, removed) where removed is a list of the column names
    taken out. Returns the SQL unchanged (and removed=[]) when there's
    nothing to strip, when it can't be parsed or isn't a plain SELECT, or
    when stripping would leave no columns at all; the validator then
    decides as usual.
    """
    try:
        tree = parse_single_sql(sql)
    except ValueError:
        return sql, []

    removed = strip_denied_projection_tree(tree, security)
    if not removed:
        return sql, []

    return tree.sql(dialect="postgres"), removed


def strip_denied_projection_tree(tree, security):
    """
    strip_denied_projection() on a parsed statement, in place. Returns
    the removed column names; the tree is unchanged when nothing is
    removed (not a plain SELECT, an unauthorised table, nothing
    restricted, or nothing would be left).
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
            and _is_denied_column(target, table_aliases, security)
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

def apply_query_limits(sql):
    """
    Ensure SELECT queries have a maximum row count.

    Existing explicit limits are preserved.
    """
    try:
        tree = parse_single_sql(sql)
    except ValueError as ex:
        raise ValueError(str(ex))

    if not isinstance(tree, exp.Select):
        return sql

    apply_query_limits_tree(tree)
    return tree.sql(dialect="postgres")


def apply_query_limits_tree(tree):
    """apply_query_limits() on a parsed SELECT, in place: add LIMIT
    MAX_ROWS unless the query already has a limit."""
    if tree.args.get("limit") is None:
        tree.set(
            "limit",
            exp.Limit(expression=exp.Literal.number(MAX_ROWS)),
        )


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
        failure_reason why validation stopped it, or None
    """
    sql: str
    withheld: list = field(default_factory=list)
    stripped_sql: str | None = None
    rewritten: bool = False
    failure_reason: str | None = None


def prepare_sql(sql, security, catalog):
    """
    Make model-generated SQL safe to run:

        parse
          -> drop restricted columns from the SELECT list
          -> validate (structure + authorisation)
          -> expand SELECT * to authorised columns, add the row limit
          -> validate the FINAL TEXT again

    The statement is parsed once and every step works on that tree. The
    only re-parse is the last check, which is deliberately run on the
    exact text that will be executed rather than the in-memory tree, so
    nothing that changes in turning the tree back into SQL can slip
    past it. (execute_sql() runs its own structural check on that same
    text as the final gate.)

    Restricted columns used anywhere other than the SELECT list (WHERE,
    JOIN, ORDER BY, inside expressions) are left in place and blocked by
    validation. Only a plain SELECT is stripped or rewritten; a UNION is
    validated and run as written.

    Raises ValueError when a SELECT * can't be expanded.
    """
    try:
        tree = parse_single_sql(sql)
    except ValueError as ex:
        return PreparedSql(sql=sql, failure_reason=str(ex))

    result = PreparedSql(sql=sql)
    is_select = isinstance(tree, exp.Select)

    if is_select:
        result.withheld = strip_denied_projection_tree(tree, security)
        if result.withheld:
            result.sql = result.stripped_sql = tree.sql(dialect="postgres")

    allowed, reason = validate_tree(tree, security)
    if not allowed:
        result.failure_reason = reason
        return result

    if is_select:
        rewrite_select_stars_tree(tree, security, catalog)
        apply_query_limits_tree(tree)
        final_sql = tree.sql(dialect="postgres")
        if final_sql != result.sql:
            result.sql = final_sql
            result.rewritten = True

    allowed, reason = validate_agent_sql(result.sql, security)
    if not allowed:
        result.failure_reason = reason

    return result
