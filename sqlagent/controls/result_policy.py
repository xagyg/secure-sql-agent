# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Result-level security: removes restricted columns from query results
# before they reach the explanation model, and caps the result size.
# Defence in depth - authorisation happens before execution (see
# sql_policy.py). Split out of agent_controls.py.

import json

from sqlagent.controls.security_utils import (
    contains_case_insensitive,
    get_denied_columns,
    is_authorized_table,
)
from sqlagent.controls.sql_policy import MAX_ROWS


MAX_RESULT_BYTES = 5_000_000


# ---------------------------------------------------------------------------
# Result policy
# ---------------------------------------------------------------------------

def _is_denied_by_name(result_column, security):
    """Name-only rule: the column name is denied on ANY table. Used only
    when the column's source table is unknown, so it fails closed."""
    return any(
        contains_case_insensitive(denied, result_column)
        for denied in security.denied_columns.values()
    )


def _is_denied_source(table, column, security):
    """A (table, column) the role may not see: an unauthorised table, or
    a column denied on THAT table."""
    if not is_authorized_table(security, table):
        return True
    return contains_case_insensitive(get_denied_columns(security, table), column)


def restricted_result_columns(columns, security, sources=None):
    """
    Decide which result columns must be removed.

    sources (from sql_execution.execute_sql_with_sources) maps each output
    column to the table column(s) it was read from, or None for a computed
    value. With sources, a column is removed only when it comes from a
    table on which it is denied, so suppliers.phone is kept while
    customers.phone is removed. Previously every column NAMED like a
    denied column was removed, whatever its table, which emptied e.g.
    "SELECT phone FROM suppliers" and the explanation then said the
    supplier didn't exist.

    A column with no known source - a computed value, a UNION column (for
    which PostgreSQL reports no table), or no sources at all - falls back
    to the old name-only rule, so unknown provenance fails closed.
    validate_agent_sql() has already blocked restricted columns used
    inside expressions; this is the backstop.
    """
    removed = set()

    for column in columns:
        column_sources = sources.get(column) if sources is not None else None

        if not column_sources:
            column_sources = [None]

        for source in column_sources:
            if source is None:
                denied = _is_denied_by_name(column, security)
            else:
                denied = _is_denied_source(source[0], source[1], security)
            if denied:
                removed.add(column)
                break

    return removed


def apply_result_policy(rows, security, sources=None):
    """
    Apply result-level security before results are passed to Ollama.

    This is defence in depth. Primary authorisation occurs before
    SQL execution.

    Returns (rows, removed): the filtered rows, and a sorted list of the
    result columns that were taken out. See restricted_result_columns()
    for how sources is used.
    """
    if not rows:
        return rows, []

    columns = []
    for row in rows:
        for column in row:
            if column not in columns:
                columns.append(column)

    removed = restricted_result_columns(columns, security, sources)

    filtered = []
    total_bytes = 0

    for row in rows:
        new_row = {k: v for k, v in row.items() if k not in removed}

        row_bytes = len(
            json.dumps(
                new_row,
                default=str,
                separators=(",", ":")
            ).encode("utf-8")
        )

        if total_bytes + row_bytes > MAX_RESULT_BYTES:
            break

        filtered.append(new_row)
        total_bytes += row_bytes

        if len(filtered) >= MAX_ROWS:
            break

    return filtered, sorted(removed)
