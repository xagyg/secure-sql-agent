# Copyright (c) 2026 Brad Long
# Author: Brad Long

import re
from contextlib import closing

from sqlglot import exp

from sqlagent.controls.sql_policy import parse_single_sql
from sqlagent.adaptive.semantic_model import default_semantic_model
from sqlagent.controls.security_utils import (
    contains_case_insensitive,
    full_table_name,
    get_denied_columns,
)
from sqlagent.execution.sql_execution import get_connection


# ---------------------------------------------------------------------------
# Semantic column aliases
# ---------------------------------------------------------------------------
# The column vocabulary is the semantic model's column labels, aliases
# and column terms (config/semantic/<database>/), the same words the catalog uses to
# pick tables and shows the LLM. Here it is read the other way round: the
# model wrote an alias ("phone") or label as if it were a column, so map
# it back to the physical column (employees.home_phone). This NEVER
# bypasses authorisation: a denied column is reported as such.


# ---------------------------------------------------------------------------
# Schema diagnostics
# ---------------------------------------------------------------------------

def get_physical_columns(full_table):
    """Return physical columns for internal diagnostics only."""
    schema_name, table_name = full_table.split(".", 1)

    sql = """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = %s
          AND table_name = %s
        ORDER BY ordinal_position
    """

    # closing(): a psycopg2 "with connection" block only ends the
    # transaction, it does not close the connection.
    with closing(get_connection()) as conn:
        with conn.cursor() as cursor:
            cursor.execute(sql, (schema_name, table_name))
            return [row["column_name"] for row in cursor.fetchall()]


def get_column_alias(full_table, column_name, semantic=None):
    """
    The physical column that column_name is another name for on this
    table (a column label, alias or column term in the semantic model),
    or None. A bare table name is in the default schema.
    """
    semantic = semantic if semantic is not None else default_semantic_model()
    return semantic.physical_column_for(full_table_name(full_table), column_name)


def extract_missing_column(error_text):
    """
    Return the bare column name from a Postgres "does not exist" error.

    Postgres words the error differently depending on how the column was
    referenced, e.g.:

        column "phone" does not exist        (unqualified)
        column e.phone does not exist        (table alias / name qualifier)
        column e."Phone" does not exist      (quoted identifier)

    Only the column part is returned ("phone"); any qualifier is dropped
    because the alias lookup that follows works on plain column names.
    Only the first line is read, so a HINT further down can't be mistaken
    for the failing column.
    """
    first_line = error_text.strip().splitlines()[0] if error_text.strip() else ""

    match = re.search(
        r"column\s+(.+?)\s+does not exist",
        first_line,
        flags=re.IGNORECASE,
    )

    if not match:
        return None

    raw = match.group(1).strip()

    # A single quoted identifier: "some.name" is one column, not a qualifier.
    if raw.startswith('"') and raw.endswith('"') and raw.count('"') == 2:
        return raw.strip('"') or None

    return raw.split(".")[-1].strip('"') or None


def diagnose_sql_error(sql, error, security, semantic=None):
    """
    Diagnose PostgreSQL "column ... does not exist" errors. semantic is
    the catalog's semantic model (the default model if omitted).

    Physical schema details remain internal and are not sent to Ollama.
    """
    error_text = str(error)

    column_name = extract_missing_column(error_text)

    if not column_name:
        return None

    try:
        tree = parse_single_sql(sql)
    except ValueError:
        return None

    referenced_tables = []

    for table in tree.find_all(exp.Table):
        full_table = full_table_name(table.name, table.db)

        if not any(
            existing.lower() == full_table.lower() for existing in referenced_tables
        ):
            referenced_tables.append(full_table)

    alias_matches = []

    for full_table in referenced_tables:
        physical_alias = get_column_alias(full_table, column_name, semantic)

        if not physical_alias:
            continue

        try:
            physical_columns = get_physical_columns(full_table)
        except Exception:
            continue

        actual_column = next(
            (
                column
                for column in physical_columns
                if column.lower() == physical_alias.lower()
            ),
            None,
        )

        if actual_column is None:
            continue

        denied = get_denied_columns(security, full_table)
        authorised = not contains_case_insensitive(denied, actual_column)

        alias_matches.append({
            "table": full_table,
            "column": actual_column,
            "alias": column_name,
            "authorised": authorised,
        })

    if alias_matches:
        error_type = (
            "invalid_column_alias_authorised"
            if any(match["authorised"] for match in alias_matches)
            else "invalid_column_alias_denied"
        )
    else:
        error_type = "invalid_column"

    return {
        "error_type": error_type,
        "column": column_name,
        "tables": referenced_tables,
        "matches": alias_matches,
    }