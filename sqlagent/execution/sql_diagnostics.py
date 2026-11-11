# Copyright (c) 2026 Brad Long
# Author: Brad Long

from contextlib import closing

from sqlglot import exp

from sqlagent.controls.sql_policy import parse_single_sql
from sqlagent.adaptive.semantic_model import default_semantic_model
from sqlagent.controls.security_utils import (
    contains_case_insensitive,
    full_table_name,
    get_denied_columns,
)
from sqlagent.execution.engines import active_engine
from sqlagent.execution.sql_execution import get_connection


# ---------------------------------------------------------------------------
# Semantic column aliases
# ---------------------------------------------------------------------------
# The column vocabulary is the semantic model's column labels, aliases
# and column terms (config/<database>/semantic/), the same words the catalog uses to
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

    # closing(): a DB-API "with connection" block only ends the
    # transaction, it does not close the connection.
    with closing(get_connection()) as conn:
        return active_engine().physical_columns(conn, schema_name, table_name)


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
    Return the bare column name from the database's "no such column"
    error, or None. The wording is the engine's (see its
    missing_column()); any table qualifier is dropped because the alias
    lookup that follows works on plain column names.
    """
    return active_engine().missing_column(error_text)


def diagnose_sql_error(sql, error, security, semantic=None):
    """
    Diagnose "no such column" errors. semantic is
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