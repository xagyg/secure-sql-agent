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
from sqlagent.execution.engines import active_engine
from sqlagent.execution.sql_execution import get_connection


# ---------------------------------------------------------------------------
# Semantic column aliases
# ---------------------------------------------------------------------------
# The column vocabulary is the semantic model's column labels, aliases and
# column terms (config/databases/<database>/semantic/), the same words the
# catalog uses to pick tables and shows the LLM. Here it is read the other way
# round: the model wrote an alias ("phone") or label as if it were a column, so
# map it back to the physical column (employees.home_phone). This NEVER
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

# ---------------------------------------------------------------------------
# JSON / JSONB type errors
# ---------------------------------------------------------------------------
# A column of type json/jsonb used as plain text or a number ("name =
# 'Australia'", "quantity * standard_price") fails with e.g. "invalid input
# syntax for type json" or "operator does not exist: numeric * jsonb". The
# raw error doesn't say WHICH column is JSON, and a small model asked to
# correct it tends to strip a correct ->>'en_US' and keep the real
# mistake. This names the JSON columns the failed SQL uses, each with its
# note from the semantic model (how to read it), so the retry is told
# exactly what to change.
#
# Only columns in the role's catalog are named: the catalog never holds an
# unauthorised table or a denied column, and the schema these columns
# come from has already been shown to the model.

_JSON_TYPES = ("json", "jsonb")
_JSON_ERROR = re.compile(r"\bjsonb?\b", re.IGNORECASE)


def is_json_type_error(error_text):
    """True when the database error is about a json/jsonb value."""
    return bool(_JSON_ERROR.search(str(error_text or "")))


def json_columns_in_sql(sql, catalog):
    """
    [(table, column, note)] for the json/jsonb columns the SQL refers to,
    in order of first use. table is the bare table name, note the column's
    semantic label/description ("" when it has none). Unparseable SQL, or
    a column that can't be tied to one catalog table, is skipped.
    """
    try:
        tree = parse_single_sql(sql)
    except ValueError:
        return []

    # alias (or bare name) -> catalog table
    by_alias = {}
    for table in tree.find_all(exp.Table):
        full = catalog.resolve_table_name(full_table_name(table.name, table.db))
        if full and full in catalog.tables:
            by_alias[(table.alias_or_name or table.name).lower()] = catalog.tables[full]
            by_alias.setdefault(table.name.lower(), catalog.tables[full])

    def column_of(table, name):
        return next((c for c in table["columns"]
                     if c["name"].lower() == name.lower()), None)

    found, seen = [], set()
    for column in tree.find_all(exp.Column):
        if column.table:
            candidates = [by_alias.get(column.table.lower())]
        else:
            # Unqualified: only when exactly one referenced table has it.
            owners = {id(t): t for t in by_alias.values() if column_of(t, column.name)}
            candidates = list(owners.values()) if len(owners) == 1 else []

        for table in candidates:
            if not table:
                continue
            info = column_of(table, column.name)
            if not info or str(info.get("type", "")).lower() not in _JSON_TYPES:
                continue
            key = (table["name"].lower(), info["name"].lower())
            if key in seen:
                continue
            seen.add(key)
            note = info.get("description") or ""
            found.append((table["name"], info["name"], note))

    return found


def json_correction_hint(sql, error_text, catalog):
    """
    The JSON COLUMNS block for correct_sql(), or "" when the error isn't
    about json or the SQL names no json column.
    """
    if not is_json_type_error(error_text):
        return ""

    columns = json_columns_in_sql(sql, catalog)
    if not columns:
        return ""

    lines = ["JSON COLUMNS IN THE FAILED SQL"]
    for table, column, note in columns:
        if note.upper().startswith("JSON"):
            line = f"- {table}.{column}: {note}"
        else:
            line = f"- {table}.{column} is JSONB" + (f": {note}" if note else "")
        lines.append(line)
    lines += [
        "A JSONB column cannot be compared with text or used in arithmetic",
        "as it is. Read a value out of it with ->> and cast it when a number",
        "is needed, e.g. (col->>'1')::numeric. Keep every ->> that is",
        "already applied to a JSONB column; do not remove it.",
    ]
    return "\n".join(lines) + "\n"
