# Copyright (c) 2026 Brad Long
# Author: Brad Long

import re

from sqlglot import exp


# ---------------------------------------------------------------------------
# Security helpers
# ---------------------------------------------------------------------------

# A name that can be written without quotes.
_PLAIN_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_$]*")


def ident(name):
    """
    A sqlglot identifier for a generated reference. Quoted only when the
    name can't be written plainly (a space or other character, e.g. SQL
    Server's "Order Details"); sqlglot then renders the dialect's quotes,
    [Order Details] or "Order Details". Plain names stay unquoted, so
    their case is matched the way the database matches it.
    """
    return exp.Identifier(this=name, quoted=not _PLAIN_IDENTIFIER.fullmatch(name))


def is_pattern(name):
    """True for a table name with fnmatch wildcards ("sales.*",
    "production.product*")."""
    return any(ch in name for ch in "*?[")


def contains_case_insensitive(values, value):
    """Return True when value matches an item in values, ignoring case."""
    value_lower = value.lower()
    return any(item.lower() == value_lower for item in values)


def get_denied_columns(security, full_table):
    """Return denied columns using case-insensitive table matching."""
    for table_name, denied_columns in security.denied_columns.items():
        if table_name.lower() == full_table.lower():
            return denied_columns
    return set()


def is_authorized_table(security, full_table):
    """Check table authorisation without relying on identifier casing."""
    return contains_case_insensitive(security.tables, full_table)


def default_schema():
    """The schema for a bare table name: the active database's
    default_schema (config/settings/databases.yaml), else its engine's
    default (public for PostgreSQL)."""
    from sqlagent.databases import active_database
    return active_database().default_schema


def full_table_name(table, schema=None):
    """
    The "schema.table" name used throughout (catalog keys, security
    context, domains). schema is the parsed schema of a SQL table
    reference, if any; otherwise a name that already contains a "." is
    returned as-is and a bare name is put in default_schema().
    """
    if schema:
        return f"{schema}.{table}"
    if "." in table:
        return table
    return f"{default_schema()}.{table}"
