# Copyright (c) 2026 Brad Long
# Author: Brad Long

# ---------------------------------------------------------------------------
# Security helpers
# ---------------------------------------------------------------------------


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
