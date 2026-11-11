# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# The database engine interface: everything that differs between database
# products (PostgreSQL, SQL Server, ...) lives behind it, so the rest of
# the agent - security policy, semantic model, routing, SQL policy - is
# written once.
#
# The SQL the agent reasons about is handled by sqlglot in the engine's
# dialect, so structural checks, authorisation and rewriting are the same
# for every engine. What an engine supplies is the part sqlglot can't:
#
#   connect            a DB-API connection for a database profile
#   list_tables        every table/view the connected login can see
#   column_rows        the columns of those tables/views (for the catalog)
#   foreign_key_rows   foreign keys, one row per column, in key order
#   physical_columns   a table's columns (internal diagnostics only)
#   execute_readonly   run a validated SELECT with the engine's own
#                      read-only and timeout guards, and trace each result
#                      column back to the table column it came from
#   missing_column     the column named in a "no such column" error
#   sanitize_error     a database error with schema detail removed, safe
#                      to send to the correction model
#   strip_row_limit    the agent's own row cap removed from a query, for
#                      the explanation model
#
# Rows are returned as dicts with the lowercase keys documented on each
# method, whatever the driver's own row type.


class Engine:
    """Base class. Subclasses set the attributes and implement the methods."""

    # Key used in databases.yaml (engine: ...).
    name = None
    # Shown to people and to the LLM ("PostgreSQL").
    label = None
    # sqlglot dialect for parsing and generating SQL.
    dialect = None
    # Schema for a bare table name ("customers" -> "public.customers"),
    # unless the database profile sets default_schema.
    default_schema = None
    # Port when the profile sets none (None: leave it to the driver).
    default_port = None
    # Top-level module of the driver, so the API can tell database errors
    # from model errors (api.py _error_source).
    driver_module = None
    # Syntax rules for the SQL generation prompt (llm.py): identifier
    # case and quoting, and anything else the model gets wrong for this
    # product. One "* ..." bullet per rule.
    prompt_rules = ""

    def quote_name(self, name):
        """One identifier as the model should write it (default: as is)."""
        return name

    def display_table(self, full_name):
        """A "schema.table" name as the model should write it."""
        schema, _, table = full_name.partition(".")
        if not table:
            return self.quote_name(schema)
        return f"{self.quote_name(schema)}.{self.quote_name(table)}"

    def connect(self, profile):
        raise NotImplementedError

    def list_tables(self, conn):
        """Every table and view the login can see, as "schema.table"."""
        raise NotImplementedError

    def column_rows(self, conn):
        """Dicts with table_schema, table_name, column_name, data_type,
        is_nullable ("YES"/"NO"), ordered by table then column position."""
        raise NotImplementedError

    def foreign_key_rows(self, conn):
        """Dicts with constraint_id, parent_schema, parent_table,
        parent_column, referenced_schema, referenced_table,
        referenced_column; one per column, in key order, so a composite
        key keeps its column pairing."""
        raise NotImplementedError

    def physical_columns(self, conn, schema, table):
        """A table's column names in order. Internal diagnostics only."""
        raise NotImplementedError

    def execute_readonly(self, conn, sql, timeout_seconds):
        """
        Run one already-validated SELECT and return (rows, sources): rows
        as dicts, sources as {output column name: [(table, column) | None,
        ...]} - see sql_execution.execute_sql_with_sources().
        """
        raise NotImplementedError

    def missing_column(self, error_text):
        """The bare column name from a "no such column" error, or None."""
        raise NotImplementedError

    def sanitize_error(self, error_text):
        """The error with any schema detail removed."""
        raise NotImplementedError

    def strip_row_limit(self, sql, max_rows):
        """sql without the agent's own row cap of max_rows."""
        raise NotImplementedError

    def __repr__(self):
        return f"<{type(self).__name__} {self.name}>"
