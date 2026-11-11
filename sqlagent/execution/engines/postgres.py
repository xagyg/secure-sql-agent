# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# PostgreSQL, through psycopg2. Moved here unchanged from
# sql_execution.py, schema_catalog.py, sql_diagnostics.py and agent.py
# when the engine interface (base.py) was introduced.

import re

import psycopg2
import psycopg2.extras

from sqlagent.execution.engines.base import Engine


# information_schema covers tables AND views, so a view such as
# semantic.employees_v is discovered like any table.
_TABLES_SQL = """
SELECT table_schema, table_name
FROM information_schema.tables
WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
  AND table_type IN ('BASE TABLE', 'VIEW')
"""

_COLUMNS_SQL = """
SELECT
    c.table_schema,
    c.table_name,
    c.column_name,
    c.data_type,
    c.is_nullable,
    c.ordinal_position
FROM information_schema.columns c
WHERE c.table_schema NOT IN ('pg_catalog', 'information_schema')
ORDER BY
    c.table_schema,
    c.table_name,
    c.ordinal_position
"""

# pg_constraint gives each foreign key once, with its columns in order, so
# a composite key (company_id, order_no) comes back as one relationship
# rather than one per column.
_FOREIGN_KEYS_SQL = """
SELECT
    con.oid AS constraint_id,
    pn.nspname AS parent_schema,
    pc.relname AS parent_table,
    pa.attname AS parent_column,
    rn.nspname AS referenced_schema,
    rc.relname AS referenced_table,
    ra.attname AS referenced_column
FROM pg_constraint con
CROSS JOIN LATERAL unnest(con.conkey, con.confkey)
    WITH ORDINALITY AS k(parent_attnum, ref_attnum, ord)
JOIN pg_class pc     ON pc.oid = con.conrelid
JOIN pg_namespace pn ON pn.oid = pc.relnamespace
JOIN pg_attribute pa ON pa.attrelid = con.conrelid  AND pa.attnum = k.parent_attnum
JOIN pg_class rc     ON rc.oid = con.confrelid
JOIN pg_namespace rn ON rn.oid = rc.relnamespace
JOIN pg_attribute ra ON ra.attrelid = con.confrelid AND ra.attnum = k.ref_attnum
WHERE con.contype = 'f'
ORDER BY pn.nspname, pc.relname, con.conname, k.ord
"""

_PHYSICAL_COLUMNS_SQL = """
    SELECT column_name
    FROM information_schema.columns
    WHERE table_schema = %s
      AND table_name = %s
    ORDER BY ordinal_position
"""

# Maps result columns back to the table column they were read from.
_SOURCE_SQL = """
SELECT a.attrelid AS table_oid,
       a.attnum   AS column_number,
       n.nspname  AS schema_name,
       c.relname  AS table_name,
       a.attname  AS column_name
FROM pg_attribute a
JOIN pg_class c     ON c.oid = a.attrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE a.attrelid = ANY(%s::oid[])
  AND a.attnum > 0
"""


class PostgresEngine(Engine):
    name = "postgresql"
    label = "PostgreSQL"
    dialect = "postgres"
    default_schema = "public"
    default_port = 5432
    driver_module = "psycopg2"
    prompt_rules = """\
* Table and column names are lowercase/snake_case unless the schema
  above shows otherwise — do not invent camelCase names.
* Only use double quotes around an identifier if the schema above
  shows it needs them (e.g. a mixed-case or reserved-word name)."""

    # -- connection ---------------------------------------------------------

    def connect(self, profile):
        c = profile.connection
        return psycopg2.connect(
            host=c.host,
            port=c.port,
            dbname=c.database,
            user=c.user,
            password=profile.password(),
            cursor_factory=psycopg2.extras.RealDictCursor,
        )

    # -- catalog ------------------------------------------------------------

    def list_tables(self, conn):
        # information_schema only lists objects the database role has some
        # privilege on, so a wildcard in the security policy can never
        # reach past the database's own grants.
        with conn.cursor() as cursor:
            cursor.execute(_TABLES_SQL)
            return {
                f"{row['table_schema']}.{row['table_name']}"
                for row in cursor.fetchall()
            }

    def column_rows(self, conn):
        with conn.cursor() as cursor:
            cursor.execute(_COLUMNS_SQL)
            return cursor.fetchall()

    def foreign_key_rows(self, conn):
        with conn.cursor() as cursor:
            cursor.execute(_FOREIGN_KEYS_SQL)
            return cursor.fetchall()

    def physical_columns(self, conn, schema, table):
        with conn.cursor() as cursor:
            cursor.execute(_PHYSICAL_COLUMNS_SQL, (schema, table))
            return [row["column_name"] for row in cursor.fetchall()]

    # -- execution ----------------------------------------------------------

    def execute_readonly(self, conn, sql, timeout_seconds):
        # Read-only transaction, enforced by Postgres itself. This is in
        # addition to (not instead of) a SELECT-only role.
        conn.set_session(readonly=True)

        with conn.cursor() as cursor:
            # SET LOCAL scopes the timeout to this transaction only, so it
            # never leaks onto other queries if the connection is ever
            # pooled/reused.
            cursor.execute(
                "SET LOCAL statement_timeout = %s",
                (timeout_seconds * 1000,),  # milliseconds
            )
            cursor.execute(sql)

            if cursor.description is None:
                raise ValueError("The SQL statement did not produce a result set.")

            description = cursor.description
            rows = [dict(row) for row in cursor.fetchall()]

            # Same read-only transaction, after the user's query.
            sources = self._column_sources(cursor, description)

            return rows, sources

    def _column_sources(self, cursor, description):
        """
        Work out which table column each result column came from.

        PostgreSQL reports, for every column in a result set, the OID of
        the table it was read from and its column number
        (cursor.description's table_oid / table_column). A computed column
        (COUNT(*), CONCAT(...), a literal) has no source. Result columns
        are reported under their output name, so an alias ("phone AS
        tel") is still traced to suppliers.phone.

        Returns {output column name: [(table, column) | None, ...]}, where
        table is "schema.table". Two output columns with the same name
        collapse into one dict key in the rows anyway; if their sources
        differ, both are kept here so the policy can check each.
        """
        oids = sorted({
            col.table_oid for col in description
            if getattr(col, "table_oid", None)
        })

        lookup = {}
        if oids:
            cursor.execute(_SOURCE_SQL, (oids,))
            for row in cursor.fetchall():
                lookup[(row["table_oid"], row["column_number"])] = (
                    f"{row['schema_name']}.{row['table_name']}",
                    row["column_name"],
                )

        sources = {}
        for col in description:
            source = lookup.get((getattr(col, "table_oid", None),
                                 getattr(col, "table_column", None)))
            sources.setdefault(col.name, []).append(source)

        return sources

    # -- errors -------------------------------------------------------------

    def missing_column(self, error_text):
        """
        Postgres words the error differently depending on how the column
        was referenced, e.g.:

            column "phone" does not exist        (unqualified)
            column e.phone does not exist        (table alias / name qualifier)
            column e."Phone" does not exist      (quoted identifier)

        Only the column part is returned ("phone"); any qualifier is
        dropped because the alias lookup that follows works on plain
        column names. Only the first line is read, so a HINT further down
        can't be mistaken for the failing column.
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

    def sanitize_error(self, error_text):
        """
        Remove PostgreSQL DETAIL/HINT sections. The full error stays in the
        local log, but hints/details can disclose physical schema
        information to the correction model.
        """
        return re.sub(
            r"(?ms)^\s*(?:DETAIL|HINT):.*?(?=^\s*(?:DETAIL|HINT):|\Z)",
            "",
            error_text,
        ).strip()

    def strip_row_limit(self, sql, max_rows):
        """Postgres renders the agent's row cap as "LIMIT n"."""
        return re.sub(
            rf"\bLIMIT\s+{max_rows}\b\s*",
            "",
            sql,
            flags=re.IGNORECASE,
        )
