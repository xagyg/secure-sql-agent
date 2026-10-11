# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Ported from pyodbc/SQL Server to psycopg2/PostgreSQL. The security
# boundary this module provides — a final structural-safety check
# immediately before execution — is unchanged.

import os
from contextlib import closing

import psycopg2
import psycopg2.extras

from sqlagent.controls.sql_policy import is_safe_sql


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# Standard libpq environment variables — psql, pg_dump etc. all respect
# these too, so this matches the rest of the Postgres tooling ecosystem.

PG_HOST = os.getenv("PG_HOST")
PG_PORT = os.getenv("PG_PORT")
PG_DATABASE = os.getenv("PG_DATABASE")
PG_USER = os.getenv("PG_USER")
PG_PASSWORD = os.getenv("PG_PASSWORD")

# Keep this comfortably below the API's request timeout (DEMO_AGENT_TIMEOUT
# in api.py). When the API gives up on a request, the worker thread and its
# database query keep running, so a long statement_timeout lets abandoned
# queries (a cross join, pg_sleep, ...) tie up connections long after the
# visitor has gone.
QUERY_TIMEOUT_SECONDS = int(os.getenv("PG_STATEMENT_TIMEOUT_SECONDS", "10"))


# ---------------------------------------------------------------------------
# PostgreSQL
# ---------------------------------------------------------------------------

def get_connection():
    return psycopg2.connect(
        host=PG_HOST,
        port=PG_PORT,
        dbname=PG_DATABASE,
        user=PG_USER,
        password=PG_PASSWORD,
        cursor_factory=psycopg2.extras.RealDictCursor,
    )


def list_tables(connection_factory=None):
    """
    Every table and view the connected role can see, as "schema.table".
    Used to expand the security policy's wildcards at startup
    (security_policy.SecurityPolicy.build_context). information_schema
    only lists objects the database role has some privilege on, so a
    wildcard can never reach past the database's own grants.
    """
    sql = """
    SELECT table_schema, table_name
    FROM information_schema.tables
    WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
      AND table_type IN ('BASE TABLE', 'VIEW')
    """
    with closing((connection_factory or get_connection)()) as conn:
        with conn.cursor() as cursor:
            cursor.execute(sql)
            return {
                f"{row['table_schema']}.{row['table_name']}"
                for row in cursor.fetchall()
            }


def execute_sql(sql):
    """
    Execute a read-only SQL query and return the rows.

    See execute_sql_with_sources() for the column provenance used by the
    result policy.
    """
    rows, _sources = execute_sql_with_sources(sql)
    return rows


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


def _column_sources(cursor, description):
    """
    Work out which table column each result column came from.

    PostgreSQL reports, for every column in a result set, the OID of the
    table it was read from and its column number (cursor.description's
    table_oid / table_column). A computed column (COUNT(*), CONCAT(...),
    a literal) has no source. Result columns are reported under their
    output name, so an alias ("phone AS tel") is still traced to
    suppliers.phone.

    Returns {output column name: (table, column) | None}, where table is
    "schema.table". Two output columns with the same name collapse into
    one dict key in the rows anyway; if their sources differ, both are
    kept here as a list so the policy can check each.
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


def execute_sql_with_sources(sql):
    """
    Execute a read-only SQL query.

    Returns (rows, sources): rows is a list of dicts, sources maps each
    output column name to a list of (table, column) tuples, or None for a
    computed column. See _column_sources().

    This is the final structural safety boundary before PostgreSQL.
    The AI execution path performs the additional authorisation checks
    in validate_agent_sql().

    PG_USER should be a dedicated, least-privileged Postgres role with
    SELECT-only grants on the authorised tables — REVOKE INSERT/UPDATE/
    DELETE from it. That gives you a second boundary enforced by the
    database itself, independent of is_safe_sql() below.
    """
    sql = sql.strip().rstrip(";")

    if not is_safe_sql(sql):
        raise ValueError("Only a single read-only SELECT query is permitted.")

    # closing(): a psycopg2 "with connection" block only ends the
    # transaction, it does not close the connection.
    with closing(get_connection()) as conn:
        # Read-only transaction, enforced by Postgres itself. This is in
        # addition to (not instead of) a SELECT-only role.
        conn.set_session(readonly=True)

        with conn.cursor() as cursor:
            # SET LOCAL scopes the timeout to this transaction only, so
            # it never leaks onto other queries if the connection is
            # ever pooled/reused.
            cursor.execute(
                "SET LOCAL statement_timeout = %s",
                (QUERY_TIMEOUT_SECONDS * 1000,),  # milliseconds
            )
            cursor.execute(sql)

            if cursor.description is None:
                raise ValueError("The SQL statement did not produce a result set.")

            description = cursor.description
            rows = [dict(row) for row in cursor.fetchall()]

            # Same read-only transaction, after the user's query.
            sources = _column_sources(cursor, description)

            return rows, sources
