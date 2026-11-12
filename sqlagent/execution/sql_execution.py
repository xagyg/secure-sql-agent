# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Controlled execution: the final structural-safety check immediately
# before a query reaches the database, then the active database engine's
# own guards (sqlagent/execution/engines/: read-only transaction and
# statement timeout on PostgreSQL).

from contextlib import closing

from sqlglot import exp

from sqlagent.controls.sql_policy import is_safe_sql
from sqlagent.databases import active_database
from sqlagent.execution.engines import active_engine
from sqlagent.settings import get_settings


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# Engine, host, port, database and user come from the active database's
# profile in config/settings/databases.yaml (sqlagent/databases.py); the
# password from the environment variable that profile names (PG_PASSWORD
# by default).

# statement_timeout in config/settings/query.yaml. Validated to be below
# the API's agent_timeout: when the API gives up on a request, the worker
# thread and its database query keep running, so a long statement_timeout
# lets abandoned queries (a cross join, pg_sleep, ...) tie up connections
# long after the visitor has gone.
QUERY_TIMEOUT_SECONDS = get_settings().query.statement_timeout_seconds


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def get_connection():
    return active_engine().connect(active_database())


def list_tables(connection_factory=None):
    """
    Every table and view the connected login can see, as "schema.table".
    Used to expand the security policy's wildcards at startup
    (security_policy.SecurityPolicy.build_context). The engine lists only
    objects the login has some privilege on, so a wildcard can never
    reach past the database's own grants.
    """
    with closing((connection_factory or get_connection)()) as conn:
        return active_engine().list_tables(conn)


def read_hierarchy(table, key, parent, connection_factory=None):
    """
    Every (key, parent) pair in a hierarchy table - e.g. each employee and
    their manager - for the row-scope values "team" and "reports"
    (security_policy.build_context). Read once per user, at sign-in.
    Internal: the identifiers come from the security policy, not a user.
    """
    from sqlagent.controls.row_scope import ident, table_expr

    engine = active_engine()
    query = exp.select(
        exp.alias_(exp.Column(this=ident(key)), "k", quoted=False),
        exp.alias_(exp.Column(this=ident(parent)), "p", quoted=False),
    ).from_(table_expr(table)).sql(dialect=engine.dialect)
    with closing((connection_factory or get_connection)()) as conn:
        rows, _ = engine.execute_readonly(conn, query, QUERY_TIMEOUT_SECONDS)
    return [(row["k"], row["p"]) for row in rows]


def read_foreign_keys(connection_factory=None):
    """
    Every foreign key in the database, as (table, [columns], referenced
    table, [columns]) with the columns in key order - for row-scope 'via'
    rules that leave the join to the foreign key
    (security_policy.SecurityPolicy._resolve_joins). Read once, at startup.
    """
    engine = active_engine()
    keys = {}
    with closing((connection_factory or get_connection)()) as conn:
        for row in engine.foreign_key_rows(conn):
            key = keys.setdefault(row["constraint_id"], (
                f"{row['parent_schema']}.{row['parent_table']}", [],
                f"{row['referenced_schema']}.{row['referenced_table']}", []))
            key[1].append(row["parent_column"])
            key[3].append(row["referenced_column"])
    return list(keys.values())


def execute_sql(sql):
    """
    Execute a read-only SQL query and return the rows.

    See execute_sql_with_sources() for the column provenance used by the
    result policy.
    """
    rows, _sources = execute_sql_with_sources(sql)
    return rows


def execute_sql_with_sources(sql):
    """
    Execute a read-only SQL query.

    Returns (rows, sources): rows is a list of dicts, sources maps each
    output column name to a list of (table, column) tuples, or None for a
    computed column (see the engine's execute_readonly()).

    This is the final structural safety boundary before the database.
    The AI execution path performs the additional authorisation checks
    in validate_agent_sql().

    The connecting user (connection.user in config/settings/databases.yaml)
    should be a dedicated, least-privileged database login with
    SELECT-only grants on the authorised tables — no INSERT/UPDATE/
    DELETE. That gives you a second boundary enforced by the database
    itself, independent of is_safe_sql() below.
    """
    sql = sql.strip().rstrip(";")

    if not is_safe_sql(sql):
        raise ValueError("Only a single read-only SELECT query is permitted.")

    # closing(): a DB-API "with connection" block only ends the
    # transaction, it does not close the connection.
    with closing(get_connection()) as conn:
        return active_engine().execute_readonly(conn, sql, QUERY_TIMEOUT_SECONDS)
