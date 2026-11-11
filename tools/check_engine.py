# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Checks a configured database end to end WITHOUT the LLM: connection,
# catalog, security filtering, the SQL policy, read-only execution, column
# tracing, the query timeout and error handling. Read-only throughout.
#
# Usage (from the project root):
#     .\.venv\Scripts\python tools\check_engine.py --db northwind_mssql
#     .\.venv\Scripts\python tools\check_engine.py --db northwind
#
# The password comes from the variable the database's password_env names
# (SQLSERVER_PASSWORD, PG_PASSWORD, ...); if it isn't set you're asked for
# it. Prints PASS / FAIL / WARN per check and exits non-zero on any FAIL.

import argparse
import contextlib
import getpass
import io
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

RESULTS = {"PASS": 0, "FAIL": 0, "WARN": 0}


def report(status, check, detail=""):
    RESULTS[status] += 1
    print(f"  {status:<4}  {check}" + (f"  -- {detail}" if detail else ""))


def section(title):
    print(f"\n=== {title}")


def quietly(fn, *args, **kwargs):
    """Run fn with the agent's own [schema]/[security] logging captured."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        result = fn(*args, **kwargs)
    return result, out.getvalue()


# A query that runs for several seconds, per engine, to test the timeout.
SLOW_QUERY = {
    "postgresql": "SELECT pg_sleep(5) AS slept",
    "sqlserver": ("SELECT COUNT_BIG(*) AS n FROM sys.all_columns a "
                  "CROSS JOIN sys.all_columns b CROSS JOIN sys.all_columns c"),
}

# Login permission check, per engine: rows of (check, value, expected).
PERMISSIONS = {
    "sqlserver": """
        SELECT IS_ROLEMEMBER('db_datareader') AS datareader,
               IS_ROLEMEMBER('db_datawriter') AS datawriter,
               IS_ROLEMEMBER('db_ddladmin')   AS ddladmin,
               IS_ROLEMEMBER('db_owner')      AS db_owner,
               IS_SRVROLEMEMBER('sysadmin')   AS sysadmin,
               HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'EXECUTE') AS can_execute
    """,
    "postgresql": """
        SELECT rolsuper AS superuser, rolcreaterole AS createrole,
               rolcreatedb AS createdb
        FROM pg_roles WHERE rolname = current_user
    """,
}
EXPECTED = {
    "datareader": 1, "datawriter": 0, "ddladmin": 0, "db_owner": 0,
    "sysadmin": 0, "can_execute": 0,
    "superuser": False, "createrole": False, "createdb": False,
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True, help="a name in config/settings/databases.yaml")
    parser.add_argument("--role", help="role to check as (default: the database's demo_roles)")
    args = parser.parse_args()
    os.environ["SQLAGENT_DATABASE"] = args.db

    section("Configuration")
    from sqlagent.databases import load_database_profile
    profile = load_database_profile(args.db)
    var = profile.connection.password_env
    if not os.environ.get(var):
        os.environ[var] = getpass.getpass(f"Password ({var}): ")
    os.environ.setdefault("OLLAMA_MODEL", "unused")   # the LLM isn't called

    from sqlagent.settings import get_settings
    settings, _ = quietly(get_settings)
    from sqlagent.databases import active_database
    profile, _ = quietly(active_database)
    from sqlagent.execution.engines import active_engine
    engine = active_engine()
    print(f"  {profile.describe()}")
    print(f"  engine {engine.label} (dialect {engine.dialect}), "
          f"max_rows {settings.query.max_rows}, "
          f"statement timeout {settings.query.statement_timeout_seconds}s")

    from sqlagent.execution import sql_execution as se
    from sqlagent.controls.security_policy import load_security_policy
    from sqlagent.adaptive.semantic_model import load_semantic_model
    from sqlagent.adaptive.schema_catalog import SchemaCatalog
    from sqlagent.controls.sql_policy import prepare_sql, is_safe_sql
    from sqlagent.controls.security_utils import get_denied_columns

    section("Connection and login")
    try:
        conn = se.get_connection()
        report("PASS", "connect")
    except Exception as ex:
        report("FAIL", "connect", str(ex))
        return finish()
    try:
        cursor = conn.cursor()
        cursor.execute(PERMISSIONS[engine.name])
        names = [d[0] for d in cursor.description]
        fetched = cursor.fetchone()
        # psycopg2's RealDictCursor gives a dict; pyodbc a tuple-like row.
        row = dict(fetched) if isinstance(fetched, dict) else dict(zip(names, fetched))
        cursor.close()
        bad = {k: v for k, v in row.items() if k in EXPECTED and v != EXPECTED[k]}
        if bad:
            report("FAIL", "login is read-only", f"unexpected: {bad} (all: {row})")
        else:
            report("PASS", "login is read-only", str(row))
    except Exception as ex:
        report("WARN", "login permissions", f"could not check: {ex}")
    finally:
        conn.close()

    section("Catalog")
    tables, _ = quietly(se.list_tables, se.get_connection)
    report("PASS" if tables else "FAIL", "list tables", f"{len(tables)} visible to the login")
    (policy, semantic), _ = quietly(lambda: (load_security_policy(), load_semantic_model()))
    role = {args.role} if args.role else set(profile.demo_roles)
    security, _ = quietly(policy.build_context, "check", role, tables, log=False)
    catalog = SchemaCatalog(se.get_connection, security, semantic=semantic)
    _, log = quietly(catalog.refresh)
    report("PASS" if catalog.tables else "FAIL", f"catalog for role {sorted(role)}",
           f"{len(catalog.tables)} tables, {len(catalog.foreign_keys)} relationships")
    skipped = 0
    for line in log.splitlines():
        if "WARNING" in line:
            report("WARN", "catalog log", line.strip())
        elif "not available" in line:
            skipped += 1   # vocabulary for tables/columns this role can't see
    if skipped:
        print(f"  info  {skipped} semantic-model entries skipped: their tables or "
              "columns aren't visible to this role (normal for a narrow role)")

    table_name = sorted(catalog.tables)[0]
    table = catalog.tables[table_name]
    shown = engine.display_table(table_name)
    denied = next(((t, sorted(get_denied_columns(security, t))[0])
                   for t in sorted(catalog.tables) if get_denied_columns(security, t)),
                  None)

    section("SQL policy and execution")

    def run(sql):
        prepared = prepare_sql(sql, security, catalog)
        if prepared.failure_reason:
            return prepared, None, None
        rows, sources = se.execute_sql_with_sources(prepared.sql)
        return prepared, rows, sources

    try:
        prepared, rows, sources = run(f"SELECT * FROM {shown}")
        ok = prepared.failure_reason is None and rows is not None
        report("PASS" if ok else "FAIL", f"SELECT * FROM {shown}",
               prepared.failure_reason or
               f"{len(rows)} rows, ran as: {prepared.sql[:100]}")
        if ok:
            traced = sum(1 for s in sources.values() if s and s[0])
            report("PASS" if traced == len(sources) else "FAIL",
                   "every column traced to its table", f"{traced}/{len(sources)}")
    except Exception as ex:
        report("FAIL", f"SELECT * FROM {shown}", f"{type(ex).__name__}: {ex}")

    first = table["columns"][0]["name"]
    try:
        prepared, rows, sources = run(
            f"SELECT {engine.quote_name(first)} AS renamed, COUNT(*) OVER () AS n "
            f"FROM {shown}")
        src = sources.get("renamed", [None])[0] if sources else None
        ok = src is not None and src[1].lower() == first.lower() and sources.get("n") == [None]
        report("PASS" if ok else "FAIL", "alias traced, computed column untraced",
               f"renamed <- {src}, n <- {sources.get('n') if sources else None}")
    except Exception as ex:
        report("FAIL", "alias tracing", f"{type(ex).__name__}: {ex}")

    if denied:
        t, column = denied
        dshown = engine.display_table(t)
        dcol = engine.quote_name(column)
        keep = next(c["name"] for c in catalog.tables[t]["columns"])
        prepared, rows, _ = run(f"SELECT {engine.quote_name(keep)}, {dcol} FROM {dshown}")
        ok = prepared.withheld and rows is not None
        report("PASS" if ok else "FAIL", f"denied column {t}.{column} withheld from results",
               f"ran as: {prepared.sql[:100]}")
        prepared, rows, _ = run(f"SELECT {engine.quote_name(keep)} FROM {dshown} "
                                f"WHERE {dcol} IS NOT NULL")
        report("PASS" if prepared.failure_reason else "FAIL",
               f"denied column {t}.{column} blocked in WHERE", prepared.failure_reason or "ran!")
    else:
        report("WARN", "denied columns", "this role has none to test")

    database = profile.connection.database
    for label, sql in [
        ("cross-database name", f"SELECT * FROM {database}.{shown}"),
        ("two statements", f"SELECT 1 AS a; SELECT 2 AS b"),
        ("data change", f"DELETE FROM {shown}"),
        ("table the role can't see", "SELECT * FROM no_such_schema.no_such_table"),
    ] + ([("external data", "SELECT * FROM OPENROWSET('SQLNCLI', 'Server=x;', 'SELECT 1') AS a")]
         if engine.name == "sqlserver" else []):
        prepared = prepare_sql(sql, security, catalog)
        report("PASS" if prepared.failure_reason else "FAIL", f"blocked: {label}",
               prepared.failure_reason or "NOT BLOCKED")

    section("Timeout and errors")
    conn = se.get_connection()
    try:
        started = time.time()
        try:
            engine.execute_readonly(conn, SLOW_QUERY[engine.name], 1)
            report("FAIL", "1s timeout cancels a slow query",
                   f"finished after {time.time() - started:.1f}s")
        except Exception as ex:
            took = time.time() - started
            report("PASS" if took < 4 else "FAIL", "1s timeout cancels a slow query",
                   f"cancelled after {took:.1f}s: {engine.sanitize_error(str(ex))}")
    finally:
        conn.close()

    bad = engine.quote_name("NoSuchColumnXyz")
    try:
        se.execute_sql_with_sources(f"SELECT {bad} FROM {shown}")
        report("FAIL", "missing column error", "query ran")
    except Exception as ex:
        name = engine.missing_column(str(ex))
        clean = engine.sanitize_error(str(ex))
        report("PASS" if name and name.lower() == "nosuchcolumnxyz" else "FAIL",
               "missing column recognised", f"{name!r}; model would see: {clean!r}")

    report("PASS" if not is_safe_sql(f"SELECT 1 AS a; DELETE FROM {shown}") else "FAIL",
           "execution gate refuses a second statement")
    return finish()


def finish():
    print(f"\n{RESULTS['PASS']} passed, {RESULTS['FAIL']} failed, {RESULTS['WARN']} warnings")
    return 1 if RESULTS["FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main())
