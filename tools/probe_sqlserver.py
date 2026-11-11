# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Read-only probe of a SQL Server database, to design the SQL Server engine
# (sqlagent/execution/engines/). It changes nothing: every statement is a
# SELECT, a catalog query, sp_describe_first_result_set or WAITFOR.
#
# Usage (from the project root, in the venv):
#     .\.venv\Scripts\pip install pyodbc
#
#   LocalDB (e.g. Visual Studio's ProjectModels instance), Windows login:
#     .\.venv\Scripts\python tools\probe_sqlserver.py --server "(localdb)\ProjectModels" --database northwind --trusted
#   Windows login (your own account):
#     .\.venv\Scripts\python tools\probe_sqlserver.py --server localhost --database Northwind --trusted
#   SQL login:
#     $env:SQLSERVER_PASSWORD = "..."      # or you'll be prompted
#     .\.venv\Scripts\python tools\probe_sqlserver.py --server localhost --database Northwind --user sqlagent_ro
#
# --check-user NAME also checks the permissions of that database user (the
# agent's read-only login) by impersonating it with EXECUTE AS USER, which
# needs an admin account such as your own Windows login. Impersonation is
# reverted straight away and changes nothing.
#
# Paste the whole output back. It never prints a password.

import argparse
import getpass
import os
import re
import sys
import time


def section(title):
    print(f"\n=== {title} " + "=" * max(0, 60 - len(title)))


def rows_as_dicts(cursor):
    names = [d[0] for d in cursor.description]
    return [dict(zip(names, row)) for row in cursor.fetchall()]


def run(cursor, sql, params=()):
    cursor.execute(sql, params)
    return rows_as_dicts(cursor) if cursor.description else []


def attempt(label, fn):
    try:
        fn()
    except Exception as ex:
        print(f"  [{label}] {type(ex).__module__}.{type(ex).__name__}: {ex}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True, help=r'e.g. "localhost\SQLEXPRESS"')
    parser.add_argument("--database", required=True)
    parser.add_argument("--user", help="SQL login (omit with --trusted)")
    parser.add_argument("--trusted", action="store_true",
                        help="Windows authentication (Trusted_Connection)")
    parser.add_argument("--check-user",
                        help="database user to check permissions for, via EXECUTE AS USER")
    parser.add_argument("--driver", help="ODBC driver name (default: newest found)")
    parser.add_argument("--trust-cert", default="yes", choices=["yes", "no"],
                        help="TrustServerCertificate (yes for a local self-signed cert)")
    args = parser.parse_args()
    if not args.trusted and not args.user:
        parser.error("give --user for a SQL login, or --trusted for Windows authentication")

    section("Python / driver")
    print("  python", sys.version.split()[0])
    try:
        import pyodbc
    except ImportError:
        print("  pyodbc is not installed: .\\.venv\\Scripts\\pip install pyodbc")
        return 1
    print("  pyodbc", pyodbc.version)
    drivers = pyodbc.drivers()
    print("  ODBC drivers:", drivers)
    # Only the modern "ODBC Driver N for SQL Server" drivers, newest first.
    # The old built-in "SQL Server" driver can't open (localdb)\... names.
    versioned = sorted(
        (int(m.group(1)), d) for d in drivers
        if (m := re.fullmatch(r"ODBC Driver (\d+) for SQL Server", d)))
    driver = args.driver or (versioned[-1][1] if versioned else None)
    if not driver:
        print("  No SQL Server ODBC driver found. Install 'ODBC Driver 18 for SQL Server'.")
        return 1
    print("  using driver:", driver)

    if args.trusted:
        password = None
        auth = "Trusted_Connection=yes;"
    else:
        password = os.environ.get("SQLSERVER_PASSWORD") or getpass.getpass(
            f"Password for {args.user}: ")
        auth = f"UID={args.user};PWD={password};"

    conn_str = (
        f"DRIVER={{{driver}}};SERVER={args.server};DATABASE={args.database};"
        f"{auth}Encrypt=yes;TrustServerCertificate={args.trust_cert};"
    )
    section("Connect")
    print("  connecting (LocalDB may take up to a minute to start)...", flush=True)
    try:
        conn = pyodbc.connect(conn_str, timeout=60, autocommit=True)
    except Exception as ex:
        message = str(ex)
        print("  FAILED:", message.replace(password, "***") if password else message)
        if "Cannot open database" in message:
            print("  Databases on this server (connect to master to list them):")
            attempt("list databases", lambda: _list_databases(driver, args, auth))
        return 1
    print("  connected")
    cur = conn.cursor()

    section("Databases on this server")
    attempt("databases", lambda: print("  ", [r["name"] for r in run(
        cur, "SELECT name FROM sys.databases ORDER BY name")]))

    section("Database users that could be the agent's login")
    attempt("users", lambda: [print("  ", r) for r in run(cur, """
        SELECT dp.name AS db_user, dp.type_desc, sp.name AS login,
               IS_ROLEMEMBER('db_datareader', dp.name) AS datareader,
               IS_ROLEMEMBER('db_datawriter', dp.name) AS datawriter,
               IS_ROLEMEMBER('db_owner', dp.name)      AS db_owner
        FROM sys.database_principals dp
        LEFT JOIN sys.server_principals sp ON sp.sid = dp.sid
        WHERE dp.type IN ('S', 'U', 'E', 'X') AND dp.principal_id > 4
        ORDER BY dp.name""")])

    section("Server")
    attempt("server", lambda: [print("  ", k, "=", str(v).splitlines()[0]) for k, v in run(cur, """
        SELECT @@VERSION AS version,
               CAST(SERVERPROPERTY('Edition') AS nvarchar(128)) AS edition,
               CAST(SERVERPROPERTY('ProductVersion') AS nvarchar(128)) AS product_version,
               CAST(SERVERPROPERTY('IsIntegratedSecurityOnly') AS int) AS windows_auth_only,
               CAST(SERVERPROPERTY('IsLocalDB') AS int) AS is_localdb,
               CAST(DATABASEPROPERTYEX(DB_NAME(), 'Collation') AS nvarchar(128)) AS db_collation,
               (SELECT compatibility_level FROM sys.databases WHERE name = DB_NAME()) AS compat_level,
               SCHEMA_NAME() AS default_schema,
               ORIGINAL_LOGIN() AS login
    """)[0].items()])

    section("Login permissions (expect reader only)")
    attempt("roles", lambda: print("  ", run(cur, """
        SELECT IS_ROLEMEMBER('db_datareader') AS datareader,
               IS_ROLEMEMBER('db_datawriter') AS datawriter,
               IS_ROLEMEMBER('db_ddladmin')   AS ddladmin,
               IS_ROLEMEMBER('db_owner')      AS db_owner,
               IS_SRVROLEMEMBER('sysadmin')   AS sysadmin
    """)[0]))
    attempt("db perms", lambda: print("   database permissions:", sorted({
        r["permission_name"] for r in run(cur, "SELECT permission_name FROM fn_my_permissions(NULL, 'DATABASE')")})))
    attempt("object perms", lambda: print("   on dbo.Customers:", run(cur, """
        SELECT HAS_PERMS_BY_NAME('dbo.Customers', 'OBJECT', 'SELECT') AS can_select,
               HAS_PERMS_BY_NAME('dbo.Customers', 'OBJECT', 'INSERT') AS can_insert,
               HAS_PERMS_BY_NAME('dbo.Customers', 'OBJECT', 'UPDATE') AS can_update,
               HAS_PERMS_BY_NAME('dbo.Customers', 'OBJECT', 'DELETE') AS can_delete,
               HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'EXECUTE') AS can_execute,
               HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'CREATE TABLE') AS can_create_table
    """)[0]))
    attempt("ad hoc", lambda: print("   server options:", run(cur, """
        SELECT name, CAST(value_in_use AS int) AS value_in_use FROM sys.configurations
        WHERE name IN ('Ad Hoc Distributed Queries', 'xp_cmdshell', 'Ole Automation Procedures',
                       'clr enabled', 'external scripts enabled')
    """)))

    if args.check_user:
        section(f"Permissions of database user {args.check_user} (EXECUTE AS USER)")
        def as_user():
            # Not parameterised: pyodbc sends parameters through
            # sp_prepexec, and an EXECUTE AS inside it is reverted as soon
            # as that call ends, so the checks below would run as you.
            quoted = args.check_user.replace("'", "''")
            cur.execute(f"EXECUTE AS USER = N'{quoted}'")
            try:
                print("  ", run(cur, """
                    SELECT USER_NAME() AS acting_as,
                           IS_ROLEMEMBER('db_datareader') AS datareader,
                           IS_ROLEMEMBER('db_datawriter') AS datawriter,
                           IS_ROLEMEMBER('db_ddladmin')   AS ddladmin,
                           IS_ROLEMEMBER('db_owner')      AS db_owner""")[0])
                print("   database permissions:", sorted({
                    r["permission_name"] for r in run(
                        cur, "SELECT permission_name FROM fn_my_permissions(NULL, 'DATABASE')")}))
                print("   on dbo.Customers:", run(cur, """
                    SELECT HAS_PERMS_BY_NAME('dbo.Customers', 'OBJECT', 'SELECT') AS can_select,
                           HAS_PERMS_BY_NAME('dbo.Customers', 'OBJECT', 'INSERT') AS can_insert,
                           HAS_PERMS_BY_NAME('dbo.Customers', 'OBJECT', 'UPDATE') AS can_update,
                           HAS_PERMS_BY_NAME('dbo.Customers', 'OBJECT', 'DELETE') AS can_delete,
                           HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'EXECUTE') AS can_execute""")[0])
                print("   tables/views it can see:", len(run(
                    cur, "SELECT 1 AS x FROM INFORMATION_SCHEMA.TABLES")))
            finally:
                cur.execute("REVERT")
        attempt("check user", as_user)

    section("Tables and views visible to the login")
    tables = []
    def list_tables():
        tables.extend(run(cur, """
            SELECT TABLE_SCHEMA, TABLE_NAME, TABLE_TYPE FROM INFORMATION_SCHEMA.TABLES
            ORDER BY TABLE_SCHEMA, TABLE_NAME"""))
        for t in tables:
            print(f"   {t['TABLE_SCHEMA']}.{t['TABLE_NAME']}  ({t['TABLE_TYPE']})")
    attempt("tables", list_tables)

    section("Columns: Customers and Order Details")
    attempt("columns", lambda: [print("  ", r) for r in run(cur, """
        SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, DATA_TYPE, IS_NULLABLE, ORDINAL_POSITION
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_NAME IN ('Customers', 'Order Details')
        ORDER BY TABLE_NAME, ORDINAL_POSITION""")])

    section("Foreign keys (first 8 column pairs)")
    attempt("fks", lambda: [print("  ", r) for r in run(cur, """
        SELECT TOP 8
            fk.object_id AS constraint_id,
            SCHEMA_NAME(pt.schema_id) AS parent_schema, pt.name AS parent_table,
            pc.name AS parent_column,
            SCHEMA_NAME(rt.schema_id) AS referenced_schema, rt.name AS referenced_table,
            rc.name AS referenced_column
        FROM sys.foreign_keys fk
        JOIN sys.foreign_key_columns fkc ON fkc.constraint_object_id = fk.object_id
        JOIN sys.tables pt  ON pt.object_id = fkc.parent_object_id
        JOIN sys.columns pc ON pc.object_id = fkc.parent_object_id AND pc.column_id = fkc.parent_column_id
        JOIN sys.tables rt  ON rt.object_id = fkc.referenced_object_id
        JOIN sys.columns rc ON rc.object_id = fkc.referenced_object_id AND rc.column_id = fkc.referenced_column_id
        ORDER BY parent_schema, parent_table, fk.name, fkc.constraint_column_id""")])

    section("Column tracing (sp_describe_first_result_set)")
    views = [t for t in tables if t["TABLE_TYPE"] == "VIEW"]
    probes = [
        "SELECT c.ContactName, c.Phone AS tel, COUNT(*) OVER () AS n FROM dbo.Customers c",
        "SELECT o.OrderID, c.CompanyName, d.Quantity FROM dbo.Orders o "
        "JOIN dbo.Customers c ON c.CustomerID = o.CustomerID "
        "JOIN dbo.[Order Details] d ON d.OrderID = o.OrderID",
        "SELECT x.Phone FROM (SELECT Phone FROM dbo.Customers) AS x",
        "SELECT Phone FROM dbo.Customers UNION SELECT Phone FROM dbo.Suppliers",
    ]
    if views:
        v = views[0]
        probes.append(f"SELECT * FROM [{v['TABLE_SCHEMA']}].[{v['TABLE_NAME']}]")
    for sql in probes:
        for mode in (1, 2):
            def describe(sql=sql, mode=mode):
                rows = run(cur, "EXEC sp_describe_first_result_set @tsql = ?, @params = NULL, "
                                "@browse_information_mode = ?", (sql, mode))
                print(f"   mode {mode}: {sql}")
                for r in rows:
                    if r.get("is_hidden"):
                        continue
                    print(f"      {r['name']!s:<16} <- {r.get('source_schema')}.{r.get('source_table')}"
                          f".{r.get('source_column')}  computed={r.get('is_computed_column')}")
            attempt(f"describe mode {mode}", describe)

    section("Error texts")
    attempt("missing column", lambda: run(cur, "SELECT c.PhoneNr FROM dbo.Customers c"))
    attempt("missing table", lambda: run(cur, "SELECT * FROM dbo.NoSuchTable"))
    attempt("syntax", lambda: run(cur, "SELECT FROM WHERE"))

    section("Query timeout (cursor/connection timeout = 1s, WAITFOR 3s)")
    def timeout():
        # pyodbc applies conn.timeout to cursors created AFTER it is set.
        conn.timeout = 1
        started = time.time()
        try:
            fresh = conn.cursor()
            try:
                run(fresh, "WAITFOR DELAY '00:00:03'; SELECT 1 AS x")
                print(f"   NOT cancelled ({time.time() - started:.1f}s)")
            except Exception as ex:
                print(f"   cancelled after {time.time() - started:.1f}s: "
                      f"{type(ex).__name__}: {ex}")
            finally:
                fresh.close()
        finally:
            conn.timeout = 0
    attempt("timeout", timeout)
    print("   after timeout, connection usable:", end=" ")
    attempt("reuse", lambda: print(run(cur, "SELECT 1 AS ok")))

    section("Impersonation test: user without login, EXECUTE AS ... WITH NO REVERT")
    # Everything happens inside a transaction that is rolled back, so the
    # test user never persists. Uses a separate connection, because
    # WITH NO REVERT can't be undone on the connection that runs it.
    def impersonation():
        test = pyodbc.connect(conn_str, timeout=60, autocommit=False)
        c = test.cursor()
        try:
            c.execute("CREATE USER probe_ro_test WITHOUT LOGIN")
            c.execute("ALTER ROLE db_datareader ADD MEMBER probe_ro_test")
            c.execute("EXECUTE AS USER = N'probe_ro_test' WITH NO REVERT")
            print("  ", run(c, "SELECT USER_NAME() AS acting_as, "
                               "IS_ROLEMEMBER('db_datareader') AS datareader, "
                               "IS_SRVROLEMEMBER('sysadmin') AS sysadmin, "
                               "(SELECT COUNT(*) FROM dbo.Customers) AS customers_readable")[0])
            for label, sql in [
                ("UPDATE", "UPDATE dbo.Customers SET City = City WHERE 1 = 0"),
                ("CREATE TABLE", "CREATE TABLE dbo.probe_x (i int)"),
                ("REVERT", "REVERT"),
                ("other database", "SELECT TOP 1 name FROM msdb.dbo.sysjobs"),
            ]:
                try:
                    c.execute(sql)
                    print(f"   {label}: ALLOWED")
                except Exception as ex:
                    print(f"   {label}: blocked ({str(ex).split('[SQL Server]')[-1][:90]})")
        finally:
            test.rollback()
            test.close()
    attempt("impersonation", impersonation)

    section("Row values (types as returned by pyodbc)")
    attempt("types", lambda: [print("  ", {k: f"{type(v).__name__}:{v}" for k, v in r.items()})
                              for r in run(cur, "SELECT TOP 2 * FROM dbo.Orders ORDER BY OrderID")])

    conn.close()
    section("Done")
    return 0


def _list_databases(driver, args, auth):
    import pyodbc
    conn = pyodbc.connect(
        f"DRIVER={{{driver}}};SERVER={args.server};DATABASE=master;{auth}"
        f"Encrypt=yes;TrustServerCertificate={args.trust_cert};", timeout=10)
    print("  ", [r[0] for r in conn.cursor().execute(
        "SELECT name FROM sys.databases ORDER BY name").fetchall()])
    conn.close()


if __name__ == "__main__":
    sys.exit(main())
