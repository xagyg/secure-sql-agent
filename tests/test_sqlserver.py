# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# SQL Server support (sqlagent/execution/engines/sqlserver.py) and the
# shipped Northwind-on-SQL-Server configuration. No server needed: the
# engine's catalog queries and execution are exercised with a stand-in
# connection that answers as a real SQL Server 2025 did (driver messages,
# sp_describe_first_result_set rows). tools/check_engine.py runs the same
# paths against a real server.

import contextlib
import io
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

import sqlglot
from sqlglot import exp

import sqlagent.databases as databases
from sqlagent.databases import DatabaseConfigError, load_database_profile
from sqlagent.execution.engines import get_engine


ENGINE = get_engine("sqlserver")


@contextlib.contextmanager
def use_database(name):
    """Make `name` the active database for the duration (the modules that
    imported active_database directly are patched too)."""
    profile = load_database_profile(name)
    targets = [
        "sqlagent.databases.active_database",
        "sqlagent.adaptive.llm.active_database",
        "sqlagent.controls.messages.active_database",
        "sqlagent.controls.question_policy.active_database",
    ]
    with contextlib.ExitStack() as stack:
        for target in targets:
            stack.enter_context(mock.patch(target, return_value=profile))
        yield profile


# The Northwind tables as SQL Server reports them (a subset of columns),
# plus one view that the shipped semantic model leaves out.
NORTHWIND_MSSQL = {
    "Categories": ["CategoryID", "CategoryName", "Description"],
    "Customers": ["CustomerID", "CompanyName", "ContactName", "ContactTitle",
                  "Address", "City", "Region", "PostalCode", "Country",
                  "Phone", "Fax"],
    "Employees": ["EmployeeID", "LastName", "FirstName", "Title", "HireDate",
                  "HomePhone", "Photo", "ReportsTo"],
    "Order Details": ["OrderID", "ProductID", "UnitPrice", "Quantity", "Discount"],
    "Orders": ["OrderID", "CustomerID", "EmployeeID", "OrderDate",
               "RequiredDate", "ShippedDate", "ShipVia", "Freight"],
    "Products": ["ProductID", "ProductName", "SupplierID", "CategoryID",
                 "UnitPrice", "UnitsInStock", "ReorderLevel"],
    "Shippers": ["ShipperID", "CompanyName", "Phone"],
    "Suppliers": ["SupplierID", "CompanyName", "ContactName", "Phone"],
    "Invoices": ["ShipName", "CustomerID"],
}
FOREIGN_KEYS = [
    (1, "Order Details", "OrderID", "Orders", "OrderID"),
    (2, "Order Details", "ProductID", "Products", "ProductID"),
    (3, "Orders", "CustomerID", "Customers", "CustomerID"),
    (4, "Orders", "EmployeeID", "Employees", "EmployeeID"),
    (5, "Products", "CategoryID", "Categories", "CategoryID"),
]


def mssql_catalog(role="demo"):
    """The shipped northwind_mssql security policy and semantic model over
    NORTHWIND_MSSQL, as main.py/api.py would build them at startup."""
    from sqlagent.adaptive.schema_catalog import SchemaCatalog
    from sqlagent.adaptive.semantic_model import load_semantic_model
    from sqlagent.controls.security_policy import load_security_policy

    columns = [
        {"table_schema": "dbo", "table_name": t, "column_name": c,
         "data_type": "nvarchar", "is_nullable": "YES", "ordinal_position": i}
        for t, cols in NORTHWIND_MSSQL.items() for i, c in enumerate(cols, 1)
    ]
    keys = [
        {"constraint_id": k, "parent_schema": "dbo", "parent_table": a,
         "parent_column": b, "referenced_schema": "dbo",
         "referenced_table": c, "referenced_column": d}
        for k, a, b, c, d in FOREIGN_KEYS
    ]
    profile = load_database_profile("northwind_mssql")
    with mock.patch.object(ENGINE, "column_rows", return_value=columns), \
         mock.patch.object(ENGINE, "foreign_key_rows", return_value=keys), \
         contextlib.redirect_stdout(io.StringIO()):
        policy = load_security_policy(profile.security_file)
        semantic = load_semantic_model(profile.semantic_path)
        tables = {f"dbo.{t}" for t in NORTHWIND_MSSQL}
        security = policy.build_context("u", {role}, tables, log=False)
        catalog = SchemaCatalog(lambda: mock.MagicMock(), security,
                                semantic=semantic, engine=ENGINE)
        catalog.refresh()
    return catalog, security


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

class Profiles(unittest.TestCase):

    def load(self, engine, connection):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder, "databases.yaml")
            path.write_text(textwrap.dedent(f"""
                version: 1
                default: x
                databases:
                  x:
                    engine: {engine}
                    connection: {connection}
                    repl_roles: [a]
                    demo_roles: [a]
            """), encoding="utf-8")
            return load_database_profile("x", path)

    def test_sqlserver_defaults(self):
        p = self.load("sqlserver", "{host: srv, database: Northwind, user: u}")
        self.assertEqual(p.engine, "sqlserver")
        self.assertEqual(p.default_schema, "dbo")
        self.assertIsNone(p.connection.port)   # left to the driver

    def test_sqlserver_options_rejected_for_postgres(self):
        with self.assertRaisesRegex(DatabaseConfigError, "only for engine: sqlserver"):
            self.load("postgresql", "{database: x, user: u, trust_server_certificate: true}")

    def test_shipped_northwind_mssql(self):
        p = load_database_profile("northwind_mssql")
        self.assertEqual(p.engine, "sqlserver")
        self.assertEqual(p.connection.user, "sqlagent_ro")
        self.assertEqual(p.connection.password_env, "SQLSERVER_PASSWORD")
        self.assertTrue(p.security_file.is_file())
        self.assertTrue((p.semantic_path / "model.yaml").is_file())
        self.assertTrue(all("dbo." in e.sql for e in p.sql_examples))


class ConnectionString(unittest.TestCase):

    def profile(self, **connection):
        spec = {"host": "BRAD-Z640", "database": "Northwind", "user": "sqlagent_ro"}
        spec.update(connection)
        p = mock.MagicMock()
        p.connection = databases.Connection(**spec)
        return p

    def test_defaults(self):
        text = ENGINE.connection_string(self.profile(), "pw")
        self.assertIn("DRIVER={ODBC Driver 18 for SQL Server};", text)
        self.assertIn("SERVER=BRAD-Z640;", text)
        self.assertIn("Encrypt=yes;", text)
        self.assertIn("TrustServerCertificate=no;", text)

    def test_options(self):
        text = ENGINE.connection_string(self.profile(
            port=1450, driver="ODBC Driver 17 for SQL Server",
            trust_server_certificate=True), "pw")
        self.assertIn("SERVER=BRAD-Z640,1450;", text)
        self.assertIn("DRIVER={ODBC Driver 17 for SQL Server};", text)
        self.assertIn("TrustServerCertificate=yes;", text)

    def test_password_cannot_inject_attributes(self):
        text = ENGINE.connection_string(self.profile(), "a;Trusted_Connection=yes}")
        self.assertIn("PWD={a;Trusted_Connection=yes}}};", text)
        self.assertNotIn(";Trusted_Connection=yes;", text)

    def test_named_instance(self):
        text = ENGINE.connection_string(self.profile(host=r"BRAD-Z640\SQLEXPRESS"), "pw")
        self.assertIn(r"SERVER=BRAD-Z640\SQLEXPRESS;", text)


# ---------------------------------------------------------------------------
# Engine text handling (messages as SQL Server 2025 / ODBC Driver 18 gave them)
# ---------------------------------------------------------------------------

MISSING_COLUMN = ("('42S22', \"[42S22] [Microsoft][ODBC Driver 18 for SQL Server]"
                  "[SQL Server]Invalid column name 'PhoneNr'. (207) (SQLExecDirectW)\")")
TWO_ERRORS = ("('42S22', \"[42S22] [Microsoft][ODBC Driver 18 for SQL Server][SQL Server]"
              "Invalid column name 'A'. (207) (SQLExecDirectW); [42S22] [Microsoft]"
              "[ODBC Driver 18 for SQL Server][SQL Server]Invalid column name 'B'. (207)\")")
TIMEOUT = ("('HYT00', '[HYT00] [Microsoft][ODBC Driver 18 for SQL Server]"
           "Query timeout expired (0) (SQLExecDirectW)')")


class Text(unittest.TestCase):

    def test_missing_column(self):
        self.assertEqual(ENGINE.missing_column(MISSING_COLUMN), "PhoneNr")
        self.assertEqual(ENGINE.missing_column(TWO_ERRORS), "A")
        self.assertEqual(ENGINE.missing_column("Invalid column name 'O''Brien'."), "O'Brien")
        self.assertIsNone(ENGINE.missing_column("Invalid object name 'dbo.X'."))

    def test_sanitize(self):
        self.assertEqual(ENGINE.sanitize_error(MISSING_COLUMN),
                         "Invalid column name 'PhoneNr'.")
        self.assertEqual(ENGINE.sanitize_error(TWO_ERRORS),
                         "Invalid column name 'A'.\nInvalid column name 'B'.")
        self.assertEqual(ENGINE.sanitize_error(TIMEOUT), "Query timeout expired")

    def test_strip_row_limit(self):
        self.assertEqual(ENGINE.strip_row_limit("SELECT TOP 100 a FROM t", 100),
                         "SELECT a FROM t")
        self.assertEqual(ENGINE.strip_row_limit("SELECT DISTINCT TOP 100 a FROM t", 100),
                         "SELECT DISTINCT a FROM t")
        self.assertEqual(
            ENGINE.strip_row_limit("SELECT a FROM t ORDER BY a OFFSET 5 ROWS "
                                   "FETCH FIRST 100 ROWS ONLY", 100),
            "SELECT a FROM t ORDER BY a OFFSET 5 ROWS")
        self.assertEqual(ENGINE.strip_row_limit("SELECT TOP 5 a FROM t", 100),
                         "SELECT TOP 5 a FROM t")

    def test_quote_name(self):
        self.assertEqual(ENGINE.quote_name("CompanyName"), "CompanyName")
        self.assertEqual(ENGINE.quote_name("Order Details"), "[Order Details]")
        self.assertEqual(ENGINE.quote_name("Order"), "[Order]")
        self.assertEqual(ENGINE.quote_name("a]b"), "[a]]b]")
        self.assertEqual(ENGINE.display_table("dbo.Order Details"), "dbo.[Order Details]")


# ---------------------------------------------------------------------------
# Execution and column tracing
# ---------------------------------------------------------------------------

class FakeCursor:
    """Answers sp_describe_first_result_set with `described` rows and the
    query itself with `rows`; records the connection timeout in force."""

    def __init__(self, conn):
        self.conn = conn
        self.description = None
        self._rows = []

    def execute(self, sql, params=()):
        self.conn.calls.append((sql.split()[0], self.conn.timeout))
        if sql.startswith("EXEC sp_describe_first_result_set"):
            self.description = [(k,) for k in (
                "is_hidden", "column_ordinal", "name",
                "source_schema", "source_table", "source_column")]
            self._rows = self.conn.described
        else:
            self.description = [(n,) for n in self.conn.names]
            self._rows = self.conn.rows
        return self

    def fetchall(self):
        return list(self._rows)

    def close(self):
        pass


class FakeConnection:
    def __init__(self, names, rows, described):
        self.names, self.rows, self.described = names, rows, described
        self.timeout = 0
        self.calls = []

    def cursor(self):
        return FakeCursor(self)


class Execution(unittest.TestCase):

    def run_query(self, names, rows, described):
        conn = FakeConnection(names, rows, described)
        result = ENGINE.execute_readonly(conn, "SELECT ...", 10)
        return conn, result

    def test_rows_sources_and_timeout(self):
        conn, (rows, sources) = self.run_query(
            ["ContactName", "tel", "n"],
            [("Maria Anders", "030-0074321", 91)],
            [(False, 1, "ContactName", "dbo", "Customers", "ContactName"),
             (False, 2, "tel", "dbo", "Customers", "Phone"),
             (False, 3, "n", None, None, None),
             (True, 4, "CustomerID", "dbo", "Customers", "CustomerID")])  # hidden
        self.assertEqual(rows, [{"ContactName": "Maria Anders",
                                 "tel": "030-0074321", "n": 91}])
        self.assertEqual(sources, {
            "ContactName": [("dbo.Customers", "ContactName")],
            "tel": [("dbo.Customers", "Phone")],          # alias traced
            "n": [None],                                   # computed
        })
        # The timeout was in force for both calls, describe first.
        self.assertEqual(conn.calls, [("EXEC", 10), ("SELECT", 10)])

    def test_view_is_its_own_source(self):
        _, (_, sources) = self.run_query(
            ["ProductName"], [("Chai",)],
            [(False, 1, "ProductName", "dbo", "Alphabetical list of products",
              "ProductName")])
        self.assertEqual(sources["ProductName"],
                         [("dbo.Alphabetical list of products", "ProductName")])

    def test_untraceable_result_is_refused(self):
        with self.assertRaisesRegex(ValueError, "could not be traced"):
            self.run_query(["a", "b"], [(1, 2)],
                           [(False, 1, "a", "dbo", "T", "a")])
        with self.assertRaisesRegex(ValueError, "could not be traced"):
            self.run_query(["a"], [(1,)],
                           [(False, 1, "b", "dbo", "T", "b")])


# ---------------------------------------------------------------------------
# SQL policy in T-SQL
# ---------------------------------------------------------------------------

class Structure(unittest.TestCase):

    def check(self, dialect, sql):
        from sqlagent.controls import sql_policy
        with mock.patch.object(sql_policy, "active_dialect", return_value=dialect):
            try:
                return sql_policy.validate_sql_structure(sql_policy.parse_single_sql(sql))
            except ValueError as ex:
                return False, str(ex)

    def test_blocked_tsql(self):
        for sql in [
            "SELECT * FROM OtherDb.dbo.Customers",
            "SELECT * FROM LinkedSrv.OtherDb.dbo.Customers",
            "SELECT * FROM OPENROWSET('SQLNCLI','Server=x;','SELECT 1') AS a",
            "SELECT * FROM OPENQUERY(L, 'SELECT 1')",
            "SELECT * FROM OPENDATASOURCE('SQLNCLI','Data Source=x').Northwind.dbo.Customers",
            "SELECT (SELECT TOP 1 a FROM OPENQUERY(L, 'x')) AS z",
            "SELECT * FROM dbo.fnSecret(1)",
            "SELECT value FROM STRING_SPLIT('a,b', ',')",
            "SELECT NEXT VALUE FOR dbo.seq",
            "EXEC sp_who",
            "SELECT 1; EXEC xp_cmdshell 'dir'",
            "SELECT * INTO dbo.t FROM dbo.Customers",
        ]:
            with self.subTest(sql=sql):
                self.assertFalse(self.check("tsql", sql)[0])

    def test_allowed_tsql(self):
        for sql in [
            "SELECT * FROM dbo.[Order Details]",
            "SELECT TOP 5 CompanyName FROM dbo.Customers WITH (NOLOCK)",
            "WITH x AS (SELECT CustomerID FROM dbo.Customers) SELECT * FROM x",
            "SELECT c.CompanyName FROM dbo.Customers c JOIN (SELECT CustomerID FROM dbo.Orders) o "
            "ON o.CustomerID = c.CustomerID",
        ]:
            with self.subTest(sql=sql):
                self.assertEqual(self.check("tsql", sql), (True, None))

    def test_postgres_cross_database_and_functions(self):
        self.assertFalse(self.check("postgres", "SELECT * FROM otherdb.public.customers")[0])
        self.assertFalse(self.check("postgres", "SELECT * FROM generate_series(1, 3)")[0])
        self.assertEqual(self.check("postgres", "SELECT * FROM (VALUES (1)) v(x)"),
                         (True, None))


class Pipeline(unittest.TestCase):
    """prepare_sql() end to end on the shipped northwind_mssql config."""

    @classmethod
    def setUpClass(cls):
        cls.stack = contextlib.ExitStack()
        cls.stack.enter_context(use_database("northwind_mssql"))
        cls.catalog, cls.security = mssql_catalog("demo")

    @classmethod
    def tearDownClass(cls):
        cls.stack.close()

    def prepare(self, sql):
        from sqlagent.controls.sql_policy import prepare_sql
        return prepare_sql(sql, self.security, self.catalog)

    def test_catalog(self):
        self.assertNotIn("dbo.Invoices", self.catalog.tables)        # view not in sources
        self.assertNotIn("dbo.Region", self.catalog.tables)          # not allowed for demo
        customers = [c["name"] for c in self.catalog.tables["dbo.Customers"]["columns"]]
        self.assertNotIn("Phone", customers)
        self.assertNotIn("Address", customers)
        employees = [c["name"] for c in self.catalog.tables["dbo.Employees"]["columns"]]
        self.assertNotIn("HomePhone", employees)
        self.assertNotIn("Photo", employees)

    def test_context_brackets_names_with_spaces(self):
        context = self.catalog.get_context("show order details with quantity over 50")
        self.assertIn("TABLE dbo.[Order Details]", context)
        self.assertIn("dbo.[Order Details].OrderID -> dbo.Orders.OrderID", context)

    def test_row_limit_is_top(self):
        r = self.prepare("SELECT CompanyName FROM dbo.Customers")
        self.assertIsNone(r.failure_reason)
        self.assertEqual(r.sql, "SELECT TOP 100 CompanyName FROM dbo.Customers")

    def test_existing_top_kept(self):
        r = self.prepare("SELECT TOP 5 CompanyName FROM dbo.Customers ORDER BY CompanyName")
        self.assertEqual(r.sql, "SELECT TOP 5 CompanyName FROM dbo.Customers ORDER BY CompanyName")

    def test_offset_gets_fetch(self):
        r = self.prepare("SELECT CompanyName FROM dbo.Customers ORDER BY CompanyName OFFSET 5 ROWS")
        self.assertIn("FETCH FIRST 100 ROWS ONLY", r.sql)

    def test_star_on_name_with_space(self):
        r = self.prepare("SELECT * FROM [Order Details] WHERE Quantity > 50")
        self.assertIsNone(r.failure_reason)
        self.assertTrue(r.sql.startswith("SELECT TOP 100 [Order Details].OrderID, "))
        sqlglot.parse_one(r.sql, read="tsql")

    def test_star_drops_denied_columns(self):
        r = self.prepare("SELECT * FROM dbo.Customers WHERE Country = 'Germany'")
        self.assertIsNone(r.failure_reason)
        self.assertNotIn("Phone", r.sql)
        self.assertNotIn("Address", r.sql)
        self.assertIn("Customers.CompanyName", r.sql)

    def test_denied_column_in_projection_is_withheld(self):
        r = self.prepare("SELECT ContactName, Phone FROM dbo.Customers")
        self.assertEqual(r.withheld, ["Phone"])
        self.assertEqual(r.sql, "SELECT TOP 100 ContactName FROM dbo.Customers")

    def test_denied_column_elsewhere_is_blocked(self):
        r = self.prepare("SELECT CompanyName FROM dbo.Customers c WHERE c.Phone LIKE '030%'")
        self.assertIn("not authorised", r.failure_reason)

    def test_bare_name_is_dbo(self):
        r = self.prepare("SELECT ProductName FROM Products WHERE UnitsInStock <= ReorderLevel")
        self.assertIsNone(r.failure_reason)

    def test_view_not_allowed(self):
        self.assertIn("not authorised", self.prepare("SELECT * FROM dbo.Invoices").failure_reason)

    def test_three_part_name_blocked(self):
        r = self.prepare("SELECT CompanyName FROM Northwind.dbo.Customers")
        self.assertIn("Cross-database", r.failure_reason)


class Prompt(unittest.TestCase):

    def prompt(self, database):
        from sqlagent.adaptive import llm
        captured = []
        with use_database(database), \
             mock.patch.object(llm, "ask_ollama",
                               side_effect=lambda m: captured.append(m) or "SELECT 1"):
            llm.generate_sql("q", "SCHEMA", [])
        return captured[0][0]["content"]

    def test_sqlserver_prompt(self):
        text = self.prompt("northwind_mssql")
        self.assertIn("You are a SQL Server assistant working with the Northwind database.", text)
        self.assertIn("SQL Server has no LIMIT", text)
        self.assertIn("-> SELECT ProductName FROM dbo.Products", text)
        self.assertNotIn("snake_case unless", text)
        self.assertNotIn("product_name", text)

    def test_postgres_prompt_keeps_its_rules(self):
        text = self.prompt("northwind")
        self.assertIn("You are a PostgreSQL assistant working with the northwind database.", text)
        self.assertIn("lowercase/snake_case", text)
        self.assertIn('  "how many customers are there?"    -> SELECT COUNT(*) FROM customers\n', text)
        self.assertIn("  \"what information do you have about Jose?\"\n"
                      "    (after an answer naming Jose Pavarotti, a customer contact)\n"
                      + " " * 37 + "-> SELECT * FROM customers", text)


if __name__ == "__main__":
    unittest.main()
