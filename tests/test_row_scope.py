# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Row scope (controls/row_scope.py, security_policy.py scopes and
# group_grants). No database needed: filters are compiled from small
# in-memory policies and the shipped Northwind ones, and the rewrite is
# checked on the SQL text. The rewrite was also checked against a real
# PostgreSQL database with hand-written ground-truth views for every
# shipped identity and 23 query shapes (README "Row-level security");
# tools/check_row_scope.py runs consistency checks on a real database.

import contextlib
import io
import textwrap
import unittest
from unittest import mock

import sqlglot
import yaml
from sqlglot import exp

from sqlagent.controls.row_scope import (
    RowScopeError,
    apply_row_scope,
    verify_row_scope,
)
from sqlagent.controls.security_policy import SecurityPolicy, SecurityPolicyError


TABLES = {
    "public.orders", "public.order_details", "public.customers",
    "public.employees", "public.products", "public.region",
}

POLICY = """
version: 1
default: deny
roles:
  sales_manager:
    scope: required
    allow: [orders, order_details, customers, employees, products]
    deny_columns:
      customers: [phone]
  hr:
    allow: [employees]
  catalogue:
    allow: [products]
scopes:
  salesperson:
    user_attribute: employee_id
    hierarchy: {table: employees, key: employee_id, parent: reports_to}
    tables:
      orders:        {column: employee_id}
      order_details: {via: orders, join: {order_id: order_id}}
      customers:     {via: orders, join: {customer_id: customer_id}}
      employees:     {column: employee_id}
      products:      unscoped
  country:
    tables:
      customers:     {column: country}
      orders:        {via: customers, join: {customer_id: customer_id}}
      order_details: {via: orders, join: {order_id: order_id}}
      employees:     unscoped
      products:      unscoped
group_grants:
  National: [{role: sales_manager, scope: unrestricted}]
  Team:     [{role: sales_manager, scope: {salesperson: team}}]
  Self:     [{role: sales_manager, scope: {salesperson: self}}]
  Reports:  [{role: sales_manager, scope: {salesperson: reports}}]
  Germany:  [{role: sales_manager, scope: {country: [Germany]}}]
  Fixed:    [{role: sales_manager, scope: {salesperson: [1, 3]}}]
  Both:     [{role: sales_manager, scope: {salesperson: [1], country: [France]}}]
  HR:       [{role: hr}]
group_roles:
  Catalogue: [catalogue]
"""

# employee -> manager: 2 at the top; 1, 5 report to 2; 6, 7 to 5; 9 to 7
HIERARCHY = [(2, None), (1, 2), (5, 2), (6, 5), (7, 5), (9, 7)]


def policy(text=POLICY):
    return SecurityPolicy.from_dict(yaml.safe_load(textwrap.dedent(text)))


def context(groups, attributes=None, text=POLICY, roles=()):
    with contextlib.redirect_stdout(io.StringIO()):
        return policy(text).build_context(
            "u", set(roles), TABLES, groups=groups, attributes=attributes or {},
            read_hierarchy=lambda *_: HIERARCHY, log=False)


def sql(expression):
    return expression.sql(dialect="postgres")


class Grants(unittest.TestCase):

    def test_unrestricted_has_no_filters(self):
        ctx = context(["National"])
        self.assertEqual(ctx.row_filters, {})
        self.assertIn("public.orders", ctx.tables)

    def test_column_and_via_chain(self):
        f = context(["Fixed"]).row_filters
        self.assertEqual(sql(f["public.orders"]), "_t.employee_id IN (1, 3)")
        self.assertEqual(
            sql(f["public.order_details"]),
            "EXISTS(SELECT 1 FROM public.orders AS _s1 WHERE _s1.order_id = _t.order_id "
            "AND _s1.employee_id IN (1, 3))")
        self.assertNotIn("public.products", f)          # unscoped

    def test_two_level_chain(self):
        f = context(["Germany"]).row_filters
        self.assertEqual(
            sql(f["public.order_details"]),
            "EXISTS(SELECT 1 FROM public.orders AS _s1 WHERE _s1.order_id = _t.order_id "
            "AND EXISTS(SELECT 1 FROM public.customers AS _s2 WHERE _s2.customer_id = "
            "_s1.customer_id AND _s2.country IN ('Germany')))")

    def test_relative_values(self):
        self.assertEqual(context(["Self"], {"employee_id": 5}).grants,
                         ["sales_manager (salesperson [5])"])
        self.assertEqual(context(["Team"], {"employee_id": 5}).grants,
                         ["sales_manager (salesperson [5, 6, 7, 9])"])
        self.assertEqual(context(["Reports"], {"employee_id": 5}).grants,
                         ["sales_manager (salesperson [6, 7, 9])"])

    def test_unresolvable_relative_value_gives_no_rows(self):
        f = context(["Team"], {}).row_filters
        self.assertEqual(sql(f["public.orders"]), "1 = 0")
        self.assertEqual(sql(context(["Reports"], {"employee_id": 6}).row_filters["public.orders"]),
                         "1 = 0")    # nobody below 6

    def test_several_dimensions_and(self):
        f = context(["Both"]).row_filters
        self.assertTrue(sql(f["public.orders"]).startswith("_t.employee_id IN (1) AND EXISTS("))

    def test_grants_combine_with_or(self):
        f = context(["Fixed", "Germany"]).row_filters
        text = sql(f["public.orders"])
        self.assertIn("_t.employee_id IN (1, 3)", text)
        self.assertIn(" OR ", text)
        self.assertIn("'Germany'", text)

    def test_unrestricted_grant_wins(self):
        self.assertEqual(context(["Fixed", "National"]).row_filters, {})

    def test_other_roles_do_not_touch_scoped_rows(self):
        # HR's unscoped employees grant opens employees only.
        f = context(["Fixed", "HR"]).row_filters
        self.assertNotIn("public.employees", f)
        self.assertIn("public.orders", f)

    def test_group_roles_still_work(self):
        ctx = context(["Catalogue"])
        self.assertEqual(ctx.tables, {"public.products"})
        self.assertEqual(ctx.row_filters, {})

    def test_column_rule_same_rows_unions_as_before(self):
        # Same rows under both grants: a column hidden only if both hide it.
        ctx = context(["Fixed"])
        self.assertEqual(ctx.denied_columns.get("public.customers"), {"phone"})

    def test_columns_narrow_when_grants_see_different_rows(self):
        text = POLICY.replace("  catalogue:\n", "  sales_open:\n    allow: [customers]\n  catalogue:\n")
        text = text.replace("  HR:       [{role: hr}]", "  HR:       [{role: hr}]\n  Open:     [{role: sales_open}]")
        ctx = context(["Fixed", "Open"], text=text)
        # sales_open sees all customers WITH phone; sales_manager sees some
        # customers WITHOUT it. Rows differ, so phone stays hidden.
        self.assertEqual(ctx.denied_columns.get("public.customers"), {"phone"})


class FailClosed(unittest.TestCase):

    def check(self, text, message, groups=("Team",), attributes=None):
        with self.assertRaisesRegex(SecurityPolicyError, message):
            context(list(groups), attributes or {"employee_id": 5}, text=text)

    def test_table_without_rule_stops_startup(self):
        self.check(POLICY.replace("      products:      unscoped\n  country:", "  country:"),
                   "salesperson.*no rule for public.products")

    def test_required_scope_through_group_roles(self):
        self.check(POLICY.replace("  Catalogue: [catalogue]", "  Catalogue: [sales_manager]"),
                   "need a scope")

    def test_required_scope_held_directly(self):
        with self.assertRaisesRegex(SecurityPolicyError, "needs a scope"):
            context([], roles={"sales_manager"})

    def test_grant_without_scope_for_required_role(self):
        self.check(POLICY.replace("National: [{role: sales_manager, scope: unrestricted}]",
                                  "National: [{role: sales_manager}]"), "needs a scope")

    def test_unknown_scope(self):
        self.check(POLICY.replace("{country: [Germany]}", "{colour: [red]}"), "undefined scope")

    def test_self_needs_attribute_setting(self):
        self.check(POLICY.replace("    user_attribute: employee_id\n", ""), "user_attribute")

    def test_team_needs_hierarchy(self):
        self.check(POLICY.replace(
            "    hierarchy: {table: employees, key: employee_id, parent: reports_to}\n", ""),
            "hierarchy")

    def test_via_unknown_table(self):
        self.check(POLICY.replace("{via: orders, join: {customer_id: customer_id}}",
                                  "{via: invoices, join: {customer_id: customer_id}}"),
                   "public.invoices, which has no rule")

    def test_via_unscoped_table(self):
        self.check(POLICY.replace("{via: orders, join: {customer_id: customer_id}}",
                                  "{via: products, join: {customer_id: customer_id}}"),
                   "unscoped - nothing would restrict it")

    def test_via_cycle(self):
        self.check(POLICY.replace("      orders:        {column: employee_id}",
                                  "      orders:        {via: customers, join: {customer_id: customer_id}}"),
                   "cycle")

    def test_on_instead_of_join(self):
        # YAML reads an unquoted "on" as true: the rule is refused, not misread.
        self.check(POLICY.replace("join: {order_id", "on: {order_id", 1), "invalid configuration")

    def test_empty_scope(self):
        self.check(POLICY.replace("{salesperson: [1, 3]}", "{}"), "scope is empty")

    def test_boolean_value(self):
        self.check(POLICY.replace("[Germany]", "[true]"), "true/false")



# The salesperson scope without its products rule, saying instead that
# anything it doesn't list is unscoped.
DEFAULTED = POLICY.replace("      products:      unscoped\n  country:", "  country:").replace(
    "    hierarchy: {table: employees, key: employee_id, parent: reports_to}\n",
    "    hierarchy: {table: employees, key: employee_id, parent: reports_to}\n"
    "    default: unscoped\n", 1)


class DefaultUnscoped(unittest.TestCase):

    def test_unlisted_table_gets_all_rows(self):
        f = context(["Team"], {"employee_id": 5}, text=DEFAULTED).row_filters
        self.assertNotIn("public.products", f)
        self.assertEqual(sql(f["public.orders"]), "_t.employee_id IN (5, 6, 7, 9)")
        self.assertIn("public.customers", f)

    def test_same_filters_as_listing_it(self):
        listed = context(["Team"], {"employee_id": 5}).row_filters
        defaulted = context(["Team"], {"employee_id": 5}, text=DEFAULTED).row_filters
        self.assertEqual({t: sql(e) for t, e in listed.items()},
                         {t: sql(e) for t, e in defaulted.items()})

    def test_only_the_scope_that_says_so(self):
        text = DEFAULTED.replace("      products:      unscoped\ngroup_grants:", "group_grants:")
        with self.assertRaisesRegex(SecurityPolicyError,
                                    "country.*no rule for public.products.*default: unscoped"):
            context(["Germany"], text=text)

    def test_printed_once_per_scope_and_role(self):
        p = policy(DEFAULTED)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            for _ in range(2):
                p.build_context("u", set(), TABLES, groups=["Team"],
                                attributes={"employee_id": 5},
                                read_hierarchy=lambda *_: HIERARCHY)
        lines = [l for l in out.getvalue().splitlines() if "unscoped by default" in l]
        self.assertEqual(lines, ["[security] scope salesperson: unscoped by default "
                                 "for role sales_manager: public.products"])

    def test_via_still_needs_a_listed_table(self):
        text = DEFAULTED.replace("{via: orders, join: {customer_id: customer_id}}",
                                 "{via: products, join: {customer_id: customer_id}}", 1)
        with self.assertRaisesRegex(SecurityPolicyError, "public.products, which has no rule"):
            context(["Team"], {"employee_id": 5}, text=text)

    def test_only_unscoped_is_a_default(self):
        with self.assertRaisesRegex(SecurityPolicyError, "invalid configuration"):
            context(["Team"], {"employee_id": 5},
                    text=DEFAULTED.replace("default: unscoped", "default: all"))


ROW_FILTERS = {
    "public.orders": sqlglot.parse_one("_t.employee_id IN (1, 3)"),
    "public.customers": sqlglot.parse_one(
        "EXISTS (SELECT 1 FROM public.orders AS _s1 WHERE _s1.customer_id = _t.customer_id "
        "AND _s1.employee_id IN (1, 3))"),
}


class Rewrite(unittest.TestCase):

    def apply(self, query, dialect="postgres", filters=ROW_FILTERS):
        return apply_row_scope(query, filters, dialect)

    def test_no_filters_is_a_no_op(self):
        q = "SELECT * FROM orders"
        self.assertIs(apply_row_scope(q, {}, "postgres"), q)

    def test_table_is_replaced_at_the_source(self):
        self.assertEqual(
            self.apply("SELECT o.order_id FROM orders o"),
            "SELECT o.order_id FROM (SELECT * FROM orders AS _t WHERE _t.employee_id IN (1, 3)) AS o")

    def test_unaliased_and_schema_qualified_columns(self):
        out = self.apply("SELECT public.orders.order_id FROM public.orders")
        self.assertEqual(
            out, "SELECT orders.order_id FROM (SELECT * FROM public.orders AS _t "
                 "WHERE _t.employee_id IN (1, 3)) AS orders")

    def test_every_shape_is_filtered(self):
        for query in [
            "SELECT c.customer_id FROM customers c LEFT JOIN orders o ON o.customer_id = c.customer_id",
            "SELECT customer_id FROM customers UNION SELECT customer_id FROM orders",
            "WITH t AS (SELECT employee_id FROM orders) SELECT * FROM t",
            "SELECT (SELECT COUNT(*) FROM orders) AS n",
            "SELECT * FROM customers c WHERE EXISTS (SELECT 1 FROM orders o WHERE o.customer_id = c.customer_id)",
            "SELECT a.order_id FROM orders a JOIN orders b ON a.customer_id = b.customer_id",
        ]:
            with self.subTest(query=query):
                out = self.apply(query)
                tree = sqlglot.parse_one(out, read="postgres")
                for table in tree.find_all(exp.Table):
                    if table.name in ("orders", "customers") and table.alias not in ("_t", "_s1"):
                        self.fail(f"unfiltered {table.sql()} in {out}")

    def test_sqlserver_names_with_spaces(self):
        filters = {"dbo.order details": sqlglot.parse_one(
            "EXISTS (SELECT 1 FROM dbo.Orders AS _s1 WHERE _s1.OrderID = _t.OrderID "
            "AND _s1.EmployeeID IN (5))", read="tsql")}
        out = self.apply("SELECT TOP 5 od.Quantity FROM dbo.[Order Details] od", "tsql", filters)
        self.assertEqual(
            out, "SELECT TOP 5 od.Quantity FROM (SELECT * FROM dbo.[Order Details] AS _t WHERE "
                 "EXISTS(SELECT 1 FROM dbo.Orders AS _s1 WHERE _s1.OrderID = _t.OrderID AND "
                 "_s1.EmployeeID IN (5))) AS od")

    def test_sqlserver_unaliased_name_with_space(self):
        filters = {"dbo.order details": sqlglot.parse_one("_t.OrderID IN (1)", read="tsql")}
        out = self.apply("SELECT [Order Details].Quantity FROM dbo.[Order Details]", "tsql", filters)
        self.assertIn(") AS [Order Details]", out)
        sqlglot.parse_one(out, read="tsql")


class Verify(unittest.TestCase):

    def test_unfiltered_table_is_refused(self):
        with self.assertRaisesRegex(RowScopeError, "public.orders is not filtered"):
            verify_row_scope("SELECT * FROM orders", ROW_FILTERS, "postgres")

    def test_wrong_filter_is_refused(self):
        with self.assertRaisesRegex(RowScopeError, "not filtered"):
            verify_row_scope(
                "SELECT * FROM (SELECT * FROM orders AS _t WHERE _t.employee_id IN (1, 3, 4)) AS o",
                ROW_FILTERS, "postgres")

    def test_lookalike_with_a_join_is_refused(self):
        with self.assertRaisesRegex(RowScopeError, "not filtered"):
            verify_row_scope(
                "SELECT * FROM (SELECT * FROM orders AS _t JOIN customers c ON 1 = 1 "
                "WHERE _t.employee_id IN (1, 3)) AS o", {"public.orders": ROW_FILTERS["public.orders"]},
                "postgres")

    def test_tables_inside_a_verified_filter_are_part_of_it(self):
        out = apply_row_scope("SELECT * FROM customers", ROW_FILTERS, "postgres")
        verify_row_scope(out, ROW_FILTERS, "postgres")      # orders AS _s1 inside is fine


class Agent(unittest.TestCase):
    """The agent applies row scope just before execution and blocks on failure."""

    def test_execute_runs_the_scoped_sql(self):
        from sqlagent import agent
        security = mock.MagicMock(row_filters=ROW_FILTERS, denied_columns={}, tables=set())
        with mock.patch.object(agent, "execute_sql_with_sources", return_value=([], {})) as run, \
             mock.patch.object(agent, "apply_result_policy", return_value=([], [])), \
             mock.patch.object(agent, "active_dialect", return_value="postgres"), \
             contextlib.redirect_stdout(io.StringIO()):
            agent._execute("SELECT order_id FROM orders", security)
        self.assertIn("_t.employee_id IN (1, 3)", run.call_args[0][0])

    def test_row_scope_failure_blocks(self):
        from sqlagent import agent
        from tests.fixtures import make_catalog
        security = mock.MagicMock(row_filters=ROW_FILTERS, denied_columns={},
                                  tables={"public.orders"}, roles={"demo"})
        with mock.patch.object(agent, "generate_sql", return_value="SELECT order_id FROM orders"), \
             mock.patch.object(agent, "_prepare_sql", return_value=("SELECT order_id FROM orders", [], None)), \
             mock.patch.object(agent, "apply_row_scope", side_effect=RowScopeError("boom")), \
             mock.patch.object(agent, "execute_sql_with_sources") as run, \
             contextlib.redirect_stdout(io.StringIO()):
            result = agent.run_agent("orders?", make_catalog(), [], security)
        run.assert_not_called()
        self.assertTrue(result["blocked"])


class ScopeSize(unittest.TestCase):
    """query.max_scope_values: a scope that resolves to too many values
    stops the context being built (fails closed)."""

    def limited(self, limit):
        settings = mock.MagicMock()
        settings.query.max_scope_values = limit
        return mock.patch("sqlagent.settings.get_settings", return_value=settings)

    def test_team_over_the_limit_stops(self):
        # employee 5's team: 5, 6, 7, 9 - four values
        with self.limited(3), self.assertRaisesRegex(
                SecurityPolicyError, r"salesperson' \(team\).*4 values.*max_scope_values \(3\)"):
            context(["Team"], {"employee_id": 5})

    def test_team_at_the_limit_is_allowed(self):
        with self.limited(4):
            ctx = context(["Team"], {"employee_id": 5})
        self.assertIn("public.orders", ctx.row_filters)

    def test_fixed_list_over_the_limit_stops(self):
        with self.limited(1), self.assertRaisesRegex(SecurityPolicyError, "a fixed list.*2 values"):
            context(["Fixed"])

    def test_unrestricted_has_no_list(self):
        with self.limited(1):
            self.assertEqual(context(["National"]).row_filters, {})

    def test_shipped_limit(self):
        from sqlagent.settings import get_settings
        self.assertEqual(get_settings().query.max_scope_values, 1000)


# Foreign keys for POLICY's tables: (table, columns, referenced, columns).
FOREIGN_KEYS = [
    ("public.order_details", ["order_id"], "public.orders", ["order_id"]),
    ("public.orders", ["customer_id"], "public.customers", ["customer_id"]),
    ("public.orders", ["employee_id"], "public.employees", ["employee_id"]),
]

# POLICY with every join left to the foreign keys.
DERIVED = (POLICY.replace(", join: {order_id: order_id}}", "}")
                 .replace(", join: {customer_id: customer_id}}", "}"))


def context_with_keys(groups, text=DERIVED, foreign_keys=FOREIGN_KEYS, pol=None, log=False):
    pol = pol or policy(text)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        ctx = pol.build_context(
            "u", set(), TABLES, groups=groups, attributes={"employee_id": 5},
            read_hierarchy=lambda *_: HIERARCHY,
            read_foreign_keys=(None if foreign_keys is None else lambda: foreign_keys),
            log=log)
    return ctx, out.getvalue()


class Joins(unittest.TestCase):
    """'via' with no join takes it from the one foreign key between the tables."""

    def assert_same_filters(self, groups):
        expected = {t: sql(f) for t, f in context(groups, {"employee_id": 5}).row_filters.items()}
        ctx, _ = context_with_keys(groups)
        self.assertEqual({t: sql(f) for t, f in ctx.row_filters.items()}, expected)

    def test_derived_joins_match_explicit(self):
        # child -> parent (order_details via orders) and parent -> child
        # (customers via orders; orders via customers) both resolve.
        for groups in (["Team"], ["Self"], ["Germany"], ["Both"], ["Team", "Germany"]):
            with self.subTest(groups=groups):
                self.assert_same_filters(groups)

    def test_joins_are_printed(self):
        _, out = context_with_keys(["Team"], log=True)
        self.assertIn("public.customers via public.orders on customer_id = customer_id "
                      "(foreign key)", out)

    def test_composite_key(self):
        keys = [("public.order_details", ["order_id", "line_no"],
                 "public.orders", ["order_id", "line_no"])] + FOREIGN_KEYS[1:]
        ctx, _ = context_with_keys(["Fixed"], foreign_keys=keys)
        filt = sql(ctx.row_filters["public.order_details"])
        self.assertIn("_s1.order_id = _t.order_id AND _s1.line_no = _t.line_no", filt)

    def test_no_foreign_key_stops(self):
        with self.assertRaisesRegex(SecurityPolicyError, "no foreign key joins them"):
            context_with_keys(["Team"], foreign_keys=FOREIGN_KEYS[1:])

    def test_two_foreign_keys_stop(self):
        keys = FOREIGN_KEYS + [("public.orders", ["billing_customer_id"],
                                "public.customers", ["customer_id"])]
        with self.assertRaisesRegex(SecurityPolicyError,
                                    "more than one foreign key.*billing_customer_id"):
            context_with_keys(["Team"], foreign_keys=keys)

    def test_explicit_join_settles_two_foreign_keys(self):
        keys = FOREIGN_KEYS + [("public.orders", ["billing_customer_id"],
                                "public.customers", ["customer_id"])]
        text = DERIVED.replace("      customers:     {via: orders}",
                               "      customers:     {via: orders, join: {customer_id: customer_id}}")
        text = text.replace("      orders:        {via: customers}",
                            "      orders:        {via: customers, join: {customer_id: customer_id}}")
        ctx, _ = context_with_keys(["Team"], text=text, foreign_keys=keys)
        self.assertIn("customer_id = _t.customer_id", sql(ctx.row_filters["public.customers"]))

    def test_all_explicit_never_reads_keys(self):
        def boom():
            raise AssertionError("foreign keys read")
        with contextlib.redirect_stdout(io.StringIO()):
            policy().build_context("u", set(), TABLES, groups=["Team"],
                                   attributes={"employee_id": 5},
                                   read_hierarchy=lambda *_: HIERARCHY,
                                   read_foreign_keys=boom, log=False)

    def test_no_reader_stops(self):
        with self.assertRaisesRegex(SecurityPolicyError, "foreign keys can't be read here"):
            context_with_keys(["Team"], foreign_keys=None)

    def test_unscoped_user_needs_no_keys(self):
        ctx, _ = context_with_keys(["National"], foreign_keys=None)
        self.assertEqual(ctx.row_filters, {})

    def test_keys_read_once(self):
        calls = []
        pol = policy(DERIVED)

        def read():
            calls.append(1)
            return FOREIGN_KEYS
        for groups in (["Team"], ["Germany"]):
            with contextlib.redirect_stdout(io.StringIO()):
                pol.build_context("u", set(), TABLES, groups=groups,
                                  attributes={"employee_id": 5},
                                  read_hierarchy=lambda *_: HIERARCHY,
                                  read_foreign_keys=read, log=False)
        self.assertEqual(len(calls), 1)

    def test_empty_join_refused(self):
        with self.assertRaises(SecurityPolicyError):
            policy(POLICY.replace("join: {order_id: order_id}", "join: {}", 1))


# Northwind's foreign keys, as the database reports them (PostgreSQL names;
# the SQL Server copy below uses its own).
NORTHWIND_KEYS = [
    ("order_details", "order_id", "orders", "order_id"),
    ("order_details", "product_id", "products", "product_id"),
    ("orders", "customer_id", "customers", "customer_id"),
    ("orders", "employee_id", "employees", "employee_id"),
    ("orders", "ship_via", "shippers", "shipper_id"),
    ("products", "category_id", "categories", "category_id"),
    ("products", "supplier_id", "suppliers", "supplier_id"),
    ("employees", "reports_to", "employees", "employee_id"),
    ("employee_territories", "employee_id", "employees", "employee_id"),
    ("employee_territories", "territory_id", "territories", "territory_id"),
    ("territories", "region_id", "region", "region_id"),
    ("customer_customer_demo", "customer_id", "customers", "customer_id"),
    ("customer_customer_demo", "customer_type_id", "customer_demographics", "customer_type_id"),
]
MSSQL_NAMES = {
    "order_details": "Order Details", "orders": "Orders", "products": "Products",
    "customers": "Customers", "employees": "Employees", "shippers": "Shippers",
    "categories": "Categories", "suppliers": "Suppliers", "territories": "Territories",
    "employee_territories": "EmployeeTerritories", "region": "Region",
    "customer_customer_demo": "CustomerCustomerDemo",
    "customer_demographics": "CustomerDemographics",
    "order_id": "OrderID", "product_id": "ProductID", "customer_id": "CustomerID",
    "employee_id": "EmployeeID", "ship_via": "ShipVia", "shipper_id": "ShipperID",
    "category_id": "CategoryID", "supplier_id": "SupplierID", "reports_to": "ReportsTo",
    "territory_id": "TerritoryID", "region_id": "RegionID",
    "customer_type_id": "CustomerTypeID",
}


def northwind_keys(db):
    if db == "northwind":
        return [(f"public.{a}", [b], f"public.{c}", [d]) for a, b, c, d in NORTHWIND_KEYS]
    m = MSSQL_NAMES
    return [(f"dbo.{m[a]}", [m[b]], f"dbo.{m[c]}", [m[d]]) for a, b, c, d in NORTHWIND_KEYS]


# The joins the shipped policies used to spell out, per dimension:
# (table, via) -> (column, via column), PostgreSQL names.
NORTHWIND_JOINS = {
    ("order_details", "orders"): ("order_id", "order_id"),
    ("customers", "orders"): ("customer_id", "customer_id"),
    ("customer_customer_demo", "customers"): ("customer_id", "customer_id"),
    ("employee_territories", "territories"): ("territory_id", "territory_id"),
    ("employees", "employee_territories"): ("employee_id", "employee_id"),
    ("orders", "employees"): ("employee_id", "employee_id"),
}


class Shipped(unittest.TestCase):
    """The shipped Northwind policies and identities compile."""

    def test_northwind_identities(self):
        from sqlagent.databases import load_database_profile
        from sqlagent.identities import load_identities, identities_file
        from sqlagent.controls.security_policy import load_security_policy
        for db, orders in (("northwind", "public.orders"), ("northwind_mssql", "dbo.orders")):
            profile = load_database_profile(db)
            with contextlib.redirect_stdout(io.StringIO()):
                pol = load_security_policy(profile.security_file)
            names = (["Customers", "Orders", "Order Details", "Products", "Categories",
                      "Suppliers", "Employees", "EmployeeTerritories", "Region", "Shippers",
                      "Territories", "CustomerDemographics", "CustomerCustomerDemo"]
                     if db == "northwind_mssql" else
                     ["customers", "orders", "order_details", "products", "categories",
                      "suppliers", "employees", "employee_territories", "region", "shippers",
                      "territories", "customer_demographics", "customer_customer_demo"])
            schema = "dbo" if db == "northwind_mssql" else "public"
            tables = {f"{schema}.{n}" for n in names}
            for name, ident in load_identities(identities_file(profile)).items():
                with self.subTest(db=db, identity=name), contextlib.redirect_stdout(io.StringIO()):
                    ctx = pol.build_context(name, set(), tables, groups=ident.groups,
                                            attributes=ident.attributes,
                                            read_hierarchy=lambda *_: [(2, None), (1, 2), (5, 2), (6, 5), (7, 5), (9, 5)],
                                            read_foreign_keys=lambda db=db: northwind_keys(db),
                                            log=False)
                    if name == "andrew":
                        self.assertEqual(ctx.row_filters, {})
                    else:
                        self.assertIn(orders, ctx.row_filters)

    def test_northwind_joins_from_foreign_keys(self):
        # Each via rule takes the same join the policy used to spell out.
        from sqlagent.databases import load_database_profile
        from sqlagent.controls.security_policy import load_security_policy
        for db in ("northwind", "northwind_mssql"):
            profile = load_database_profile(db)
            with contextlib.redirect_stdout(io.StringIO()):
                pol = load_security_policy(profile.security_file)
                pol._resolve_joins(lambda db=db: northwind_keys(db), log=False)
            name = (lambda n: n) if db == "northwind" else (lambda n: MSSQL_NAMES[n])
            schema = "public" if db == "northwind" else "dbo"
            found = 0
            for dim, (_, rules) in pol.scopes.items():
                for table, rule in rules.items():
                    if rule[0] != "via":
                        continue
                    found += 1
                    key = next(k for k in NORTHWIND_JOINS
                               if f"{schema}.{name(k[0])}".lower() == table
                               and f"{schema}.{name(k[1])}".lower() == rule[1])
                    col, via_col = NORTHWIND_JOINS[key]
                    with self.subTest(db=db, dim=dim, table=table):
                        self.assertEqual(rule[2], {name(col): name(via_col)})
            self.assertEqual(found, 9)



class ClosureExample(unittest.TestCase):
    """docs/examples/closure-table: the example policies compile for every
    Northwind identity, and a manager's team is one value, not a list."""

    EXAMPLES = {
        "northwind": ("security.postgres.yaml", "public.employee_hierarchy",
                      "manager_id", "employee_id", "public.orders"),
        "northwind_mssql": ("security.sqlserver.yaml", "dbo.EmployeeHierarchy",
                            "ManagerID", "EmployeeID", "dbo.orders"),
    }

    def load(self, db, text=None):
        from sqlagent.config_files import PROJECT_ROOT
        from sqlagent.controls.security_policy import load_security_policy
        name, *_ = self.EXAMPLES[db]
        path = PROJECT_ROOT / "docs" / "examples" / "closure-table" / name
        with contextlib.redirect_stdout(io.StringIO()):
            if text is None:
                return load_security_policy(path)
            return SecurityPolicy.from_dict(yaml.safe_load(text(path.read_text(encoding="utf-8"))))

    def keys(self, db):
        _, table, manager, employee, _ = self.EXAMPLES[db]
        employees = "public.employees" if db == "northwind" else "dbo.Employees"
        key = "employee_id" if db == "northwind" else "EmployeeID"
        return northwind_keys(db) + [(table, [manager], employees, [key]),
                                     (table, [employee], employees, [key])]

    def tables(self, db):
        return ({t for t, _, _, _ in northwind_keys(db)}
                | {t for _, _, t, _ in northwind_keys(db)} | {self.EXAMPLES[db][1]})

    def context(self, pol, db, name, ident):
        with contextlib.redirect_stdout(io.StringIO()):
            return pol.build_context(name, set(), self.tables(db), groups=ident.groups,
                                     attributes=ident.attributes,
                                     read_hierarchy=lambda *_: self.fail("hierarchy read"),
                                     read_foreign_keys=lambda: self.keys(db), log=False)

    def test_every_identity_compiles_and_teams_are_one_value(self):
        from sqlagent.databases import load_database_profile
        from sqlagent.identities import identities_file, load_identities
        for db, (_, table, manager, _, orders) in self.EXAMPLES.items():
            pol = self.load(db)
            for name, ident in load_identities(identities_file(load_database_profile(db))).items():
                with self.subTest(db=db, identity=name):
                    ctx = self.context(pol, db, name, ident)
                    if name == "steven":
                        self.assertEqual(ctx.grants, ["sales_manager (team [5])"])
                        orders_filter = ctx.row_filters[orders].sql()
                        self.assertIn(f"{manager} IN (5)", orders_filter)
                        self.assertNotRegex(orders_filter, r"IN \(5, ")
                    if name == "nancy":
                        self.assertEqual(ctx.grants, ["sales_manager (salesperson [1])"])

    def test_join_to_the_closure_table_must_be_given(self):
        # Two foreign keys to employees: without join, startup stops.
        for db in self.EXAMPLES:
            def drop_join(text, db=db):
                key = "employee_id" if db == "northwind" else "EmployeeID"
                hierarchy = self.EXAMPLES[db][1]
                return text.replace(f"{{via: {hierarchy}, join: {{{key}: {key}}}}}", f"{{via: {hierarchy}}}", 1)
            pol = self.load(db, drop_join)
            from sqlagent.identities import load_identities, identities_file
            from sqlagent.databases import load_database_profile
            steven = load_identities(identities_file(load_database_profile(db)))["steven"]
            with self.subTest(db=db), self.assertRaisesRegex(SecurityPolicyError,
                                                             "more than one foreign key"):
                self.context(pol, db, "steven", steven)

if __name__ == "__main__":
    unittest.main()
