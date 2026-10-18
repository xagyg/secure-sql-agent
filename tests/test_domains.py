# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Tests for Domain of Discourse routing (domains.py) and domain-scoped
# schema discovery (schema_catalog.py). No database or LLM needed: the
# catalog is built from a static copy of the Northwind (Postgres) schema.
#
#     python -m unittest tests.test_domains -v

import unittest

from sqlagent.adaptive.domains import DomainResolver, parse_context_tags
from tests.fixtures import make_catalog


def route(catalog, text, roles=(), previous=None):
    ctx = parse_context_tags(text)
    decision = catalog.domain_resolver.resolve(
        ctx.question, roles=roles, where=ctx.where, who=ctx.who,
        previous_domain=previous)
    print(f"\n  {text!r} roles={set(roles) or '-'}\n    -> {decision.summary()}")
    return ctx, decision


def tables_in(schema):
    return {line.split()[1].split(".")[1]
            for line in schema.splitlines() if line.startswith("TABLE ")}


class TagParsing(unittest.TestCase):

    def test_where_tag_removed(self):
        ctx = parse_context_tags("What was the last order? [where=financials data entry]")
        self.assertEqual(ctx.question, "What was the last order?")
        self.assertEqual(ctx.where, "financials data entry")
        self.assertIsNone(ctx.who)

    def test_both_tags_any_order_and_case(self):
        ctx = parse_context_tags("[WHO = buyer] list products [Where=stock control]")
        self.assertEqual(ctx.question, "list products")
        self.assertEqual(ctx.where, "stock control")
        self.assertEqual(ctx.who, "buyer")

    def test_no_tags(self):
        ctx = parse_context_tags("how many customers are in Germany?")
        self.assertEqual(ctx.question, "how many customers are in Germany?")
        self.assertIsNone(ctx.where)


class Routing(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.catalog = make_catalog()

    # -- What --------------------------------------------------------

    def test_what_suppliers(self):
        _, d = route(self.catalog, "list our vendors in Japan")
        self.assertEqual(d.domains, ["purchasing"])

    def test_what_territories(self):
        _, d = route(self.catalog, "which territories does each employee cover?")
        self.assertEqual(d.domains[0], "hr")

    def test_what_explicit_domain_name(self):
        _, d = route(self.catalog, "in purchasing, which products are low on stock?")
        self.assertEqual(d.domains, ["purchasing"])

    def test_what_ambiguous_order_blends(self):
        # "order" alone could be Sales, Financials or Logistics.
        _, d = route(self.catalog, "what was the last order?")
        self.assertEqual(d.mode, "blended")

    # -- Where -------------------------------------------------------

    def test_where_settles_ambiguous_order(self):
        _, d = route(self.catalog, "what was the last order? [where=financials data entry]")
        self.assertEqual(d.domains, ["finance"])

    def test_where_dispatch(self):
        _, d = route(self.catalog, "what was the last order? [where=shipping desk]")
        self.assertEqual(d.domains, ["logistics"])

    def test_where_function_code(self):
        _, d = route(self.catalog, "show me the latest one [where=PUR0410]")
        self.assertEqual(d.domains, ["purchasing"])

    def test_where_specific_phrase_beats_sub_phrase(self):
        # "purchase order entry" must not also count as Sales' "order entry".
        _, d = route(self.catalog, "show me recent activity [where=purchase order entry]")
        self.assertEqual(d.domains, ["purchasing"])

    # -- Who ---------------------------------------------------------

    def test_who_alone_routes_vague_question(self):
        _, d = route(self.catalog, "show me Nancy's information", roles={"HR_Officer"})
        self.assertEqual(d.domains, ["hr"])

    def test_who_tag_friendly_role_name(self):
        _, d = route(self.catalog, "what was the last order? [who=accountant]")
        self.assertEqual(d.domains, ["finance"])

    def test_who_is_a_nudge_not_a_selector(self):
        # A buyer asking clearly about employees' territories goes to HR.
        _, d = route(self.catalog, "which territories does each employee cover?",
                     roles={"buyer"})
        self.assertEqual(d.domains[0], "hr")

    # -- Conversation ------------------------------------------------

    def test_follow_up_stays_in_domain(self):
        _, d = route(self.catalog, "now by month", previous="logistics")
        self.assertEqual(d.domains, ["logistics"])
        self.assertEqual(d.mode, "follow_up")

    def test_weak_follow_up_stays_in_domain(self):
        # Only the column word "phone" matches (suppliers, shippers; the
        # customers.phone column is hidden). That mustn't pull a customer
        # conversation into Purchasing / Logistics.
        catalog = make_catalog()
        _, d = route(catalog, "What is Maria's phone number?", previous="sales")
        self.assertEqual(d.domains, ["sales"])
        self.assertEqual(d.mode, "follow_up")

    def test_weak_question_without_history_routes_as_before(self):
        _, d = route(self.catalog, "What is Maria's phone number?")
        self.assertEqual(set(d.domains), {"purchasing", "logistics"})

    def test_named_table_still_moves_conversation(self):
        _, d = route(self.catalog, "show me all shippers", previous="sales")
        self.assertEqual(d.domains, ["logistics"])

    def test_named_domain_still_moves_conversation(self):
        _, d = route(self.catalog, "what is the phone number in purchasing?",
                     previous="sales")
        self.assertEqual(d.domains, ["purchasing"])

    def test_where_tag_still_moves_conversation(self):
        _, d = route(self.catalog, "what is the phone number? [where=dispatch]",
                     previous="sales")
        self.assertEqual(d.domains, ["logistics"])

    def test_no_signal_searches_whole_schema(self):
        _, d = route(self.catalog, "now by month")
        self.assertEqual(d.domains, [])
        self.assertIsNone(self.catalog.domain_resolver.scope(d))


class ScopedSchema(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.catalog = make_catalog()

    def schema_for(self, text, roles=()):
        ctx, d = route(self.catalog, text, roles=roles)
        scope = self.catalog.domain_resolver.scope(d)
        return tables_in(self.catalog.discover_schema(ctx.question, scope=scope))

    def test_domain_narrows_schema(self):
        unscoped = tables_in(self.catalog.discover_schema("what was the last order?"))
        scoped = self.schema_for("what was the last order? [where=shipping desk]")
        print(f"    unscoped: {sorted(unscoped)}\n    scoped:   {sorted(scoped)}")
        self.assertIn("orders", scoped)
        self.assertIn("shippers", scoped)
        self.assertLessEqual(len(scoped), len(unscoped))

    def test_hops_cross_domain_boundary(self):
        # Starts in Purchasing (products), one hop reaches order_details,
        # which is in Sales.
        tables = self.schema_for("which products are we stocking? [where=stock control]")
        self.assertIn("products", tables)
        self.assertIn("order_details", tables)

    def test_named_table_outside_domain_is_kept(self):
        # Where says HR, but the question names shippers explicitly.
        tables = self.schema_for("list the shippers [where=staff records]")
        self.assertIn("shippers", tables)

    def test_domain_fallback_for_vague_question(self):
        tables = self.schema_for("show me Nancy's information", roles={"hr_officer"})
        self.assertIn("employees", tables)
        self.assertIn("territories", tables)
        self.assertNotIn("orders", tables)


class FollowUpAnchors(unittest.TestCase):

    PREVIOUS_SQL = ("SELECT contact_name, contact_title FROM customers "
                    "WHERE company_name = 'Around the Horn'")

    @classmethod
    def setUpClass(cls):
        cls.catalog = make_catalog()

    def test_tables_in_sql(self):
        sql = ("SELECT c.company_name, COUNT(*) FROM customers c "
               "JOIN orders o ON o.customer_id = c.customer_id "
               "WHERE o.employee_id IN (SELECT employee_id FROM employees) "
               "GROUP BY c.company_name")
        self.assertEqual(self.catalog.tables_in_sql(sql),
                         {"public.customers", "public.orders", "public.employees"})

    def test_tables_in_sql_bad_input(self):
        self.assertEqual(self.catalog.tables_in_sql("not sql at all ("), set())
        self.assertEqual(self.catalog.tables_in_sql(None), set())

    def test_weak_follow_up_starts_from_previous_tables(self):
        # "What is Thomas's full name?" after a customers query: "name"
        # matches customers AND employees, but only customers (and its
        # direct neighbours) should be offered.
        catalog = self.catalog
        q = "What is Thomas's full name?"
        _, d = route(catalog, q, previous="sales")
        self.assertTrue(d.signals.get("weak_evidence"))
        anchors = catalog.tables_in_sql(self.PREVIOUS_SQL)
        tables = tables_in(catalog.discover_schema(
            q, scope=catalog.domain_resolver.scope(d), anchors=anchors))
        print(f"    schema: {sorted(tables)}")
        self.assertIn("customers", tables)
        self.assertNotIn("employees", tables)
        self.assertNotIn("suppliers", tables)

    def test_unauthorised_previous_table_is_ignored(self):
        catalog = make_catalog(exclude={"customers"})
        self.assertEqual(catalog.tables_in_sql(self.PREVIOUS_SQL), set())


class Security(unittest.TestCase):

    def test_domain_never_adds_unauthorised_tables(self):
        # Role can't see employees: HR routing must not bring it back.
        catalog = make_catalog(exclude={"employees"})
        ctx, d = route(catalog, "show me staff details [where=staff records]",
                       roles={"hr_officer"})
        tables, fallbacks, _ = catalog.domain_resolver.scope(d)
        self.assertNotIn("public.employees", tables | fallbacks)
        schema = catalog.discover_schema(ctx.question,
                                         scope=catalog.domain_resolver.scope(d))
        self.assertNotIn("employees", tables_in(schema))

    def test_domain_with_no_authorised_tables_is_ineligible(self):
        catalog = make_catalog(exclude={"shippers", "orders"})
        _, d = route(catalog, "anything [where=shipping desk]")
        self.assertNotIn("logistics", d.domains)


class WildcardTables(unittest.TestCase):
    """Domain tables given as patterns ("sales.*"), for schema-per-domain
    databases such as AdventureWorks."""

    EXTRA = {
        "sales.customer": ["customerid", "storeid"],
        "sales.salesorderheader": ["salesorderid", "customerid"],
        "sales.salesorderdetail": ["salesorderid", "productid"],
        "purchasing.vendor": ["businessentityid", "name"],
        "purchasing.purchaseorderheader": ["purchaseorderid", "vendorid"],
        "production.product": ["productid", "name"],
        "production.productcategory": ["productcategoryid", "name"],
        "production.workorder": ["workorderid", "productid"],
    }

    @staticmethod
    def domain(label, tables, fallback=()):
        return {"label": label, "aliases": {label.lower()}, "tables": set(tables),
                "roles": {}, "where": set(), "hops": 1,
                "fallback_tables": tuple(fallback)}

    def resolver(self, domains, exclude_extra=()):
        catalog = make_catalog(extra_tables={
            k: v for k, v in self.EXTRA.items() if k not in exclude_extra})
        return DomainResolver(catalog, domains=domains, role_aliases={},
                              function_aliases={})

    def test_schema_wildcard_expands(self):
        r = self.resolver({"sales": self.domain("Sales", ["sales.*"])})
        self.assertEqual(r.domain_tables["sales"], {
            "sales.customer", "sales.salesorderheader", "sales.salesorderdetail"})

    def test_partial_wildcard(self):
        r = self.resolver({"prod": self.domain("Production", ["production.product*"])})
        self.assertEqual(r.domain_tables["prod"], {
            "production.product", "production.productcategory"})

    def test_wildcard_is_case_insensitive(self):
        r = self.resolver({"sales": self.domain("Sales", ["SALES.*"])})
        self.assertIn("sales.customer", r.domain_tables["sales"])

    def test_wildcard_mixed_with_exact_names(self):
        r = self.resolver({"buy": self.domain(
            "Purchasing", ["purchasing.*", "production.product"])})
        self.assertEqual(r.domain_tables["buy"], {
            "purchasing.vendor", "purchasing.purchaseorderheader",
            "production.product"})

    def test_bare_wildcard_is_default_schema(self):
        # "*" means public.*, like a bare table name.
        r = self.resolver({"all": self.domain("All", ["*"])})
        self.assertIn("public.orders", r.domain_tables["all"])
        self.assertNotIn("sales.customer", r.domain_tables["all"])

    def test_wildcard_fallback_tables(self):
        r = self.resolver({"buy": self.domain(
            "Purchasing", ["purchasing.*"], fallback=["purchasing.*"])})
        self.assertEqual(r.domain_fallbacks["buy"], r.domain_tables["buy"])

    def test_unmatched_wildcard_leaves_domain_ineligible(self):
        r = self.resolver({"hr": self.domain("HR", ["humanresources.*"])})
        self.assertEqual(r.domain_tables["hr"], set())
        d = r.resolve("in hr, list departments")
        self.assertNotIn("hr", d.domains)

    def test_wildcard_never_adds_unauthorised_tables(self):
        r = self.resolver({"sales": self.domain("Sales", ["sales.*"])},
                          exclude_extra={"sales.customer"})
        self.assertNotIn("sales.customer", r.domain_tables["sales"])
        self.assertIn("sales.salesorderheader", r.domain_tables["sales"])

    def test_wildcard_domain_routes(self):
        r = self.resolver({
            "sales": self.domain("Sales", ["sales.*"]),
            "purchasing": self.domain("Purchasing", ["purchasing.*"]),
        })
        d = r.resolve("list each vendor")
        self.assertEqual(d.domains, ["purchasing"])


if __name__ == "__main__":
    unittest.main()
