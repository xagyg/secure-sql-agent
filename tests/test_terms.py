# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Tests for business-term predicates with EXISTS / NOT EXISTS subqueries
# (SchemaCatalog._attach_terms), for the shipped Odoo terms that use
# them (customer, vendor, out_of_stock), and for terms defined in a table's
# own block, where a name is unique per table rather than per model.
# No database or LLM needed.
#
#     python -m unittest tests.test_terms -v

import unittest
from pathlib import Path

from sqlagent.adaptive.semantic_model import SemanticModelError, load_semantic_model
from tests.fixtures import NORTHWIND, make_catalog
from tests.test_semantic_model import model_from

CONFIG = Path(__file__).resolve().parent.parent / "config" / "databases"
ODOO_SEMANTIC_PATH = CONFIG / "odoo" / "semantic"
NORTHWIND_SEMANTIC_PATH = CONFIG / "northwind" / "semantic"

TERMS = """
tables:
  customers:
    terms:
      has_orders:
        predicate: >-
          EXISTS (SELECT 1 FROM orders o WHERE o.customer_id = customers.customer_id)
      no_orders:
        predicate: >-
          NOT EXISTS (SELECT 1 FROM orders o WHERE o.customer_id = customers.customer_id)
      german_with_orders:
        predicate: >-
          country = 'Germany'
          AND EXISTS (SELECT 1 FROM orders WHERE orders.customer_id = customers.customer_id)
      in_subquery:
        predicate: customer_id IN (SELECT customer_id FROM orders)
      star:
        predicate: EXISTS (SELECT * FROM orders o WHERE o.customer_id = customers.customer_id)
      bad_column_in_subquery:
        predicate: >-
          EXISTS (SELECT 1 FROM orders o WHERE o.no_such_column = customers.customer_id)
      bad_outer_column:
        predicate: >-
          EXISTS (SELECT 1 FROM orders o WHERE o.customer_id = customers.no_such_column)
  orders:
    terms:
      scalar_subquery:
        predicate: freight > (SELECT max(freight) FROM orders)
"""


def term_names(catalog, table):
    return {t["name"] for t in catalog.tables[f"public.{table}"]["terms"]}


class ExistsPredicates(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.catalog = make_catalog(semantic=model_from(**{"t.yaml": TERMS}))

    def test_exists_and_not_exists_are_allowed(self):
        self.assertTrue({"has_orders", "no_orders", "german_with_orders"}
                        <= term_names(self.catalog, "customers"))

    def test_definition_is_shown_to_the_model(self):
        context = self.catalog._format_context({"public.customers"})
        self.assertIn("has orders: public.customers WHERE EXISTS(SELECT 1 FROM orders", context)

    def test_other_subqueries_are_rejected(self):
        self.assertNotIn("scalar_subquery", term_names(self.catalog, "orders"))
        self.assertNotIn("in_subquery", term_names(self.catalog, "customers"))

    def test_select_star_is_rejected(self):
        self.assertNotIn("star", term_names(self.catalog, "customers"))

    def test_unknown_columns_are_rejected(self):
        names = term_names(self.catalog, "customers")
        self.assertNotIn("bad_column_in_subquery", names)
        self.assertNotIn("bad_outer_column", names)

    def test_subquery_on_hidden_table_is_rejected(self):
        # The role can't see orders: no term may mention it.
        catalog = make_catalog(exclude={"orders", "order_details"},
                               semantic=model_from(**{"t.yaml": TERMS}))
        self.assertEqual(term_names(catalog, "customers"), set())

    def test_subquery_on_hidden_column_is_rejected(self):
        semantic = model_from(**{"t.yaml": TERMS})
        catalog = make_catalog(semantic=semantic)
        catalog.tables["public.orders"]["columns"] = [
            c for c in catalog.tables["public.orders"]["columns"]
            if c["name"] != "customer_id"]
        for table in catalog.tables.values():
            table["terms"] = []
        catalog._attach_terms()
        self.assertEqual(term_names(catalog, "customers"), set())


ODOO_TABLES = {
    "public.res_partner": ["id", "name", "commercial_partner_id", "is_company", "customer_rank", "active"],
    "public.res_company": ["id", "partner_id"],
    "public.sale_order": ["id", "partner_id", "state"],
    "public.purchase_order": ["id", "partner_id", "state"],
    "public.product_product": ["id"],
    "public.stock_quant": ["id", "product_id", "location_id", "quantity"],
    "public.stock_location": ["id", "usage"],
}


def odoo_catalog(hide=()):
    return make_catalog(
        exclude=set(NORTHWIND),
        semantic=load_semantic_model(ODOO_SEMANTIC_PATH),
        extra_tables={k: v for k, v in ODOO_TABLES.items()
                      if k.split(".")[1] not in hide},
    )


class ShippedOdooTerms(unittest.TestCase):

    def test_customer_vendor_and_out_of_stock_load(self):
        catalog = odoo_catalog()
        self.assertTrue({"customer", "vendor"} <= term_names(catalog, "res_partner"))
        self.assertIn("out_of_stock", term_names(catalog, "product_product"))

    def test_customer_excludes_our_own_companies(self):
        catalog = odoo_catalog()
        term = next(t for t in catalog.tables["public.res_partner"]["terms"]
                    if t["name"] == "customer")
        self.assertIn("NOT EXISTS(SELECT 1 FROM res_company", term["definition"])
        self.assertIn("commercial_partner_id", term["definition"])

    def test_customer_needs_no_order(self):
        # Any active top-level partner is a customer, ordered or not;
        # contact people aren't listed separately, and no order, invoice
        # or rank is required.
        catalog = odoo_catalog()
        term = next(t for t in catalog.tables["public.res_partner"]["terms"]
                    if t["name"] == "customer")
        self.assertIn("commercial_partner_id = res_partner.id", term["definition"])
        self.assertIn("res_partner.active", term["definition"])
        for required in ("sale_order", "customer_rank", "account_move"):
            self.assertNotIn(required, term["definition"])

    def test_role_without_purchasing_gets_no_vendor_term(self):
        catalog = odoo_catalog(hide={"purchase_order"})
        names = term_names(catalog, "res_partner")
        self.assertIn("customer", names)
        self.assertNotIn("vendor", names)


# The same term name, and a shared alias, on two tables.
TABLE_TERMS = """
tables:
  orders:
    terms:
      priority:
        predicate: freight > 500
        aliases: [urgent]
        description: an order with high freight
  products:
    terms:
      priority:
        predicate: units_in_stock = 0
        aliases: [urgent]
        description: a product with nothing in stock
"""


def term_named(catalog, table, name):
    return next(t for t in catalog.tables[f"public.{table}"]["terms"]
                if t["name"] == name)


class TermsInTableBlocks(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.semantic = model_from(**{"t.yaml": TABLE_TERMS})
        cls.catalog = make_catalog(semantic=cls.semantic)

    def test_table_term_names_no_table(self):
        # The table is the block's own: no table: key is needed.
        self.assertIn(("public.orders", "priority"), self.semantic.terms)

    def test_same_name_on_two_tables(self):
        self.assertEqual(len(self.semantic.terms), 2)
        self.assertIn("priority", term_names(self.catalog, "orders"))
        self.assertIn("priority", term_names(self.catalog, "products"))

    def test_each_table_keeps_its_own_definition(self):
        self.assertIn("freight > 500",
                      term_named(self.catalog, "orders", "priority")["definition"])
        self.assertIn("units_in_stock = 0",
                      term_named(self.catalog, "products", "priority")["definition"])

    def test_shared_word_is_flagged_when_both_tables_are_shown(self):
        context = self.catalog._format_context({"public.orders", "public.products"})
        self.assertIn("priority, urgent mean different rows on different tables",
                      context)
        self.assertIn("public.orders WHERE freight > 500", context)
        self.assertIn("public.products WHERE units_in_stock = 0", context)

    def test_one_table_shows_only_its_meaning(self):
        context = self.catalog._format_context({"public.orders"})
        self.assertIn("public.orders WHERE freight > 500", context)
        self.assertNotIn("units_in_stock = 0", context)
        self.assertNotIn("different rows on different tables", context)

    def test_table_key_inside_a_table_block_is_an_error(self):
        with self.assertRaises(SemanticModelError):
            model_from(**{"t.yaml": """
tables:
  orders:
    terms:
      late:
        table: orders
        predicate: shipped_date > required_date
"""})

    def test_column_or_predicate_still_required(self):
        with self.assertRaises(SemanticModelError):
            model_from(**{"t.yaml": """
tables:
  orders:
    terms:
      late:
        aliases: [delayed]
"""})

    def test_top_level_terms_is_an_error(self):
        # Terms used to be a top-level section with a table: key each.
        with self.assertRaises(SemanticModelError) as raised:
            model_from(**{"t.yaml": """
terms:
  late:
    table: orders
    predicate: shipped_date > required_date
"""})
        self.assertIn("move each term into its table's block", str(raised.exception))


class ShippedTermsInTableBlocks(unittest.TestCase):

    def test_northwind_terms_load_from_their_table_blocks(self):
        catalog = make_catalog(semantic=load_semantic_model(NORTHWIND_SEMANTIC_PATH))
        self.assertIn("shipped_late", term_names(catalog, "orders"))
        self.assertIn("low_stock", term_names(catalog, "products"))

    def test_every_shipped_model_loads_its_terms(self):
        # A leftover top-level terms: section would stop the load.
        for database, count in (("northwind", 2), ("northwind_mssql", 2),
                                ("adventureworks", 16), ("odoo", 24)):
            with self.subTest(database=database):
                semantic = load_semantic_model(CONFIG / database / "semantic")
                self.assertEqual(len(semantic.terms), count)


if __name__ == "__main__":
    unittest.main()
