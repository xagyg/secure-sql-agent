# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Tests for business-term predicates with EXISTS / NOT EXISTS subqueries
# (SchemaCatalog._attach_terms), and for the shipped Odoo terms that use
# them (customer, vendor, out_of_stock). No database or LLM needed.
#
#     python -m unittest tests.test_terms -v

import unittest
from pathlib import Path

from sqlagent.adaptive.semantic_model import load_semantic_model
from tests.fixtures import NORTHWIND, make_catalog
from tests.test_semantic_model import model_from

ODOO_SEMANTIC_PATH = (Path(__file__).resolve().parent.parent
                      / "config" / "databases" / "odoo" / "semantic")

TERMS = """
terms:
  has_orders:
    table: customers
    predicate: >-
      EXISTS (SELECT 1 FROM orders o WHERE o.customer_id = customers.customer_id)
  no_orders:
    table: customers
    predicate: >-
      NOT EXISTS (SELECT 1 FROM orders o WHERE o.customer_id = customers.customer_id)
  german_with_orders:
    table: customers
    predicate: >-
      country = 'Germany'
      AND EXISTS (SELECT 1 FROM orders WHERE orders.customer_id = customers.customer_id)
  scalar_subquery:
    table: orders
    predicate: freight > (SELECT max(freight) FROM orders)
  in_subquery:
    table: customers
    predicate: customer_id IN (SELECT customer_id FROM orders)
  star:
    table: customers
    predicate: EXISTS (SELECT * FROM orders o WHERE o.customer_id = customers.customer_id)
  bad_column_in_subquery:
    table: customers
    predicate: >-
      EXISTS (SELECT 1 FROM orders o WHERE o.no_such_column = customers.customer_id)
  bad_outer_column:
    table: customers
    predicate: >-
      EXISTS (SELECT 1 FROM orders o WHERE o.customer_id = customers.no_such_column)
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
    "public.res_partner": ["id", "name", "commercial_partner_id", "is_company"],
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

    def test_role_without_purchasing_gets_no_vendor_term(self):
        catalog = odoo_catalog(hide={"purchase_order"})
        names = term_names(catalog, "res_partner")
        self.assertIn("customer", names)
        self.assertNotIn("vendor", names)


if __name__ == "__main__":
    unittest.main()
