# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Tests for helpers shared across modules: table naming, catalog lookup
# and the column-alias vocabulary used by SQL error diagnostics. No
# database or LLM needed.
#
#     python -m unittest tests.test_shared_helpers -v

import unittest

from sqlagent.controls.security_utils import full_table_name
from sqlagent.execution.sql_diagnostics import get_column_alias
from tests.fixtures import make_catalog


class FullTableName(unittest.TestCase):

    def test_bare_name_gets_default_schema(self):
        self.assertEqual(full_table_name("customers"), "public.customers")

    def test_qualified_name_unchanged(self):
        self.assertEqual(full_table_name("sales.orders"), "sales.orders")

    def test_parsed_schema_wins(self):
        self.assertEqual(full_table_name("orders", "sales"), "sales.orders")
        self.assertEqual(full_table_name("orders", None), "public.orders")
        self.assertEqual(full_table_name("orders", ""), "public.orders")


class CatalogLookup(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.catalog = make_catalog(exclude={"shippers"})

    def test_case_insensitive(self):
        self.assertEqual(self.catalog.resolve_table_name("Public.Customers"),
                         "public.customers")
        self.assertEqual(self.catalog.resolve_table_name("CUSTOMERS"),
                         "public.customers")

    def test_get_table(self):
        self.assertEqual(self.catalog.get_table("orders")["name"], "orders")

    def test_not_loaded(self):
        # Excluded tables behave like tables the role can't see.
        self.assertIsNone(self.catalog.get_table("shippers"))
        self.assertIsNone(self.catalog.resolve_table_name("nonexistent"))


class DiagnosticAliases(unittest.TestCase):

    def test_alias_maps_back_to_physical_column(self):
        self.assertEqual(get_column_alias("public.employees", "phone"), "home_phone")
        self.assertEqual(get_column_alias("public.employees", "Start_Date"), "hire_date")

    def test_alias_is_per_table(self):
        self.assertIsNone(get_column_alias("public.customers", "phone"))
        self.assertEqual(get_column_alias("public.customers", "zip"), "postal_code")

    def test_unknown(self):
        self.assertIsNone(get_column_alias("public.employees", "salary"))


if __name__ == "__main__":
    unittest.main()
