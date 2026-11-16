# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Tests for the tables added to a correction's schema
# (SchemaCatalog.tables_missing_from): a table the failed SQL reads that
# the question's schema didn't show - taken from the history, or
# remembered - is shown to the correction, so its hint has a table to
# point at. Only the role's tables (denied columns are never in the
# catalog, so they can't be shown). No database
# or LLM needed.
#
#     python -m unittest tests.test_correction_schema -v

import contextlib
import io
import unittest
from unittest import mock

from sqlagent import agent
from sqlagent.controls.security_context import SecurityContext
from tests.fixtures import make_catalog


def catalog_for(**kwargs):
    with contextlib.redirect_stdout(io.StringIO()):
        return make_catalog(**kwargs)


class TablesMissingFrom(unittest.TestCase):

    def setUp(self):
        self.catalog = catalog_for()
        with contextlib.redirect_stdout(io.StringIO()):
            self.orders_only = self.catalog._format_context({"public.orders"})

    def test_adds_a_table_the_schema_does_not_show(self):
        schema, added = self.catalog.tables_missing_from(
            self.orders_only,
            "SELECT COUNT(*) FROM products WHERE discontinued_flag = 1")
        self.assertEqual(added, {"public.products"})
        self.assertTrue(schema.startswith(self.orders_only.rstrip()))
        self.assertIn("TABLE public.products", schema)

    def test_nothing_added_when_every_table_is_shown(self):
        schema, added = self.catalog.tables_missing_from(
            self.orders_only, "SELECT o.order_id FROM orders o")
        self.assertEqual(added, set())
        self.assertEqual(schema, self.orders_only)

    def test_a_table_outside_the_catalog_is_never_added(self):
        catalog = catalog_for(exclude={"employees", "employee_territories"})
        schema, added = catalog.tables_missing_from(
            self.orders_only, "SELECT e.salary FROM employees e")
        self.assertEqual(added, set())
        self.assertNotIn("TABLE public.employees", schema)

    def test_wide_table_keeps_the_columns_the_sql_reaches_for(self):
        # A wide table lists only the columns that matter, plus those whose
        # words the SQL's own column names use: a "GENERAL_RELEASE_IND"
        # guess keeps the real GENERAL_REL in view.
        with mock.patch.object(self.catalog, "question_terms",
                               side_effect=lambda text: set(text.lower().replace("_", " ").split())):
            schema, _ = self.catalog.tables_missing_from(
                self.orders_only,
                "SELECT COUNT(*) FROM customers c WHERE c.postal_area = 'x'")
        block = schema.split("TABLE public.customers", 1)[1]
        self.assertIn("postal_code", block)


class InTheCorrection(unittest.TestCase):

    def test_correction_sees_the_table_the_sql_used(self):
        catalog = catalog_for()
        security = SecurityContext(user_id="sam", roles={"sales"},
                                   tables=set(catalog.tables))
        with contextlib.redirect_stdout(io.StringIO()):
            orders_only = catalog._format_context({"public.orders"})
        with mock.patch.object(catalog, "discover_schema", return_value=orders_only), \
             mock.patch.object(agent, "generate_sql",
                               return_value="SELECT COUNT(*) FROM products WHERE in_stock = 1"), \
             mock.patch.object(agent, "correct_sql",
                               return_value="DATA_NOT_AVAILABLE") as correct, \
             contextlib.redirect_stdout(io.StringIO()) as out:
            agent.run_agent("how many products are in stock?", catalog, [], security)
        schema_sent = correct.call_args[0][1]
        self.assertIn("TABLE public.products", schema_sent)
        self.assertIn("Added to the correction", out.getvalue())
        self.assertIn("public.products", out.getvalue())


if __name__ == "__main__":
    unittest.main()
