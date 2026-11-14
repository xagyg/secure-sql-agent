# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Tests for the COLUMN NOT FOUND hint given to the correction step
# (sql_diagnostics.missing_column_hint), and for a correction that says
# the data isn't available. Cases are real misses from an Odoo test run.
# No database or LLM needed.
#
#     python -m unittest tests.test_missing_column_hint -v

import contextlib
import io
import unittest
from unittest import mock

from sqlagent import agent
from sqlagent.execution.sql_diagnostics import column_similarity, missing_column_hint
from tests.fixtures import NORTHWIND, make_catalog

ODOO = {
    "public.hr_employee": ["id", "name", "current_version_id", "work_email", "parent_id"],
    "public.hr_version": ["id", "employee_id", "date_version", "contract_date_start",
                          "contract_date_end", "trial_date_end", "job_title", "address_id"],
    "public.project_task": ["id", "name", "project_id", "state", "allocated_hours",
                            "date_deadline", "date_assign", "date_end"],
    "public.project_project": ["id", "name", "partner_id", "date"],
    "public.stock_picking": ["id", "name", "origin", "partner_id", "scheduled_date",
                             "date_done", "sale_id", "backorder_id"],
    "public.purchase_order": ["id", "name", "partner_id", "date_order", "state"],
    "public.purchase_order_line": ["id", "order_id", "product_id", "product_qty",
                                   "price_unit"],
    "public.product_product": ["id", "product_tmpl_id", "standard_price"],
    "public.product_template": ["id", "name", "list_price"],
    "public.res_users": ["id", "login", "partner_id"],
    "public.res_partner": ["id", "name"],
}


def odoo_catalog():
    catalog = make_catalog(exclude=set(NORTHWIND), extra_tables=ODOO)
    catalog.tables["public.res_users"]["description"] = (
        "People who sign in to Odoo. The user's name is on its partner: "
        "join res_partner ON res_partner.id = res_users.partner_id.")
    for column in catalog.tables["public.purchase_order_line"]["columns"]:
        if column["name"] == "product_qty":
            column["label"] = "quantity"
    return catalog


def pg_error(qualified):
    return f"column {qualified} does not exist\nLINE 1: SELECT ..."


class Similarity(unittest.TestCase):

    def test_reordered_words(self):
        self.assertGreaterEqual(column_similarity("contract_end_date", "contract_date_end"), 95)

    def test_word_subset(self):
        self.assertGreaterEqual(column_similarity("hours", "allocated_hours"), 85)

    def test_bare_id_never_counts(self):
        self.assertEqual(column_similarity("purchase_order_id", "id"), 0)


class Hint(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.catalog = odoo_catalog()

    def hint(self, sql, qualified):
        return missing_column_hint(sql, pg_error(qualified), self.catalog)

    def test_renamed_column(self):
        text = self.hint("SELECT e.name, v.contract_end_date FROM hr_employee e "
                         "JOIN hr_version v ON v.id = e.current_version_id",
                         "v.contract_end_date")
        self.assertIn("v.contract_end_date: hr_version has no column contract_end_date.", text)
        self.assertIn("Closest columns in hr_version: contract_date_end", text)

    def test_hours_points_to_allocated_hours(self):
        text = self.hint("SELECT p.name, SUM(t.hours) FROM project_project p "
                         "JOIN project_task t ON t.project_id = p.id GROUP BY p.name",
                         "t.hours")
        self.assertIn("Closest columns in project_task: allocated_hours", text)
        self.assertNotIn("project_project has no column", text)

    def test_nothing_similar_is_said_plainly(self):
        text = self.hint("SELECT rp.name FROM purchase_order po "
                         "JOIN stock_picking sp ON po.id = sp.purchase_order_id "
                         "JOIN res_partner rp ON rp.id = po.partner_id",
                         "sp.purchase_order_id")
        self.assertIn("stock_picking has no similar column.", text)
        self.assertIn("return DATA_NOT_AVAILABLE rather than invent a column", text)

    def test_label_match(self):
        text = self.hint("SELECT pol.quantity FROM purchase_order_line pol", "pol.quantity")
        self.assertIn("Closest columns in purchase_order_line: product_qty", text)

    def test_table_note_is_included(self):
        text = self.hint("SELECT u.name FROM project_project p "
                         "JOIN res_users u ON u.id = p.partner_id", "u.name")
        self.assertIn("About res_users: People who sign in to Odoo. The user's name "
                      "is on its partner", text)

    def test_column_on_another_table_in_the_query(self):
        text = self.hint("SELECT pt.standard_price FROM product_template pt "
                         "JOIN product_product pp ON pp.product_tmpl_id = pt.id",
                         "pt.standard_price")
        self.assertIn("standard_price is a column of: product_product (pp)", text)

    def test_unqualified_column_checks_every_table(self):
        text = missing_column_hint(
            "SELECT contract_end_date FROM hr_employee e JOIN hr_version v "
            "ON v.id = e.current_version_id",
            'column "contract_end_date" does not exist', self.catalog)
        self.assertIn("hr_employee has no column contract_end_date.", text)
        self.assertIn("Closest columns in hr_version: contract_date_end", text)

    def test_other_errors_give_no_hint(self):
        self.assertEqual(missing_column_hint("SELECT 1 FROM hr_employee",
                                             "syntax error at or near FROM",
                                             self.catalog), "")

    def test_only_the_roles_tables(self):
        # A table the role can't see isn't in the catalog: no hint names it.
        catalog = make_catalog(exclude=set(NORTHWIND),
                               extra_tables={"public.hr_employee": ["id", "name"]})
        text = missing_column_hint("SELECT v.wage FROM hr_employee e JOIN hr_version v "
                                   "ON v.id = e.current_version_id",
                                   pg_error("v.wage"), catalog)
        self.assertNotIn("hr_version", text)


class NotAvailableCorrection(unittest.TestCase):
    """The correction answers DATA_NOT_AVAILABLE: the user is told the data
    isn't available, as when the first attempt says so."""

    def run_with_correction(self, reply, question="total hours per project?",
                            denied=False):
        catalog = odoo_catalog()
        security = mock.MagicMock(row_filters={}, denied_columns={},
                                  tables=set(catalog.tables), roles={"projects"})
        with mock.patch.object(agent, "generate_sql",
                               return_value="SELECT SUM(t.hours) FROM project_task t"), \
             mock.patch.object(agent, "_execute",
                               side_effect=RuntimeError(pg_error("t.hours"))), \
             mock.patch.object(agent, "diagnose_sql_error", return_value=None), \
             mock.patch.object(agent, "mentions_denied_column", return_value=denied), \
             mock.patch.object(agent, "correct_sql", return_value=reply) as correct, \
             contextlib.redirect_stdout(io.StringIO()) as out:
            result = agent.run_agent(question, catalog, [], security)
        return result, correct, out.getvalue()

    def test_hint_reaches_the_correction(self):
        _, correct, out = self.run_with_correction("DATA_NOT_AVAILABLE")
        self.assertIn("Closest columns in project_task: allocated_hours",
                      correct.call_args[0][4])
        self.assertIn("[sql] Missing column hint", out)

    def test_not_available_is_reported(self):
        result, _, _ = self.run_with_correction("DATA_NOT_AVAILABLE")
        self.assertTrue(result["blocked"])
        self.assertEqual(result["rule"], "not_available")

    def test_restricted_column_is_still_reported_as_restricted(self):
        result, _, _ = self.run_with_correction("DATA_NOT_AVAILABLE", denied=True)
        self.assertEqual(result["rule"], "restricted_data")


if __name__ == "__main__":
    unittest.main()
