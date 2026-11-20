# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Tests for the pre-execution column check (sql_diagnostics.
# find_unknown_columns, agent._check_before_running): a column that isn't in the
# role's catalog goes to correction without running the query, and
# nothing the check can't be sure of is ever flagged. No database or LLM
# needed.
#
#     python -m unittest tests.test_column_check -v

import contextlib
import io
import unittest
from unittest import mock

from sqlagent import agent
from sqlagent.execution.engines.postgres import PostgresEngine
from sqlagent.execution.engines.sqlserver import SqlServerEngine
from sqlagent.execution.sql_diagnostics import (
    find_unknown_columns, missing_column_hint)
from tests.test_missing_column_hint import odoo_catalog


def unknown(sql, catalog=None):
    with contextlib.redirect_stdout(io.StringIO()):
        return find_unknown_columns(sql, catalog or odoo_catalog())


class Finds(unittest.TestCase):

    def test_qualified_column(self):
        self.assertEqual(
            unknown("SELECT v.contract_end_date FROM hr_version v"),
            [("contract_end_date", "v", "hr_version")])

    def test_every_unknown_column_once(self):
        # The database reports one at a time (Q37 needed two attempts).
        found = unknown("SELECT pp.name, pol.quantity, pol.quantity FROM purchase_order_line pol "
                        "JOIN product_product pp ON pp.id = pol.product_id")
        self.assertEqual(found, [("name", "pp", "product_product"),
                                 ("quantity", "pol", "purchase_order_line")])

    def test_unqualified_column(self):
        self.assertEqual(unknown("SELECT hours FROM project_task"), [("hours", None, None)])

    def test_columns_in_where_join_and_subqueries(self):
        found = unknown("SELECT p.name FROM project_project p WHERE EXISTS "
                        "(SELECT 1 FROM project_task t WHERE t.project_id = p.id "
                        "AND t.planned_hours > 0)")
        self.assertEqual(found, [("planned_hours", "t", "project_task")])


class NoFalseAlarms(unittest.TestCase):

    def assertClean(self, sql):
        self.assertEqual(unknown(sql), [], sql)

    def test_known_columns(self):
        self.assertClean("SELECT e.name, v.contract_date_end FROM hr_employee e "
                         "JOIN hr_version v ON v.id = e.current_version_id")

    def test_output_alias_in_order_by(self):
        self.assertClean("SELECT p.name, COUNT(t.id) AS task_count FROM project_project p "
                         "JOIN project_task t ON t.project_id = p.id "
                         "GROUP BY p.name ORDER BY task_count DESC")

    def test_derived_table_columns(self):
        self.assertClean("SELECT x.total FROM (SELECT SUM(allocated_hours) AS total "
                         "FROM project_task) x")
        self.assertClean("SELECT total FROM (SELECT SUM(allocated_hours) AS total "
                         "FROM project_task) x")

    def test_same_alias_for_different_tables_in_subqueries(self):
        self.assertClean("SELECT p.name FROM project_project p WHERE EXISTS "
                         "(SELECT 1 FROM res_partner p WHERE p.name = 'x')")

    def test_table_not_in_the_catalog_is_left_to_the_database(self):
        # Authorised but not discovered, or simply unknown here.
        self.assertClean("SELECT r.anything FROM report_stock_quantity r")
        self.assertClean("SELECT anything FROM project_task t JOIN mystery m ON m.id = t.id")

    def test_keywords_and_functions(self):
        self.assertClean("SELECT t.name, CURRENT_DATE, EXTRACT(year FROM t.date_end), "
                         "DATE_TRUNC('month', t.date_deadline) AS month "
                         "FROM project_task t WHERE t.date_deadline < CURRENT_DATE "
                         "- INTERVAL '30 days' GROUP BY month, t.name, t.date_end")

    def test_unparseable_sql(self):
        self.assertClean("SELEC nonsense FROM")

    def test_northwind_examples_are_clean(self):
        from sqlagent.databases import load_database_profile
        from tests.fixtures import make_catalog
        catalog = make_catalog()
        for example in load_database_profile("northwind").sql_examples:
            with self.subTest(question=example.question):
                self.assertEqual(unknown(example.sql, catalog), [])


class EngineMessages(unittest.TestCase):
    """Each engine reads back its own synthetic message, so the rest of
    the correction step works unchanged."""

    def test_postgres(self):
        engine = PostgresEngine.__new__(PostgresEngine)
        self.assertEqual(engine.missing_column(
            engine.missing_column_message("contract_end_date", "v")), "contract_end_date")
        self.assertEqual(engine.missing_column(
            engine.missing_column_message("hours")), "hours")

    def test_sqlserver(self):
        engine = SqlServerEngine.__new__(SqlServerEngine)
        self.assertEqual(engine.missing_column(
            engine.missing_column_message("O'Brien", "v")), "O'Brien")


class Hint(unittest.TestCase):

    def test_one_block_for_every_unknown_column(self):
        catalog = odoo_catalog()
        sql = ("SELECT pt.standard_price, pol.quantity FROM purchase_order_line pol "
               "JOIN product_product pp ON pp.id = pol.product_id "
               "JOIN product_template pt ON pt.id = pp.product_tmpl_id")
        text = missing_column_hint(sql, "", catalog, unknown=unknown(sql, catalog))
        self.assertEqual(text.count("COLUMN NOT FOUND"), 1)
        self.assertIn("standard_price is a column of: product_product (pp)", text)
        self.assertIn("Closest columns in purchase_order_line: product_qty", text)
        self.assertEqual(text.count("DATA_NOT_AVAILABLE"), 1)


class AgentFlow(unittest.TestCase):

    def run_agent(self, generated, corrected, check=True):
        catalog = odoo_catalog()
        security = mock.MagicMock(row_filters={}, denied_columns={},
                                  tables=set(catalog.tables), roles={"hr"})
        settings = mock.MagicMock()
        settings.query.check_columns = check
        with mock.patch.object(agent, "generate_sql", return_value=generated), \
             mock.patch.object(agent, "get_settings", return_value=settings), \
             mock.patch.object(agent, "_execute", return_value=([{"n": 1}], [])) as execute, \
             mock.patch.object(agent, "diagnose_sql_error", return_value=None), \
             mock.patch.object(agent, "correct_sql", return_value=corrected) as correct, \
             mock.patch.object(agent, "explain_results", return_value="ok"), \
             contextlib.redirect_stdout(io.StringIO()) as out:
            agent.run_agent("contracts ending soon?", catalog, [], security)
        return execute, correct, out.getvalue()

    BAD = "SELECT e.name, v.contract_end_date FROM hr_employee e JOIN hr_version v ON v.id = e.current_version_id"
    GOOD = "SELECT e.name, v.contract_date_end FROM hr_employee e JOIN hr_version v ON v.id = e.current_version_id"

    def test_bad_column_is_corrected_before_running(self):
        execute, correct, out = self.run_agent(self.BAD, self.GOOD)
        self.assertIn("[sql] Pre-run check: not in the schema - v.contract_end_date", out)
        self.assertNotIn("[SQL ERROR]", out)
        self.assertIn("Closest columns in hr_version: contract_date_end", correct.call_args[0][4])
        # Only the corrected SQL ran.
        self.assertEqual(execute.call_count, 1)
        self.assertIn("contract_date_end", execute.call_args[0][0])

    def test_corrected_sql_is_checked_too(self):
        execute, _, out = self.run_agent(self.BAD, self.BAD.replace("contract_end_date", "end_date"))
        execute.assert_not_called()
        self.assertIn("[CORRECTION ERROR] column v.end_date does not exist", out)

    def test_good_sql_runs_without_correction(self):
        execute, correct, _ = self.run_agent(self.GOOD, self.GOOD)
        correct.assert_not_called()
        self.assertEqual(execute.call_count, 1)

    def test_check_can_be_turned_off(self):
        execute, _, out = self.run_agent(self.BAD, self.GOOD, check=False)
        self.assertNotIn("Pre-run check", out)
        self.assertIn("contract_end_date", execute.call_args_list[0][0][0])


if __name__ == "__main__":
    unittest.main()
