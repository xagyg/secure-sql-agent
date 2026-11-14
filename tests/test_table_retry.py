# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Tests for the one retry given to SQL stopped for reading a table outside
# the role's schema (agent._retry_unavailable_table). Runs the real
# validator on Northwind with a role that can't see employees. No database
# or LLM needed.
#
#     python -m unittest tests.test_table_retry -v

import contextlib
import io
import unittest
from unittest import mock

from sqlagent import agent
from sqlagent.controls.security_context import SecurityContext
from tests.fixtures import make_catalog


def run(question, generated, corrections=()):
    catalog = make_catalog(exclude={"employees", "employee_territories"})
    security = SecurityContext(user_id="sam", roles={"sales"},
                               tables=set(catalog.tables))
    with mock.patch.object(agent, "generate_sql", return_value=generated), \
         mock.patch.object(agent, "correct_sql", side_effect=list(corrections)) as correct, \
         mock.patch.object(agent, "_execute", return_value=([{"n": 3}], [])) as execute, \
         mock.patch.object(agent, "explain_results", return_value="three"), \
         contextlib.redirect_stdout(io.StringIO()) as out:
        result = agent.run_agent(question, catalog, [], security)
    return result, correct, execute, out.getvalue()


class Retry(unittest.TestCase):

    def test_invented_table_gets_one_rewrite(self):
        result, correct, execute, out = run(
            "how many orders were shipped late?",
            "SELECT COUNT(*) FROM order_shipping_log",
            ["SELECT COUNT(*) FROM orders WHERE shipped_date > required_date"])
        self.assertEqual(correct.call_count, 1)
        hint = correct.call_args[0][4]
        self.assertIn("order_shipping_log is not in the schema you were given", hint)
        self.assertIn("return exactly DATA_NOT_AVAILABLE", hint)
        self.assertIn("required_date", execute.call_args[0][0])
        self.assertEqual(result["answer"], "three")
        self.assertIn("Asking Ollama to rewrite it without order_shipping_log", out)

    def test_rewrite_can_say_not_available(self):
        result, _, execute, _ = run("total billable hours?",
                                    "SELECT SUM(hours) FROM timesheet_line",
                                    ["DATA_NOT_AVAILABLE"])
        execute.assert_not_called()
        self.assertEqual(result["rule"], "not_available")

    def test_rewrite_gets_every_check_again(self):
        # Still outside the schema: blocked, and never retried twice.
        result, correct, execute, _ = run("total billable hours?",
                                          "SELECT SUM(hours) FROM timesheet_line",
                                          ["SELECT * FROM employees"])
        self.assertEqual(correct.call_count, 1)
        execute.assert_not_called()
        self.assertEqual(result["rule"], "restricted_data")

    def test_same_sql_back_is_a_block(self):
        result, _, execute, _ = run("total billable hours?",
                                    "SELECT SUM(hours) FROM timesheet_line",
                                    ["SELECT SUM(hours) FROM timesheet_line"])
        execute.assert_not_called()
        self.assertEqual(result["rule"], "restricted_data")

    def test_hidden_and_missing_tables_get_the_same_hint(self):
        _, hidden, _, _ = run("how many people report to Andrew?",
                              "SELECT COUNT(*) FROM employees", ["DATA_NOT_AVAILABLE"])
        _, missing, _, _ = run("how many people report to Andrew?",
                               "SELECT COUNT(*) FROM staff_list", ["DATA_NOT_AVAILABLE"])
        self.assertEqual(hidden.call_args[0][4].replace("employees", "X"),
                         missing.call_args[0][4].replace("staff_list", "X"))


class NoRetry(unittest.TestCase):

    def test_question_naming_the_data_stays_blocked(self):
        result, correct, execute, out = run("list all employees",
                                            "SELECT * FROM employees")
        correct.assert_not_called()
        execute.assert_not_called()
        self.assertEqual(result["rule"], "restricted_data")
        self.assertIn("The question asks for that data - not retrying", out)

    def test_other_validation_failures_are_not_retried(self):
        result, correct, _, _ = run("delete old orders", "DELETE FROM orders")
        correct.assert_not_called()
        self.assertTrue(result["blocked"])


class QuestionNamesTable(unittest.TestCase):

    def test_examples(self):
        names = agent._question_names_table
        self.assertTrue(names("show me the payslips", "public.hr_payslip"))
        self.assertTrue(names("list all employees", "public.employees"))
        self.assertFalse(names("which employees have the most billable hours?",
                               "public.timesheet_line"))
        self.assertFalse(names("which customers have unpaid invoices?",
                               "public.account_payment_rel"))
        self.assertFalse(names("how many orders were shipped late?",
                               "public.order_shipping_log"))


if __name__ == "__main__":
    unittest.main()
