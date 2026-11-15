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


class QuestionNamingTheData(unittest.TestCase):
    """A question that names restricted data gets the same one rewrite;
    the hint stops it being answered from a different table, so it ends
    as not available - the same reply as for data that doesn't exist."""

    def test_rewrite_says_not_available(self):
        result, correct, execute, _ = run("list all employees",
                                          "SELECT * FROM employees",
                                          ["DATA_NOT_AVAILABLE"])
        self.assertEqual(correct.call_count, 1)
        self.assertIn("do not\nanswer it from a table that means something else",
                      correct.call_args[0][4])
        execute.assert_not_called()
        self.assertEqual(result["rule"], "not_available")


class NoRetry(unittest.TestCase):

    def test_other_validation_failures_are_not_retried(self):
        result, correct, _, _ = run("delete old orders", "DELETE FROM orders")
        correct.assert_not_called()
        self.assertTrue(result["blocked"])


if __name__ == "__main__":
    unittest.main()
