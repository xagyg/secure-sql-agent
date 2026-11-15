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
        self.assertEqual(result["row_count"], 1)       # for the batch summary
        self.assertIn("Asking Ollama to rewrite it without order_shipping_log", out)

    def test_rewrite_hint_names_the_closest_table(self):
        # The SQL Server spelling of Northwind's order_details.
        _, correct, execute, out = run(
            "employee sales by year",
            'SELECT SUM(od.quantity) FROM "order details" od',
            ["SELECT SUM(quantity) FROM order_details"])
        hint = correct.call_args[0][4]
        self.assertIn("Closest tables in the schema: order_details", hint)
        self.assertIn("Closest table(s) to order details: order_details", out)
        execute.assert_called_once()

    def test_closest_tables_never_name_a_hidden_table(self):
        # employees exists but this role can't see it.
        _, correct, _, _ = run("how many staff?",
                               "SELECT COUNT(*) FROM employee",
                               ["DATA_NOT_AVAILABLE"])
        self.assertNotIn("employees", correct.call_args[0][4])

    def test_no_closest_line_when_nothing_is_near(self):
        _, correct, _, _ = run("total billable hours?",
                               "SELECT SUM(hours) FROM timesheet_line",
                               ["DATA_NOT_AVAILABLE"])
        self.assertNotIn("Closest tables", correct.call_args[0][4])

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

    def test_hidden_and_missing_tables_get_the_same_answer(self):
        # The user can't tell a hidden table from one that doesn't exist.
        hidden, _, _, _ = run("how many people report to Andrew?",
                              "SELECT COUNT(*) FROM employees")
        missing, _, _, _ = run("how many people report to Andrew?",
                               "SELECT COUNT(*) FROM staff_list", ["DATA_NOT_AVAILABLE"])
        self.assertEqual(hidden["answer"], missing["answer"])
        self.assertEqual(hidden["rule"], missing["rule"])


class RealTableTheRoleCantSee(unittest.TestCase):
    """A real table outside the role's schema is not retried: the answer
    is "not available" at once. Retried, these nearly always came back
    DATA_NOT_AVAILABLE, and the one that didn't answered from a look-alike
    table with wrong figures (AdventureWorks Q75)."""

    def test_not_retried(self):
        result, correct, execute, out = run("list all employees",
                                            "SELECT * FROM employees")
        correct.assert_not_called()
        execute.assert_not_called()
        self.assertEqual(result["rule"], "not_available")
        self.assertIn("employees is a table this role can't see; not retried", out)

    def test_quoted_or_schema_qualified_name(self):
        _, correct, _, _ = run("which staff cover which territories?",
                               'SELECT * FROM public."employee_territories"')
        correct.assert_not_called()

    def test_restricted_column_named_is_still_reported_as_restricted(self):
        catalog = make_catalog(exclude={"employees", "employee_territories"})
        security = SecurityContext(user_id="sam", roles={"sales"},
                                   tables=set(catalog.tables),
                                   denied_columns={"public.customers": {"phone"}})
        with mock.patch.object(agent, "generate_sql",
                               return_value="SELECT * FROM employees"), \
             mock.patch.object(agent, "correct_sql") as correct, \
             contextlib.redirect_stdout(io.StringIO()):
            result = agent.run_agent("what is the phone of each employee?",
                                     catalog, [], security)
        correct.assert_not_called()
        self.assertEqual(result["rule"], "restricted_data")


class NoRetry(unittest.TestCase):

    def test_other_validation_failures_are_not_retried(self):
        result, correct, _, _ = run("delete old orders", "DELETE FROM orders")
        correct.assert_not_called()
        self.assertTrue(result["blocked"])


if __name__ == "__main__":
    unittest.main()
