# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Tests for two checks the code makes instead of trusting the model:
#   - a subquery in FROM / JOIN: one rewrite, not a security block
#   - a question about something the database doesn't record
#     (semantic model not_recorded): "not available" before any SQL
# No database or LLM needed.
#
#     python -m unittest tests.test_deterministic_checks -v

import contextlib
import dataclasses
import io
import unittest
from unittest import mock

from sqlagent import agent
from sqlagent.adaptive.text_match import tokenize
from sqlagent.controls.security_context import SecurityContext
from sqlagent.execution.sql_diagnostics import has_derived_table
from tests.fixtures import make_catalog

# The shapes of the failing Odoo queries, on Northwind tables.
FINE = (
    "SELECT c.company_name FROM customers c WHERE "
    "EXISTS (SELECT 1 FROM orders o WHERE o.customer_id = c.customer_id)")
DERIVED = (                    # Q19
    "SELECT c.company_name, cy.total FROM customers c "
    "JOIN (SELECT customer_id, SUM(freight) AS total FROM orders GROUP BY customer_id) cy "
    "ON cy.customer_id = c.customer_id")
REWRITTEN = ("SELECT c.company_name, SUM(o.freight) AS total FROM customers c "
             "JOIN orders o ON o.customer_id = c.customer_id GROUP BY c.company_name")


def run(generated, corrections=(), question="customers?"):
    catalog = make_catalog()
    security = SecurityContext(user_id="sam", roles={"sales"},
                               tables=set(catalog.tables))
    with mock.patch.object(agent, "generate_sql", return_value=generated) as generate, \
         mock.patch.object(agent, "correct_sql", side_effect=list(corrections)) as correct, \
         mock.patch.object(agent, "_execute", return_value=([{"n": 1}], [])) as execute, \
         mock.patch.object(agent, "explain_results", return_value="ok"), \
         contextlib.redirect_stdout(io.StringIO()) as out:
        result = agent.run_agent(question, catalog, [], security)
    return result, generate, correct, execute, out.getvalue()


class SubqueryInFrom(unittest.TestCase):

    def test_detected(self):
        self.assertTrue(has_derived_table(DERIVED))
        self.assertTrue(has_derived_table(
            "WITH x AS (SELECT 1 AS a) SELECT a FROM x"))
        self.assertFalse(has_derived_table(FINE))
        self.assertFalse(has_derived_table(
            "SELECT o.order_id FROM orders o WHERE o.freight > (SELECT AVG(freight) FROM orders)"))

    def test_rewritten_once_not_blocked(self):
        result, _, correct, execute, out = run(DERIVED, [REWRITTEN])
        self.assertIn("SUBQUERY IN FROM NOT ALLOWED", correct.call_args[0][4])
        self.assertIn("without subqueries in FROM", out)
        execute.assert_called_once()
        self.assertFalse(result["blocked"])

    def test_second_failure_stops(self):
        result, _, correct, execute, _ = run(DERIVED, [DERIVED + " WHERE 1 = 1"])
        self.assertEqual(correct.call_count, 1)
        execute.assert_not_called()


class NotRecorded(unittest.TestCase):

    def setUp(self):
        self.catalog = make_catalog()
        # A copy: the semantic model may be shared with other tests.
        self.catalog.semantic = dataclasses.replace(self.catalog.semantic, not_recorded={
            "timesheets": (("timesheets", "billable hours", "exceeded allocated hours"),
                           "no timesheet app")})

    def match(self, question):
        return self.catalog.semantic.not_recorded_match(tokenize(question))

    def test_matches(self):
        self.assertEqual(self.match("Show me projects with no timesheets recorded")[0], "timesheets")
        self.assertEqual(self.match("Which employees have the most billable hours?")[0], "timesheets")
        self.assertEqual(self.match("Which projects have exceeded their allocated hours?")[0],
                         "timesheets")

    def test_other_questions_dont_match(self):
        self.assertIsNone(self.match("Show allocated hours per project"))
        self.assertIsNone(self.match("Which employees work in sales?"))

    def test_answered_before_any_sql(self):
        catalog = self.catalog
        security = SecurityContext(user_id="sam", roles={"sales"},
                                   tables=set(catalog.tables))
        with mock.patch.object(agent, "generate_sql") as generate, \
             contextlib.redirect_stdout(io.StringIO()) as out:
            result = agent.run_agent("Which employees have the most billable hours?",
                                     catalog, [], security)
        generate.assert_not_called()
        self.assertEqual(result["rule"], "not_available")
        self.assertIn("Not recorded in this database: timesheets", out.getvalue())

    def test_odoo_model_lists_timesheets(self):
        from sqlagent.adaptive.semantic_model import load_semantic_model
        from pathlib import Path
        root = Path(__file__).resolve().parent.parent
        with contextlib.redirect_stdout(io.StringIO()):
            model = load_semantic_model(root / "config/databases/odoo/semantic")
        self.assertIn("timesheets", model.not_recorded)
        self.assertEqual(model.not_recorded_match(tokenize("hours worked by Mitchell"))[0],
                         "timesheets")

    def test_adventureworks_model_lists_country_of_manufacture(self):
        from sqlagent.adaptive.semantic_model import load_semantic_model
        from pathlib import Path
        root = Path(__file__).resolve().parent.parent
        with contextlib.redirect_stdout(io.StringIO()):
            model = load_semantic_model(root / "config/databases/adventureworks/semantic")
        match = model.not_recorded_match(tokenize(
            "Which customers have purchased products manufactured in a "
            "different country from their own?"))
        self.assertEqual(match[0], "country_of_manufacture")
        # Questions about making things, or about countries, still run.
        for question in ("Which products were manufactured last month?",
                         "Which products are made in-house?",
                         "How many products manufactured in-house were sold in each country?"):
            self.assertIsNone(model.not_recorded_match(tokenize(question)), question)


if __name__ == "__main__":
    unittest.main()
