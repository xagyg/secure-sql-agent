# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Tests for the parameter-placeholder check (sql_diagnostics
# find_placeholders / PlaceholderError): SQL like "WHERE parent_id = %s"
# is never run - nothing fills the marker in - and goes to correction
# with a NO PARAMETERS hint. No database or LLM needed.
#
#     python -m unittest tests.test_placeholders -v

import contextlib
import io
import unittest
from unittest import mock

from sqlagent import agent
from sqlagent.controls.security_context import SecurityContext
from sqlagent.execution.sql_diagnostics import find_placeholders, placeholder_hint
from tests.fixtures import make_catalog


class Finding(unittest.TestCase):

    def test_each_style(self):
        self.assertEqual(find_placeholders("SELECT 1 FROM t WHERE a = %s"), ["%s"])
        self.assertEqual(find_placeholders("SELECT 1 FROM t WHERE a = $1"), ["$1"])
        self.assertEqual(find_placeholders("SELECT 1 FROM t WHERE a = ?"), ["?"])
        # PostgreSQL writes a named one back as %(manager)s.
        self.assertEqual(len(find_placeholders("SELECT 1 FROM t WHERE a = :manager")), 1)

    def test_text_in_a_string_is_not_one(self):
        self.assertEqual(find_placeholders("SELECT 1 FROM t WHERE a LIKE '%s%'"), [])

    def test_plain_sql_has_none(self):
        self.assertEqual(find_placeholders("SELECT a FROM t WHERE a = 5"), [])

    def test_hint(self):
        hint = placeholder_hint(["%s"])
        self.assertIn("NO PARAMETERS", hint)
        self.assertIn("list every match", hint)


class InTheAgent(unittest.TestCase):

    def run_agent(self, generated, corrected):
        catalog = make_catalog()
        security = SecurityContext(user_id="sam", roles={"sales"},
                                   tables=set(catalog.tables))
        with mock.patch.object(agent, "generate_sql", return_value=generated), \
             mock.patch.object(agent, "correct_sql", return_value=corrected) as correct, \
             mock.patch.object(agent, "_execute", return_value=([{"n": 1}], [])) as execute, \
             mock.patch.object(agent, "explain_results", return_value="ok"), \
             contextlib.redirect_stdout(io.StringIO()) as out:
            agent.run_agent("orders for a particular customer?", catalog, [], security)
        return correct, execute, out.getvalue()

    def test_placeholder_is_corrected_before_running(self):
        correct, execute, out = self.run_agent(
            "SELECT order_id FROM orders WHERE customer_id = %s",
            "SELECT order_id, customer_id FROM orders")
        self.assertIn("Pre-run check: unfilled placeholder %s", out)
        self.assertIn("Not run: correcting it first", out)
        self.assertIn("NO PARAMETERS", correct.call_args[0][4])
        # Only the corrected SQL ran.
        execute.assert_called_once()
        self.assertNotIn("%s", execute.call_args[0][0])

    def test_placeholder_left_in_the_correction_is_not_run(self):
        correct, execute, out = self.run_agent(
            "SELECT order_id FROM orders WHERE customer_id = %s",
            "SELECT order_id FROM orders WHERE customer_id = ?")
        execute.assert_not_called()
        self.assertIn("[CORRECTION ERROR]", out)


if __name__ == "__main__":
    unittest.main()
