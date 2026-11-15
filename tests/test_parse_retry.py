# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Tests for the one retry given to SQL the parser couldn't read
# (agent._retry_unparseable), e.g. the financial-year lookup written as a
# second FROM. Runs the real validator on Northwind. No database or LLM
# needed.
#
#     python -m unittest tests.test_parse_retry -v

import contextlib
import io
import unittest
from unittest import mock

from sqlagent import agent
from sqlagent.controls.security_context import SecurityContext
from tests.fixtures import make_catalog

# Two FROM clauses - the shape of the failing financial-year query.
BROKEN = ("SELECT SUM(freight) AS total FROM orders o WHERE o.order_date >= "
          "CASE WHEN c.x < CURRENT_DATE THEN c.x ELSE c.y END "
          "FROM customers c WHERE c.customer_id = o.customer_id")
FIXED = "SELECT SUM(freight) AS total FROM orders"


def run(generated, corrections=(), exclude=()):
    catalog = make_catalog(exclude=set(exclude))
    security = SecurityContext(user_id="sam", roles={"sales"},
                               tables=set(catalog.tables))
    with mock.patch.object(agent, "generate_sql", return_value=generated), \
         mock.patch.object(agent, "correct_sql", side_effect=list(corrections)) as correct, \
         mock.patch.object(agent, "_execute", return_value=([{"total": 3}], [])) as execute, \
         mock.patch.object(agent, "explain_results", return_value="three"), \
         contextlib.redirect_stdout(io.StringIO()) as out:
        result = agent.run_agent("total freight this financial year?", catalog, [], security)
    return result, correct, execute, out.getvalue()


class ParseRetry(unittest.TestCase):

    def test_unparseable_sql_gets_one_rewrite(self):
        result, correct, execute, out = run(BROKEN, [FIXED])
        self.assertEqual(correct.call_count, 1)
        hint = correct.call_args[0][4]
        self.assertIn("SQL COULD NOT BE PARSED", hint)
        self.assertIn("single FROM clause", hint)
        self.assertIn("FROM orders", execute.call_args[0][0])
        self.assertEqual(result["answer"], "three")
        self.assertIn("rewrite it as valid SQL", out)

    def test_second_parse_failure_ends_it(self):
        result, correct, execute, _ = run(BROKEN, [BROKEN + " AND 1=1"])
        self.assertEqual(correct.call_count, 1)
        execute.assert_not_called()
        self.assertEqual(result["reason"], "error")

    def test_same_sql_back_stops(self):
        result, correct, execute, _ = run(BROKEN, [BROKEN])
        self.assertEqual(correct.call_count, 1)
        execute.assert_not_called()
        self.assertEqual(result["reason"], "error")

    def test_rewrite_can_say_not_available(self):
        result, _, execute, _ = run(BROKEN, ["DATA_NOT_AVAILABLE"])
        execute.assert_not_called()
        self.assertEqual(result["rule"], "not_available")

    def test_rewrite_gets_every_check_again(self):
        # The rewrite reads a table the role can't see: blocked, not run.
        result, _, execute, _ = run(BROKEN, ["SELECT * FROM employees"],
                                    exclude={"employees", "employee_territories"})
        execute.assert_not_called()
        self.assertTrue(result["blocked"])

    def test_valid_sql_is_not_retried(self):
        _, correct, execute, _ = run(FIXED)
        correct.assert_not_called()
        execute.assert_called_once()


if __name__ == "__main__":
    unittest.main()
