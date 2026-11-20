# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Tests for the ways a request ends early in agent._run_pipeline(): each
# step raises agent._Finished with the result dict, caught once. Runs the
# real validator on Northwind; the model, the database and the error
# diagnosis are replaced. No database or LLM needed.
#
#     python -m unittest tests.test_pipeline_exits -v

import contextlib
import io
import unittest
from unittest import mock

from sqlagent import agent
from sqlagent.controls.row_scope import RowScopeError
from sqlagent.controls.security_context import SecurityContext
from tests.fixtures import make_catalog

GOOD_SQL = "SELECT company_name FROM customers"


def run(generated=GOOD_SQL, corrections=(), execute=None, **patches):
    """run_agent() with the model's SQL, its corrections (values or
    exceptions) and _execute's results or exceptions, in order."""
    catalog = make_catalog(exclude={"employees", "employee_territories"})
    security = SecurityContext(user_id="sam", roles={"sales"},
                               tables=set(catalog.tables),
                               denied_columns={"public.customers": {"fax"}})
    execute = execute if execute is not None else [([{"company_name": "A"}], [])]
    with contextlib.ExitStack() as stack:
        stack.enter_context(mock.patch.object(agent, "generate_sql", return_value=generated))
        correct = stack.enter_context(
            mock.patch.object(agent, "correct_sql", side_effect=list(corrections)))
        ran = stack.enter_context(
            mock.patch.object(agent, "_execute", side_effect=list(execute)))
        stack.enter_context(mock.patch.object(agent, "explain_results", return_value="ok"))
        for name, value in patches.items():
            stack.enter_context(mock.patch.object(agent, name, value))
        stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        result = agent.run_agent("which customers are there?", catalog, [], security)
    return result, correct, ran


class PipelineExits(unittest.TestCase):

    def test_answered(self):
        result, correct, ran = run()
        self.assertEqual(result["answer"], "ok")
        self.assertIsNone(result["reason"])
        correct.assert_not_called()

    def test_prepare_error_is_a_technical_error(self):
        result, _, ran = run(prepare_sql=mock.Mock(side_effect=ValueError("boom")))
        self.assertEqual(result["reason"], "error")
        self.assertFalse(result["blocked"])
        self.assertIn("couldn't safely prepare", result["answer"])
        ran.assert_not_called()

    def test_table_retry_model_failure(self):
        result, _, ran = run("SELECT COUNT(*) FROM order_shipping_log",
                             corrections=[TimeoutError("model down")])
        self.assertEqual(result["reason"], "error")
        self.assertEqual(result["answer"], "I couldn't correct that query.")
        ran.assert_not_called()

    def test_execution_error_then_model_failure(self):
        result, _, _ = run(corrections=[TimeoutError("model down")],
                           execute=[RuntimeError("column x does not exist")])
        self.assertEqual(result["reason"], "error")
        self.assertEqual(result["answer"], "I couldn't correct that query.")

    def test_execution_error_then_same_sql(self):
        result, _, ran = run(corrections=[GOOD_SQL],
                             execute=[RuntimeError("column x does not exist")])
        self.assertEqual(result["answer"], "I wasn't able to correct that query.")
        self.assertEqual(ran.call_count, 1)

    def test_correction_that_fails_validation_is_blocked(self):
        result, _, ran = run(corrections=["SELECT company_name, fax FROM customers "
                                          "WHERE fax LIKE '0%'"],
                             execute=[RuntimeError("column x does not exist")])
        self.assertTrue(result["blocked"])
        self.assertEqual(result["rule"], "restricted_data")
        self.assertEqual(ran.call_count, 1)

    def test_row_scope_failure_on_corrected_sql(self):
        result, _, ran = run(corrections=["SELECT contact_name FROM customers"],
                             execute=[RuntimeError("column x does not exist"),
                                      RowScopeError("cannot scope")])
        self.assertTrue(result["blocked"])
        self.assertEqual(result["rule"], "policy")
        self.assertEqual(ran.call_count, 2)

    def test_row_scope_failure_on_first_run(self):
        result, correct, _ = run(execute=[RowScopeError("cannot scope")])
        self.assertTrue(result["blocked"])
        self.assertEqual(result["rule"], "policy")
        correct.assert_not_called()

    def test_error_naming_a_restricted_column_ends_without_correction(self):
        diagnosis = {"error_type": "invalid_column_alias_denied", "column": "tel",
                     "matches": [{"table": "public.customers", "column": "fax"}]}
        result, correct, _ = run(execute=[RuntimeError('column "tel" does not exist')],
                                 diagnose_sql_error=mock.Mock(return_value=diagnosis))
        self.assertTrue(result["blocked"])
        self.assertEqual(result["rule"], "restricted_data")
        correct.assert_not_called()


if __name__ == "__main__":
    unittest.main()
