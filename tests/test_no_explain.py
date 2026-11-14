# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Tests for run_agent(explain=False) (main.py --no-explain): the LLM
# explanation is skipped and the rows are shown instead, with every
# security step on the result still applied. No database or LLM needed.
#
#     python -m unittest tests.test_no_explain -v

import contextlib
import io
import unittest
from unittest import mock

from sqlagent import agent
from sqlagent.adaptive.history import format_results_table
from sqlagent.controls.security_context import SecurityContext
from tests.fixtures import make_catalog


def run(rows, explain, sql="SELECT company_name, country FROM customers",
        denied=None, sources=None):
    catalog = make_catalog()
    security = SecurityContext(user_id="sam", roles={"sales"},
                               tables=set(catalog.tables),
                               denied_columns=denied or {})
    with mock.patch.object(agent, "generate_sql", return_value=sql), \
         mock.patch.object(agent, "execute_sql_with_sources",
                           return_value=(rows, sources or {})), \
         mock.patch.object(agent, "explain_results", return_value="Two customers.") as explain_mock, \
         contextlib.redirect_stdout(io.StringIO()) as out:
        history = []
        result = agent.run_agent("customers?", catalog, history, security, explain=explain)
    return result, explain_mock, out.getvalue(), history


ROWS = [{"company_name": "Alfreds Futterkiste", "country": "Germany"},
        {"company_name": "Ana Trujillo", "country": "Mexico"}]


class NoExplain(unittest.TestCase):

    def test_explanation_is_skipped_and_rows_shown(self):
        result, explain_mock, out, _ = run(ROWS, explain=False)
        explain_mock.assert_not_called()
        self.assertIn("[answer] (explanation skipped)", out)
        self.assertIn("2 row(s).", result["answer"])
        self.assertIn("Alfreds Futterkiste | Germany", result["answer"])

    def test_default_still_explains(self):
        result, explain_mock, _, _ = run(ROWS, explain=True)
        explain_mock.assert_called_once()
        self.assertEqual(result["answer"], "Two customers.")

    def test_history_is_the_same_either_way(self):
        *_, with_llm = run(ROWS, explain=True)
        *_, without = run(ROWS, explain=False)
        self.assertEqual(with_llm[0]["result_summary"], without[0]["result_summary"])

    def test_result_policy_still_withholds_columns(self):
        # A denied column that comes back in the rows (e.g. through an
        # expression) is still removed before anything is shown.
        rows = [{"company_name": "Alfreds Futterkiste", "phone": "030-0074321"}]
        result, _, out, _ = run(
            rows, explain=False, sql="SELECT company_name FROM customers",
            denied={"public.customers": {"phone"}},
            sources={"phone": ("public.customers", "phone")})
        self.assertNotIn("030-0074321", result["answer"])
        self.assertNotIn("030-0074321", out)


class Table(unittest.TestCase):

    def test_layout(self):
        self.assertEqual(format_results_table(ROWS),
                         "company_name        | country\n"
                         "--------------------+--------\n"
                         "Alfreds Futterkiste | Germany\n"
                         "Ana Trujillo        | Mexico")

    def test_more_rows_are_counted(self):
        text = format_results_table([{"n": i} for i in range(25)], max_rows=20)
        self.assertTrue(text.endswith("... 5 more row(s)"))

    def test_long_values_are_cut(self):
        self.assertIn("...", format_results_table([{"note": "x" * 200}], max_value_chars=20))

    def test_empty(self):
        self.assertEqual(format_results_table([]), "(no rows)")


if __name__ == "__main__":
    unittest.main()
