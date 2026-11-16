# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Tests for the prompt that explains a result (llm.explain_results): the
# row count stated before and after the rows, at most explain_rows rows
# shown compactly, long values cut, and a capped result reported as
# "at least". No database or LLM needed.
#
#     python -m unittest tests.test_explain_prompt -v

import json
import unittest
from unittest import mock

from sqlagent.adaptive import llm


def prompt_for(results, row_cap=None, rows=50, value_chars=300, chars=100_000):
    captured = []
    with mock.patch.object(llm, "EXPLAIN_ROWS", rows), \
         mock.patch.object(llm, "EXPLAIN_VALUE_CHARS", value_chars), \
         mock.patch.object(llm, "EXPLAIN_RESULT_CHARS", chars), \
         mock.patch.object(llm, "ask_ollama",
                           side_effect=lambda m: captured.append(m) or "ok"):
        llm.explain_results("q", "SELECT ...", results, row_cap=row_cap)
    return captured[0][1]["content"]


def rows(n, **extra):
    return [{"id": i, "name": f"account {i}", **extra} for i in range(n)]


class ExplainPrompt(unittest.TestCase):

    def test_small_result_shows_every_row(self):
        text = prompt_for(rows(3))
        self.assertIn("RESULTS (one row per line)", text)
        self.assertIn('{"id": 2, "name": "account 2"}', text)
        self.assertIn("ROW COUNT (again): 3", text)

    def test_large_result_is_sampled_and_counted(self):
        text = prompt_for(rows(100), rows=50)
        self.assertIn("RESULTS (the first 50 of 100 rows, one per line)", text)
        self.assertIn('"id": 49', text)
        self.assertNotIn('"id": 50,', text)
        self.assertIn("ROW COUNT\n100", text)
        self.assertIn("ROW COUNT (again): 100", text)
        self.assertIn("describe the shown rows as examples", text)

    def test_complete_result_is_not_called_examples(self):
        text = prompt_for(rows(6))
        self.assertIn("Every row is shown: this is the complete result", text)
        self.assertNotIn("describe the shown rows as examples", text)

    def test_no_table_or_column_names_rule(self):
        self.assertIn("Don't name tables or columns", prompt_for(rows(3)))

    def test_capped_result_says_at_least(self):
        text = prompt_for(rows(100), row_cap=100)
        self.assertIn('the row limit: there may be more; say "at least 100"', text)
        self.assertNotIn("row limit", prompt_for(rows(99), row_cap=100))

    def test_long_values_are_cut(self):
        text = prompt_for([{"note": "x" * 1000}], value_chars=50)
        self.assertIn('"x' + "x" * 46 + '..."', text)
        self.assertNotIn("x" * 60, text)

    def test_one_compact_line_per_row(self):
        text = prompt_for(rows(2))
        block = text.split("RESULTS (one row per line)\n", 1)[1].split("\n\n", 1)[0]
        self.assertEqual([json.loads(line)["id"] for line in block.splitlines()], [0, 1])

    def test_no_rows(self):
        text = prompt_for([])
        self.assertIn("ROW COUNT\n0", text)
        self.assertIn("(no rows)", text)

    def test_character_budget_limits_wide_rows(self):
        wide = [{f"column_{c}": "value" * 4 for c in range(16)} for _ in range(100)]
        text = prompt_for(wide, chars=2000)
        shown = int(text.split("RESULTS (the first ", 1)[1].split(" ", 1)[0])
        self.assertLess(shown, 10)
        self.assertIn("ROW COUNT (again): 100", text)

    def test_at_least_one_row_even_if_over_budget(self):
        text = prompt_for([{"note": "y" * 500}, {"note": "z"}], chars=100)
        self.assertIn("RESULTS (the first 1 of 2 rows", text)

    def test_shipped_settings(self):
        self.assertEqual((llm.EXPLAIN_ROWS, llm.EXPLAIN_VALUE_CHARS,
                          llm.EXPLAIN_RESULT_CHARS), (50, 300, 8000))


if __name__ == "__main__":
    unittest.main()
