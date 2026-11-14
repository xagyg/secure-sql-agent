# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Tests for the compact conversation history sent with each SQL prompt.
# No database or LLM needed.
#
#     python -m unittest tests.test_history -v

import unittest
from datetime import date
from decimal import Decimal

from sqlagent.adaptive.history import format_history, summarise_result


class SummariseResult(unittest.TestCase):

    def test_no_rows(self):
        self.assertEqual(summarise_result([]), "No rows returned.")

    def test_single_row_keeps_every_value(self):
        rows = [{"ProductName": "Perth Pasties", "LastOrdered": date(1998, 5, 1)}]
        self.assertEqual(
            summarise_result(rows),
            "1 row. ProductName=Perth Pasties, LastOrdered=1998-05-01")

    def test_many_rows_shows_a_sample(self):
        rows = [{"Country": c} for c in ("Germany", "Mexico", "UK", "Spain")]
        text = summarise_result(rows, sample_rows=2)
        self.assertTrue(text.startswith("4 rows. Columns: Country."))
        self.assertIn("First 2: Country=Germany | Country=Mexico", text)
        self.assertNotIn("Spain", text)

    def test_all_rows_shown_when_few(self):
        rows = [{"n": 1}, {"n": 2}]
        self.assertIn("Rows: n=1 | n=2", summarise_result(rows))

    def test_capped_result_is_marked(self):
        rows = [{"n": i} for i in range(10)]
        self.assertIn("capped at 10", summarise_result(rows, row_cap=10))
        self.assertNotIn("capped", summarise_result(rows, row_cap=1000))

    def test_long_values_and_summary_are_cut(self):
        rows = [{"Notes": "x" * 500}]
        text = summarise_result(rows, max_value_chars=20)
        self.assertIn("Notes=" + "x" * 17 + "...", text)
        rows = [{"a": "y" * 30, "b": "z" * 30} for _ in range(5)]
        self.assertLessEqual(len(summarise_result(rows, max_chars=100)), 100)

    def test_values_are_formatted(self):
        rows = [{"Price": Decimal("18.000"), "Ratio": 0.5, "Fax": None}]
        self.assertEqual(summarise_result(rows),
                         "1 row. Price=18, Ratio=0.5, Fax=null")

    def test_withheld_columns_are_named_not_shown(self):
        rows = [{"CompanyName": "Save-a-lot Markets"}]
        text = summarise_result(rows, withheld=["Phone"])
        self.assertIn("Withheld by policy: Phone.", text)


class FormatHistory(unittest.TestCase):

    def _turn(self, n):
        return {"question": f"q{n}", "sql": f"SELECT {n}",
                "answer": f"long prose answer {n}",
                "result_summary": f"summary {n}"}

    def test_empty(self):
        self.assertEqual(format_history([], 3), "")
        self.assertEqual(format_history([self._turn(1)], 0), "")

    def test_keeps_last_turns_only(self):
        text = format_history([self._turn(n) for n in range(1, 6)], 3)
        self.assertNotIn("q2", text)
        for n in (3, 4, 5):
            self.assertIn(f"q{n}", text)

    def test_only_latest_turn_has_sql(self):
        text = format_history([self._turn(1), self._turn(2)], 3)
        self.assertNotIn("SELECT 1", text)
        self.assertIn("Most recent SQL:\nSELECT 2", text)

    def test_sql_turns_setting(self):
        turns = [self._turn(n) for n in range(1, 4)]
        none = format_history(turns, 3, sql_turns=0)
        self.assertNotIn("SELECT", none)
        two = format_history(turns, 3, sql_turns=2)
        self.assertNotIn("SELECT 1", two)
        self.assertIn("SELECT 2", two)
        self.assertIn("SELECT 3", two)
        every = format_history(turns, 3, sql_turns=10)
        for n in (1, 2, 3):
            self.assertIn(f"SELECT {n}", every)

    def test_summary_replaces_prose_answer(self):
        text = format_history([self._turn(1)], 3)
        self.assertIn("summary 1", text)
        self.assertNotIn("long prose answer", text)

    def test_old_turn_without_summary_falls_back_to_answer(self):
        turn = {"question": "q", "sql": "SELECT 1", "answer": "old answer"}
        self.assertIn("old answer", format_history([turn], 3))


if __name__ == "__main__":
    unittest.main()
