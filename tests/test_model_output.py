# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Tests for reading the model's reply (llm.classify_model_output) and for
# clean parse errors. No database or LLM needed.
#
#     python -m unittest tests.test_model_output -v

import unittest

from sqlagent.agent import _normalise_sql
from sqlagent.controls.sql_policy import parse_single_sql
from sqlagent.adaptive.llm import classify_model_output


class ClassifyModelOutput(unittest.TestCase):

    def test_plain_sql(self):
        self.assertEqual(classify_model_output("SELECT 1"), "sql")

    def test_bare_markers(self):
        self.assertEqual(classify_model_output("READ_ONLY_VIOLATION"), "write_request")
        self.assertEqual(classify_model_output("`DATA_NOT_AVAILABLE`."), "not_available")
        self.assertEqual(classify_model_output("NOT_A_DATA_QUESTION"), "off_topic")

    def test_marker_line_beats_sql(self):
        # The hedged reply from "What is Maria's phone number?".
        text = ("SELECT phone FROM suppliers WHERE contact_name = 'Maria Anders'\n"
                "READ_ONLY_VIOLATION")
        self.assertEqual(classify_model_output(text), "write_request")

    def test_marker_before_sql(self):
        text = "DATA_NOT_AVAILABLE\nSELECT phone FROM suppliers"
        self.assertEqual(classify_model_output(text), "not_available")

    def test_two_different_markers(self):
        text = "READ_ONLY_VIOLATION\nDATA_NOT_AVAILABLE"
        self.assertEqual(classify_model_output(text), "no_sql")

    def test_marker_mid_sentence_does_not_count(self):
        text = "SELECT 'READ_ONLY_VIOLATION' AS note"
        self.assertEqual(classify_model_output(text), "sql")

    def test_prose(self):
        self.assertEqual(classify_model_output("I can't help with that."), "no_sql")


class ParseErrors(unittest.TestCase):

    def test_no_terminal_codes_in_parse_error(self):
        with self.assertRaises(ValueError) as ctx:
            parse_single_sql(
                "SELECT phone FROM suppliers WHERE contact_name = 'Maria Anders'\n"
                "READ_ONLY_VIOLATION")
        self.assertNotIn("\x1b", str(ctx.exception))
        self.assertIn("could not be parsed", str(ctx.exception))


class SameSqlCheck(unittest.TestCase):
    """The correction step stops when the model returns the query it
    already wrote (see _run_pipeline)."""

    def test_same_query_matches(self):
        self.assertEqual(_normalise_sql("SELECT nme FROM suppliers;"),
                         _normalise_sql("  select nme\n  from suppliers "))

    def test_different_query_differs(self):
        self.assertNotEqual(_normalise_sql("SELECT nme FROM suppliers"),
                            _normalise_sql("SELECT company_name FROM suppliers"))


if __name__ == "__main__":
    unittest.main()
