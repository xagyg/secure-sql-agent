# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Tests for the REPL's batch mode (main.py --questions): reading the
# questions file, naming the results file, and running each question as
# the REPL would. No database or LLM needed.
#
#     python -m unittest tests.test_batch -v

import io
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime
from pathlib import Path
from unittest import mock

import main


def questions_file(text):
    handle = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False,
                                         encoding="utf-8")
    handle.write(text)
    handle.close()
    return handle.name


class ReadQuestions(unittest.TestCase):

    def test_one_question_per_line(self):
        path = questions_file("Which customers are in Germany?\n"
                              "  only those in Berlin  \n")
        self.assertEqual(main.read_questions(path),
                         ["Which customers are in Germany?", "only those in Berlin"])

    def test_blank_lines_and_comments_are_skipped(self):
        path = questions_file("# sales checks\n\nTop 5 customers?\n\n# end\n")
        self.assertEqual(main.read_questions(path), ["Top 5 customers?"])

    def test_dashes_start_a_new_conversation(self):
        path = questions_file("---\nq1\nq2\n---\n-----\nq3\n---\n")
        self.assertEqual(main.read_questions(path),
                         ["q1", "q2", main.NEW_CONVERSATION, "q3"])

    def test_exit_word_ends_the_file(self):
        path = questions_file("q1\nquit\nq2\n")
        self.assertEqual(main.read_questions(path), ["q1"])

    def test_questions_that_contain_exit_words_are_kept(self):
        path = questions_file("who is on leave?\n")
        self.assertEqual(main.read_questions(path), ["who is on leave?"])

    def test_list_numbers_are_removed(self):
        path = questions_file("1. Which customers are in Germany?\n"
                              "10.  only those in Berlin\n"
                              "3) top 5 products?\n")
        self.assertEqual(main.read_questions(path),
                         ["Which customers are in Germany?",
                          "only those in Berlin", "top 5 products?"])

    def test_numbers_that_are_part_of_the_question_are_kept(self):
        path = questions_file("1.5% of revenue is what?\n"
                              "2024 sales by month\n"
                              "10 most expensive products\n")
        self.assertEqual(main.read_questions(path),
                         ["1.5% of revenue is what?", "2024 sales by month",
                          "10 most expensive products"])

    def test_number_alone_is_skipped_and_numbered_exit_ends(self):
        path = questions_file("1.\n2. q1\n3. quit\n4. q2\n")
        self.assertEqual(main.read_questions(path), ["q1"])

    def test_utf8_with_bom(self):
        # Notepad and PowerShell may save with a byte-order mark.
        path = questions_file("﻿Folk och fä HB orders?\n")
        self.assertEqual(main.read_questions(path), ["Folk och fä HB orders?"])


class ResultsPath(unittest.TestCase):

    def test_named_after_the_questions_file(self):
        path = main.default_results_path(Path("tests") / "odoo.txt",
                                         now=datetime(2026, 11, 14, 15, 2))
        self.assertEqual(path, Path("tests") / "odoo-results-20261114-1502.txt")


class RunBatch(unittest.TestCase):

    def run_items(self, items, side_effect=None):
        seen = []

        def fake_run_agent(question, catalog, history, security):
            seen.append((question, list(history)))
            history.append(question)
            if side_effect:
                side_effect(question)

        out = io.StringIO()
        with mock.patch.object(main, "run_agent", fake_run_agent), redirect_stdout(out):
            main.run_batch(items, catalog=None, security=None)
        return seen, out.getvalue()

    def test_questions_share_a_conversation(self):
        seen, _ = self.run_items(["q1", "q2"])
        self.assertEqual(seen, [("q1", []), ("q2", ["q1"])])

    def test_new_conversation_clears_the_history(self):
        seen, out = self.run_items(["q1", main.NEW_CONVERSATION, "q2"])
        self.assertEqual(seen[1], ("q2", []))
        self.assertIn("new conversation", out)

    def test_each_question_is_numbered_and_echoed(self):
        _, out = self.run_items(["q1", "q2"])
        self.assertIn("Question 2 of 2", out)
        self.assertIn("\n> q2", out)
        self.assertIn("Done: 2 question(s)", out)

    def test_an_error_is_reported_and_the_batch_goes_on(self):
        def boom(question):
            if question == "q1":
                raise TimeoutError("Ollama took too long")

        seen, out = self.run_items(["q1", "q2"], side_effect=boom)
        self.assertEqual([q for q, _ in seen], ["q1", "q2"])
        self.assertIn("[error] TimeoutError: Ollama took too long", out)
        self.assertIn("1 failed with an error", out)


class Tee(unittest.TestCase):

    def test_writes_to_both(self):
        a, b = io.StringIO(), io.StringIO()
        main.Tee(a, b).write("hello")
        self.assertEqual((a.getvalue(), b.getvalue()), ("hello", "hello"))


if __name__ == "__main__":
    unittest.main()
