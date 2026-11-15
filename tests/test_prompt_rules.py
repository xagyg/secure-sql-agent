# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Tests for rules in the SQL-generation prompt. No database or LLM needed.
#
#     python -m unittest tests.test_prompt_rules -v

import unittest
from unittest import mock

from sqlagent.adaptive import llm
from tests.test_sqlserver import use_database


def system_prompt():
    captured = []
    with use_database("northwind"), \
         mock.patch.object(llm, "ask_ollama",
                           side_effect=lambda m: captured.append(m) or "SELECT 1"):
        llm.generate_sql("q", "SCHEMA", [])
    return captured[0][0]["content"]


class NamesNotIds(unittest.TestCase):
    """Results showed partner_id: 11 instead of the vendor's name (Q31, 34, 61)."""

    def test_rule_covers_every_reference_column(self):
        text = system_prompt()
        self.assertIn("Show names, not internal IDs", text)
        self.assertIn("join that record's table and select its name", text)
        self.assertIn("unless the user asks", text)

    def test_old_narrow_rule_is_gone(self):
        self.assertNotIn("When the user asks for a person, customer, employee",
                         system_prompt())


class TrimmedRules(unittest.TestCase):
    """Rules the code enforces itself are left out of the prompts."""

    def test_generation_prompt(self):
        text = system_prompt()
        self.assertNotIn("Only SELECT queries", text)
        self.assertNotIn("home phone", text)
        self.assertIn("no subqueries in FROM or JOIN", text)
        self.assertIn("Reply with the SQL only", text)

    def test_correction_prompt(self):
        captured = []
        with use_database("northwind"), \
             mock.patch.object(llm, "ask_ollama",
                               side_effect=lambda m: captured.append(m) or "SELECT 1"):
            llm.correct_sql("q", "SCHEMA", "SELECT x", "error", "HINT")
        text = captured[0][1]["content"]
        self.assertIn("Follow any hint above the TASK", text)
        self.assertNotIn("KNOWN COLUMN MAPPING is supplied", text)
        self.assertNotIn("Do not modify data", text)
        self.assertIn("DATA_NOT_AVAILABLE", text)


if __name__ == "__main__":
    unittest.main()
