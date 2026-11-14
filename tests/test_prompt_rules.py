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
        self.assertIn("Only return id columns when the user asks for ids", text)

    def test_old_narrow_rule_is_gone(self):
        self.assertNotIn("When the user asks for a person, customer, employee",
                         system_prompt())


if __name__ == "__main__":
    unittest.main()
