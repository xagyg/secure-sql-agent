# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Tests for choosing the SQL examples that go into the SQL-generation
# prompt (llm.examples_for_role): only examples whose tables the role may
# see. No database or LLM needed.
#
#     python -m unittest tests.test_sql_examples -v

import unittest
from unittest import mock

from sqlagent.adaptive import llm
from sqlagent.databases import SqlExample, load_database_profile
from tests.test_sqlserver import use_database


def example(question, sql):
    return SqlExample(question=question, sql=sql)


EXAMPLES = [
    example("all customers", "SELECT * FROM customers"),
    example("orders per customer",
            "SELECT c.company_name, COUNT(*) FROM customers c "
            "JOIN orders o ON o.customer_id = c.customer_id GROUP BY 1"),
    example("staff", "SELECT first_name FROM employees"),
    example("with a subquery",
            "SELECT * FROM customers c WHERE EXISTS "
            "(SELECT 1 FROM orders o WHERE o.customer_id = c.customer_id)"),
    example("broken", "SELECT FROM WHERE ((("),
]


def questions(examples):
    return [e.question for e in examples]


class ExamplesForRole(unittest.TestCase):

    def test_only_examples_on_allowed_tables(self):
        kept = llm.examples_for_role(EXAMPLES, {"public.customers", "public.orders"})
        self.assertEqual(questions(kept),
                         ["all customers", "orders per customer", "with a subquery"])

    def test_one_hidden_table_drops_the_example(self):
        kept = llm.examples_for_role(EXAMPLES, {"public.customers"})
        self.assertEqual(questions(kept), ["all customers"])

    def test_names_match_case_insensitively(self):
        kept = llm.examples_for_role(EXAMPLES, {"PUBLIC.Employees"})
        self.assertEqual(questions(kept), ["staff"])

    def test_unparseable_example_is_left_out(self):
        kept = llm.examples_for_role(EXAMPLES, {"public.customers", "public.orders",
                                                "public.employees"})
        self.assertNotIn("broken", questions(kept))

    def test_none_keeps_every_example(self):
        self.assertEqual(llm.examples_for_role(EXAMPLES, None), EXAMPLES)


class PromptExamples(unittest.TestCase):

    def prompt(self, allowed_tables):
        captured = []
        with use_database("northwind"), \
             mock.patch.object(llm, "ask_ollama",
                               side_effect=lambda m: captured.append(m) or "SELECT 1"):
            llm.generate_sql("q", "SCHEMA", [], allowed_tables=allowed_tables)
        return captured[0][0]["content"]

    def test_hidden_table_examples_are_not_sent(self):
        text = self.prompt({"public.customers"})
        self.assertIn("SELECT COUNT(*) FROM customers", text)
        self.assertNotIn("SELECT product_name FROM products", text)

    def test_every_example_without_a_catalog(self):
        text = self.prompt(None)
        self.assertIn("SELECT product_name FROM products", text)


class ShippedOdooExamples(unittest.TestCase):

    def test_examples_duplicating_terms_are_gone(self):
        # The customer and out_of_stock terms define these now.
        asked = {e.question for e in load_database_profile("odoo").sql_examples}
        self.assertNotIn("list our customers in Australia", asked)
        self.assertNotIn("which products are currently out of stock?", asked)

    def test_every_example_parses(self):
        profile = load_database_profile("odoo")
        for e in profile.sql_examples:
            with self.subTest(question=e.question):
                self.assertIsNotNone(llm._example_tables(e.sql, "postgres"))


if __name__ == "__main__":
    unittest.main()
