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


class ExamplesForQuestion(unittest.TestCase):
    """llm.examples_for_question: at most sql_examples_max, the ones on
    the question's tables and words first."""

    EXAMPLES = [
        example("all customers", "SELECT * FROM customers"),
        example("staff list", "SELECT first_name FROM employees"),
        example("products we sell", "SELECT product_name FROM products"),
        example("orders per customer",
                "SELECT c.company_name, COUNT(*) FROM customers c "
                "JOIN orders o ON o.customer_id = c.customer_id GROUP BY 1"),
        example("shipping companies", "SELECT company_name FROM shippers"),
    ]
    SCHEMA = ("TABLE public.orders  -- orders\n  - order_id int\n\n"
              "TABLE public.customers\n  - customer_id text\n")

    def chosen(self, question, schema="", limit=2):
        with use_database("northwind"):
            return questions(llm.examples_for_question(
                self.EXAMPLES, question, schema, limit))

    def test_tables_in_the_schema_count_most(self):
        # orders per customer: 2 tables in the schema (4); all customers: 1 (2).
        self.assertEqual(self.chosen("show something", self.SCHEMA),
                         ["all customers", "orders per customer"])

    def test_question_words_count(self):
        self.assertEqual(self.chosen("which shipping companies do we use?", limit=1),
                         ["shipping companies"])

    def test_generic_words_do_not_count(self):
        # "show" and "all" are generic: no match, so the first two.
        self.assertEqual(self.chosen("show all"), ["all customers", "staff list"])

    def test_chosen_keep_the_file_order(self):
        self.assertEqual(self.chosen("products for staff"),
                         ["staff list", "products we sell"])

    def test_zero_or_a_short_list_keeps_all(self):
        self.assertEqual(len(self.chosen("x", limit=0)), 5)
        self.assertEqual(len(self.chosen("x", limit=9)), 5)

    def test_quoted_schema_names(self):
        self.assertEqual(llm._schema_tables('TABLE "dbo"."Orders"\nTABLE [x].[Y]'),
                         {"dbo.orders", "x.y"})

    def test_shipped_default_is_five(self):
        from sqlagent.settings import LlmSettings
        self.assertEqual(LlmSettings(model="m").sql_examples_max, 5)

    def log(self, verbose):
        import io
        from contextlib import redirect_stdout
        out = io.StringIO()
        with redirect_stdout(out), \
             mock.patch.object(llm._LLM, "verbose", verbose):
            self.chosen("which shipping companies do we use?", limit=1)
        return out.getvalue()

    def test_log_gives_only_the_count(self):
        log = self.log(False)
        self.assertIn("[llm] SQL examples: 1 of 5\n", log)
        self.assertNotIn("shipping companies", log)

    def test_verbose_log_lists_the_examples_with_scores(self):
        self.assertIn("[llm] SQL examples: 1 of 5: shipping companies (2)",
                      self.log(True))

    def test_verbose_off_by_default_and_set_by_environment(self):
        from sqlagent.settings import load_settings
        self.assertFalse(load_settings(environ={}).llm.verbose)
        settings = load_settings(environ={"SQLAGENT_VERBOSE": "true"})
        self.assertTrue(settings.llm.verbose)
        self.assertIn("SQLAGENT_VERBOSE", settings.overridden)

    def test_prompt_carries_only_the_chosen(self):
        captured = []
        with use_database("northwind"), \
             mock.patch.object(llm._LLM, "sql_examples_max", 1), \
             mock.patch.object(llm, "ask_ollama",
                               side_effect=lambda m: captured.append(m) or "SELECT 1"):
            llm.generate_sql("how many customers?", "SCHEMA", [])
        text = captured[0][0]["content"]
        self.assertIn("SELECT COUNT(*) FROM customers", text)
        self.assertNotIn("SELECT product_name FROM products", text)


class ShippedOdooExamples(unittest.TestCase):

    def test_examples_duplicating_terms_are_gone(self):
        # The customer and out_of_stock terms define these now.
        asked = {e.question for e in load_database_profile("odoo").sql_examples}
        self.assertNotIn("list our customers in Australia", asked)
        self.assertNotIn("which products are currently out of stock?", asked)

    def test_no_example_uses_with(self):
        # The SQL prompt forbids CTEs and the policy rejects them (a CTE's
        # name reads as an unknown table), so an example must not teach one.
        for name in ("odoo", "northwind", "adventureworks"):
            for e in load_database_profile(name).sql_examples:
                with self.subTest(database=name, question=e.question):
                    self.assertNotRegex(e.sql.upper(), r"^\s*WITH\b")

    def test_every_example_parses(self):
        profile = load_database_profile("odoo")
        for e in profile.sql_examples:
            with self.subTest(question=e.question):
                self.assertIsNotNone(llm._example_tables(e.sql, "postgres"))


if __name__ == "__main__":
    unittest.main()
