# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Tests for questions about the database itself ("What does Northwind
# have?") and for vague questions the model can't turn into one query.
# Previously these got the fallback schema, the model guessed
# "WHERE category_name = 'North Wind'" with a READ_ONLY_VIOLATION marker,
# and the user was told the data "may be restricted for your role".
# No database or LLM needed.
#
#     python -m unittest tests.test_unclear_questions -v

import unittest
from unittest import mock

from sqlagent import agent
from sqlagent.adaptive.llm import classify_model_output
from sqlagent.controls.messages import (
    clarify_message,
    overview_message,
    rule_message,
)
from sqlagent.controls.question_policy import is_overview_question
from sqlagent.controls.security_context import SecurityContext
from tests.fixtures import make_catalog


def demo_security():
    return SecurityContext(
        user_id="test",
        roles={"demo"},
        denied_columns={
            "public.customers": {"phone"},
            "public.employees": {"home_phone"},
        },
    )


class OverviewQuestions(unittest.TestCase):

    def test_matches_questions_about_the_database(self):
        for q in [
            "What do North wind have",
            "what does Northwind have?",
            "What data do you have?",
            "what kind of information does the database hold",
            "What's in Northwind?",
            "tell me about the database",
            "What can I ask?",
            "what can you do",
            "help",
            "which tables are available?",
        ]:
            with self.subTest(q=q):
                self.assertTrue(is_overview_question(q))

    def test_leaves_real_data_questions_alone(self):
        for q in [
            "what products does Northwind have?",
            "what information do you have about Jose?",
            "what do you have on Maria Anders?",
            "how many customers are there?",
            "which customers are in Germany?",
            "what does Nancy's order history look like?",
            "delete all customers",
        ]:
            with self.subTest(q=q):
                self.assertFalse(is_overview_question(q))


class UnclearMarker(unittest.TestCase):

    def test_bare_marker(self):
        self.assertEqual(classify_model_output("UNCLEAR_QUESTION"), "unclear")

    def test_marker_line_beats_sql(self):
        text = ("SELECT * FROM categories WHERE category_name = 'North Wind';\n"
                "UNCLEAR_QUESTION")
        self.assertEqual(classify_model_output(text), "unclear")


class Messages(unittest.TestCase):

    def test_messages_never_blame_security(self):
        for msg in (overview_message(["Sales"]), clarify_message(["Sales"])):
            self.assertNotIn("restricted", msg.lower())
            self.assertNotIn("role", msg.lower())

    def test_areas_listed(self):
        msg = overview_message(["Sales", "Human Resources", "Financials"])
        self.assertIn("Sales, Human Resources and Financials", msg)


class RunAgent(unittest.TestCase):
    """End to end with the model stubbed out."""

    def setUp(self):
        self.catalog = make_catalog()
        self.security = demo_security()

    def run_with_model_reply(self, question, reply):
        with mock.patch.object(agent, "generate_sql", return_value=reply) as gen:
            result = agent.run_agent(question, self.catalog, [], self.security)
        return result, gen

    def test_overview_question_skips_the_model(self):
        result, gen = self.run_with_model_reply("What do North wind have", "SELECT 1")
        gen.assert_not_called()
        self.assertFalse(result["blocked"])
        self.assertIsNone(result["reason"])
        self.assertIn("Sales", result["answer"])
        self.assertIsNone(result["sql"])

    def test_overview_lists_only_authorised_areas(self):
        # Without the HR tables, the HR domain mustn't be offered.
        self.catalog = make_catalog(exclude=(
            "employees", "employee_territories", "territories", "region"))
        result, _ = self.run_with_model_reply("what data do you have?", "SELECT 1")
        self.assertNotIn("Human Resources", result["answer"])
        self.assertIn("Sales", result["answer"])

    def test_misused_write_marker_on_vague_question_asks_to_clarify(self):
        # The trace from the bug report, for a vague question that isn't
        # caught as an overview question.
        reply = ("SELECT * FROM categories WHERE category_name = 'North Wind';\n"
                 "READ_ONLY_VIOLATION")
        result, _ = self.run_with_model_reply("show me some north wind stuff", reply)
        self.assertFalse(result["blocked"])
        self.assertIsNone(result["reason"])
        self.assertEqual(result["answer"], clarify_message(
            agent._available_areas(self.catalog)))
        self.assertNotEqual(result["answer"], rule_message("not_available"))

    def test_misused_write_marker_on_restricted_column_is_still_restricted(self):
        result, _ = self.run_with_model_reply(
            "what is Maria's phone number?", "READ_ONLY_VIOLATION")
        self.assertTrue(result["blocked"])
        self.assertEqual(result["rule"], "restricted_data")

    def test_real_write_request_is_still_read_only(self):
        result, _ = self.run_with_model_reply(
            "delete all customers", "READ_ONLY_VIOLATION")
        self.assertTrue(result["blocked"])
        self.assertEqual(result["rule"], "read_only")

    def test_unclear_marker(self):
        result, _ = self.run_with_model_reply("what's going on?", "UNCLEAR_QUESTION")
        self.assertFalse(result["blocked"])
        self.assertIn("not sure what you're asking", result["answer"])

    def test_data_not_available_unchanged(self):
        result, _ = self.run_with_model_reply(
            "what is the CEO's salary?", "DATA_NOT_AVAILABLE")
        self.assertTrue(result["blocked"])
        self.assertEqual(result["rule"], "not_available")


if __name__ == "__main__":
    unittest.main()
