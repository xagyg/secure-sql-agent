# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Tests for how the schema is written into the SQL prompt
# (retrieval.schema_text): supporting tables list only the columns that
# matter, types are shortened and NULL markers dropped. No database or
# LLM needed.
#
#     python -m unittest tests.test_schema_text -v

import unittest
from unittest import mock

from sqlagent.settings import SchemaText
from tests.fixtures import make_catalog

WIDE = [f"setting_{i}" for i in range(40)]


def catalog_with_wide_table():
    catalog = make_catalog(extra_tables={
        "public.company": ["id", "name", "currency", *WIDE],
    })
    catalog.tables["public.orders"]["columns"].append(
        {"name": "company_id", "type": "integer", "nullable": True})
    catalog.foreign_keys = catalog.foreign_keys + catalog._build_relationships([
        {"from_table": "public.orders", "from_columns": ("company_id",),
         "to_table": "public.company", "to_columns": ("id",),
         "cardinality": None, "source": "database"}])
    return catalog


def style(**values):
    settings = mock.MagicMock()
    settings.retrieval.schema_text = SchemaText(**values)
    return mock.patch("sqlagent.adaptive.schema_catalog.get_settings",
                      return_value=settings)


class SupportingTables(unittest.TestCase):

    def setUp(self):
        self.catalog = catalog_with_wide_table()
        self.selected = {"public.orders", "public.company"}

    def text(self, focus, question=None, **values):
        with style(**values), \
             mock.patch.object(self.catalog, "question_terms",
                               side_effect=lambda q: set(q.lower().split())):
            return self.catalog._format_context(self.selected, focus=focus,
                                                question=question)

    def test_supporting_table_lists_only_what_matters(self):
        text = self.text({"public.orders"})
        company = text.split("TABLE public.company")[1].split("TABLE")[0]
        self.assertIn("  - id text", company)
        self.assertIn("  - name text", company)
        self.assertNotIn("setting_5", company)
        self.assertIn("... 41 more columns, not listed", company)

    def test_matched_table_lists_every_column(self):
        text = self.text({"public.orders", "public.company"})
        self.assertIn("setting_39", text)
        self.assertNotIn("more columns, not listed", text)

    def test_column_the_question_names_is_kept(self):
        text = self.text({"public.orders"}, question="orders by currency")
        self.assertIn("currency", text.split("TABLE public.company")[1])

    def test_relationship_key_is_kept(self):
        # orders is the focus; its company_id key is in its own full list,
        # and company.id (the other end) is kept on the supporting table.
        company = self.text({"public.orders"}).split("TABLE public.company")[1]
        self.assertIn("  - id text", company)

    def test_off_lists_every_column(self):
        text = self.text({"public.orders"}, supporting_table_columns=0)
        self.assertIn("setting_39", text)

    def test_no_focus_lists_every_column(self):
        self.assertIn("setting_39", self.text(None))


class ColumnWordMatch(unittest.TestCase):
    """When the question names a table, a table matched only on a column
    word is left out; the named tables and their walk remain."""

    def test_column_word_match_is_dropped_when_a_table_is_named(self):
        catalog = make_catalog(extra_tables={
            "public.audit_log": ["id", "freight_note", *WIDE]})
        terms = catalog.question_terms("show orders with their freight")
        self.assertGreater(catalog.score_table(catalog.tables["public.audit_log"], terms), 0)
        text = catalog.get_context("show orders with their freight")
        self.assertIn("TABLE public.orders", text)
        self.assertNotIn("audit_log", text)
        # orders is named, so every column is listed.
        orders = text.split("TABLE public.orders")[1].split("TABLE")[0]
        self.assertNotIn("not listed", orders)

    def test_related_table_is_still_walked_in(self):
        # order_details isn't named, but orders' walk brings it in.
        text = catalog_with_wide_table().get_context("show orders with their freight")
        self.assertIn("TABLE public.order_details", text)


class ColumnLines(unittest.TestCase):

    def line(self, column_type, **values):
        catalog = make_catalog(extra_tables={"public.t": ["a"]})
        catalog.tables["public.t"]["columns"] = [
            {"name": "a", "type": column_type, "nullable": False}]
        with style(**values):
            return catalog._format_context({"public.t"}).splitlines()[1]

    def test_types_are_shortened(self):
        self.assertEqual(self.line("character varying"), "  - a varchar")
        self.assertEqual(self.line("timestamp without time zone"), "  - a timestamp")
        self.assertEqual(self.line("jsonb").split("  --")[0], "  - a jsonb")

    def test_long_types_can_be_kept(self):
        self.assertEqual(self.line("character varying", compact_types=False),
                         "  - a character varying")

    def test_nullability_can_be_shown(self):
        self.assertEqual(self.line("integer", show_nullability=True),
                         "  - a int NOT NULL")


if __name__ == "__main__":
    unittest.main()
