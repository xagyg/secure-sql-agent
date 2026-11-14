# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# The correction hint for json/jsonb type errors
# (sqlagent/execution/sql_diagnostics.py: json_correction_hint).

import unittest

from sqlagent.execution.sql_diagnostics import (
    is_json_type_error,
    json_columns_in_sql,
    json_correction_hint,
)


def _col(name, type_, description=None):
    return {"name": name, "type": type_, "nullable": True,
            "description": description}


class _Catalog:
    """Just what the hint uses: tables and resolve_table_name()."""

    def __init__(self, tables):
        self.tables = {f"public.{t['name']}": t for t in tables}

    def resolve_table_name(self, name):
        bare = name.split(".")[-1].lower()
        return next((k for k, t in self.tables.items()
                     if t["name"].lower() == bare), None)


CATALOG = _Catalog([
    {"schema": "public", "name": "product_product", "columns": [
        _col("id", "integer"),
        _col("product_tmpl_id", "integer"),
        _col("standard_price", "jsonb",
             "JSONB by company: use (standard_price->>'1')::numeric"),
    ]},
    {"schema": "public", "name": "product_template", "columns": [
        _col("id", "integer"),
        _col("name", "jsonb", "JSONB by language: use name->>'en_US'"),
    ]},
    {"schema": "public", "name": "stock_quant", "columns": [
        _col("product_id", "integer"),
        _col("quantity", "numeric"),
    ]},
    {"schema": "public", "name": "res_partner", "columns": [
        _col("id", "integer"),
        _col("name", "character varying"),
        _col("properties", "jsonb"),
    ]},
])

VALUE_SQL = (
    "SELECT pt.name, SUM(q.quantity * pp.standard_price) "
    "FROM stock_quant AS q "
    "JOIN product_product AS pp ON pp.id = q.product_id "
    "JOIN product_template AS pt ON pt.id = pp.product_tmpl_id "
    "GROUP BY pt.name")


class JsonErrorDetection(unittest.TestCase):

    def test_json_errors_are_recognised(self):
        for text in ("operator does not exist: numeric * jsonb",
                     "operator does not exist: jsonb = integer",
                     'invalid input syntax for type json'):
            self.assertTrue(is_json_type_error(text), text)

    def test_other_errors_are_not(self):
        for text in ('column "x" does not exist',
                     'relation "jsonish_table" does not exist', ""):
            self.assertFalse(is_json_type_error(text), text)


class JsonColumns(unittest.TestCase):

    def test_names_each_json_column_once_with_its_note(self):
        found = json_columns_in_sql(VALUE_SQL, CATALOG)
        self.assertEqual(
            [(t, c) for t, c, _ in found],
            [("product_template", "name"), ("product_product", "standard_price")])
        self.assertIn("->>'1'", found[1][2])

    def test_plain_columns_are_not_named(self):
        sql = "SELECT name FROM res_partner WHERE name = 'Gemini'"
        self.assertEqual(json_columns_in_sql(sql, CATALOG), [])

    def test_unqualified_column_needs_a_single_owner(self):
        # "name" is on res_partner (text) and product_template (jsonb):
        # ambiguous, so not named.
        sql = ("SELECT name FROM res_partner "
               "JOIN product_template ON product_template.id = res_partner.id")
        self.assertEqual(json_columns_in_sql(sql, CATALOG), [])

    def test_table_not_in_catalog_is_ignored(self):
        sql = "SELECT secret FROM ir_config_parameter"
        self.assertEqual(json_columns_in_sql(sql, CATALOG), [])

    def test_unparseable_sql_gives_nothing(self):
        self.assertEqual(json_columns_in_sql("SELEC nonsense ((", CATALOG), [])


class Hint(unittest.TestCase):

    def test_hint_for_a_json_error(self):
        hint = json_correction_hint(
            VALUE_SQL, "operator does not exist: numeric * jsonb", CATALOG)
        self.assertTrue(hint.startswith("JSON COLUMNS IN THE FAILED SQL"))
        self.assertIn("product_product.standard_price: JSONB by company", hint)
        self.assertIn("product_template.name: JSONB by language", hint)
        self.assertIn("do not remove it", hint)

    def test_column_without_a_note_still_named(self):
        sql = "SELECT properties FROM res_partner WHERE properties = 'x'"
        hint = json_correction_hint(
            sql, "invalid input syntax for type json", CATALOG)
        self.assertIn("- res_partner.properties is JSONB\n", hint)

    def test_no_hint_for_other_errors(self):
        self.assertEqual(
            json_correction_hint(VALUE_SQL, 'column "x" does not exist', CATALOG), "")

    def test_no_hint_when_no_json_column_is_used(self):
        sql = "SELECT name FROM res_partner"
        self.assertEqual(json_correction_hint(
            sql, "invalid input syntax for type json", CATALOG), "")



class SchemaJsonNote(unittest.TestCase):
    """The short note json/jsonb columns get in the schema shown to the
    model (SchemaCatalog._json_note), from their discovered type."""

    @classmethod
    def setUpClass(cls):
        from tests.fixtures import NORTHWIND, make_catalog
        cls.catalog = make_catalog(exclude=set(NORTHWIND), extra_tables={
            "public.res_company": ["name", "settings", "notes", "label_json"]})
        columns = cls.catalog.tables["public.res_company"]["columns"]
        types = {"name": "character varying", "settings": "jsonb",
                 "notes": "json", "label_json": "jsonb"}
        for column in columns:
            column["type"] = types[column["name"]]
        next(c for c in columns if c["name"] == "label_json")["description"] = (
            "JSONB by language: use label_json->>'en_US'")
        cls.context = cls.catalog._format_context({"public.res_company"})

    def line(self, column):
        return next(l for l in self.context.splitlines()
                    if l.startswith(f"  - {column} ") or l.startswith(f'  - "{column}" '))

    def test_jsonb_and_json_columns_get_the_note(self):
        from sqlagent.adaptive.schema_catalog import JSON_NOTE
        self.assertIn(JSON_NOTE, self.line("settings"))
        self.assertIn(JSON_NOTE, self.line("notes"))

    def test_other_columns_do_not(self):
        self.assertNotIn("--", self.line("name"))

    def test_own_description_is_not_repeated(self):
        from sqlagent.adaptive.schema_catalog import JSON_NOTE
        line = self.line("label_json")
        self.assertIn("label_json->>'en_US'", line)
        self.assertNotIn(JSON_NOTE, line)

    def test_shipped_odoo_model_has_no_generic_notes(self):
        from pathlib import Path
        model = (Path(__file__).resolve().parent.parent / "config" / "databases"
                 / "odoo" / "semantic" / "model.yaml").read_text(encoding="utf-8")
        self.assertNotIn("JSONB, not a plain value", model)


if __name__ == "__main__":
    unittest.main()
