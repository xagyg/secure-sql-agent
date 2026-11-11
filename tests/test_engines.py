# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Database engines (sqlagent/execution/engines/). No database needed: the
# engines' SQL is exercised against a real server separately; these pin
# the text handling and the wiring.

import tempfile
import textwrap
import unittest
from pathlib import Path

from sqlagent.controls.security_utils import full_table_name
from sqlagent.databases import DatabaseConfigError, load_database_profile
from sqlagent.execution.engines import ENGINES, active_dialect, active_engine, get_engine


class Registry(unittest.TestCase):

    def test_postgres_is_registered(self):
        engine = get_engine("postgresql")
        self.assertEqual(engine.dialect, "postgres")
        self.assertEqual(engine.default_schema, "public")
        self.assertIn("postgresql", ENGINES)

    def test_unknown_engine(self):
        with self.assertRaisesRegex(ValueError, "unknown database engine"):
            get_engine("oracle")

    def test_shipped_databases_are_postgres(self):
        for name in ("northwind", "adventureworks"):
            self.assertEqual(load_database_profile(name).engine, "postgresql")
        self.assertEqual(active_engine().name, "postgresql")
        self.assertEqual(active_dialect(), "postgres")


class Profiles(unittest.TestCase):

    def load(self, extra):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder, "databases.yaml")
            path.write_text(textwrap.dedent(f"""
                version: 1
                default: x
                databases:
                  x:
                    {extra}
                    connection: {{database: x, user: u}}
                    repl_roles: [a]
                    demo_roles: [a]
            """), encoding="utf-8")
            return load_database_profile("x", path)

    def test_engine_defaults_to_postgres(self):
        profile = self.load("description: d")
        self.assertEqual(profile.engine, "postgresql")
        self.assertEqual(profile.default_schema, "public")

    def test_default_schema_can_be_set(self):
        self.assertEqual(self.load("default_schema: sales").default_schema, "sales")

    def test_unknown_engine_is_rejected(self):
        with self.assertRaisesRegex(DatabaseConfigError, "engine"):
            self.load("engine: oracle")

    def test_bare_table_uses_default_schema(self):
        self.assertEqual(full_table_name("customers"), "public.customers")
        self.assertEqual(full_table_name("customers", "erp"), "erp.customers")


class PostgresText(unittest.TestCase):

    engine = get_engine("postgresql")

    def test_missing_column_forms(self):
        cases = {
            'column "phone" does not exist': "phone",
            "column e.phone does not exist": "phone",
            'column e."Phone" does not exist': "Phone",
            'column "some.name" does not exist': "some.name",
            "relation \"x\" does not exist": None,
            "": None,
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(self.engine.missing_column(text), expected)

    def test_hint_line_is_never_the_column(self):
        text = 'syntax error\nHINT: column "phone" does not exist'
        self.assertIsNone(self.engine.missing_column(text))

    def test_sanitize_removes_detail_and_hint(self):
        text = ('column "x" does not exist\nLINE 1: SELECT x\n'
                'HINT:  Perhaps you meant to reference the column "c.secret_col".\n'
                'DETAIL: more')
        clean = self.engine.sanitize_error(text)
        self.assertNotIn("secret_col", clean)
        self.assertNotIn("DETAIL", clean)
        self.assertTrue(clean.startswith('column "x" does not exist'))

    def test_strip_row_limit(self):
        self.assertEqual(self.engine.strip_row_limit("SELECT a FROM t LIMIT 100", 100),
                         "SELECT a FROM t ")
        # Another limit is the user's own and stays.
        self.assertEqual(self.engine.strip_row_limit("SELECT a FROM t LIMIT 1000", 100),
                         "SELECT a FROM t LIMIT 1000")


if __name__ == "__main__":
    unittest.main()
