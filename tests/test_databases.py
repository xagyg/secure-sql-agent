# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Database profiles (config/databases.yaml, sqlagent/databases.py).

import os
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

from sqlagent.config_files import CONFIG_DIR, PROJECT_ROOT
from sqlagent.databases import (
    DATABASES_FILE,
    DatabaseConfigError,
    load_database_profile,
)


TWO = """
version: 1
default: northwind
databases:
  northwind:
    connection: {database: northwind, user: sqlagent_ro}
    repl_roles: [sales]
    demo_roles: [demo]
  AdventureWorks:
    connection: {host: db.local, port: 6543, database: aw, user: aw_ro, password_env: AW_PASSWORD}
    semantic_path: elsewhere/aw
    repl_roles: [sales, purchasing]
    demo_roles: [demo]
"""


class Profiles(unittest.TestCase):

    def load(self, text, name=None, env=None):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder, "databases.yaml")
            path.write_text(textwrap.dedent(text), encoding="utf-8")
            with mock.patch.dict(os.environ, env or {}, clear=False):
                if env is None:
                    os.environ.pop("SQLAGENT_DATABASE", None)
                return load_database_profile(name, path)

    def test_default_is_used_when_nothing_is_selected(self):
        profile = self.load(TWO)
        self.assertEqual(profile.name, "northwind")
        self.assertEqual(profile.connection.host, "localhost")
        self.assertEqual(profile.connection.port, 5432)
        self.assertEqual(profile.security_file, CONFIG_DIR / "security" / "northwind.yaml")
        self.assertEqual(profile.semantic_path, CONFIG_DIR / "semantic" / "northwind")
        self.assertEqual(profile.repl_roles, {"sales"})

    def test_environment_selects_case_insensitively(self):
        profile = self.load(TWO, env={"SQLAGENT_DATABASE": "adventureworks"})
        self.assertEqual(profile.name, "adventureworks")
        self.assertEqual(profile.connection.database, "aw")
        self.assertEqual(profile.connection.port, 6543)
        self.assertEqual(profile.security_file, CONFIG_DIR / "security" / "adventureworks.yaml")
        self.assertEqual(profile.semantic_path, PROJECT_ROOT / "elsewhere" / "aw")
        self.assertEqual(profile.repl_roles, {"sales", "purchasing"})

    def test_password_comes_from_the_named_variable(self):
        profile = self.load(TWO, name="adventureworks")
        with mock.patch.dict(os.environ, {"AW_PASSWORD": "s3cret", "PG_PASSWORD": "other"}):
            self.assertEqual(profile.password(), "s3cret")

    def test_pg_variables_do_not_override_the_profile(self):
        profile = self.load(TWO, env={"SQLAGENT_DATABASE": "northwind",
                                      "PG_DATABASE": "aw", "PG_HOST": "elsewhere"})
        self.assertEqual(profile.connection.database, "northwind")
        self.assertEqual(profile.connection.host, "localhost")

    def test_unknown_name_fails_closed(self):
        with self.assertRaisesRegex(DatabaseConfigError, "no database named 'erp'"):
            self.load(TWO, name="erp")

    def test_default_must_exist(self):
        with self.assertRaisesRegex(DatabaseConfigError, "default 'erp'"):
            self.load(TWO.replace("default: northwind", "default: erp"))

    def test_unknown_key_fails(self):
        with self.assertRaisesRegex(DatabaseConfigError, "invalid configuration"):
            self.load(TWO.replace("demo_roles: [demo]\n  AdventureWorks",
                                  "demo_roles: [demo]\n    pasword: x\n  AdventureWorks"))

    def test_roles_are_required(self):
        with self.assertRaisesRegex(DatabaseConfigError, "repl_roles"):
            self.load(TWO.replace("    repl_roles: [sales]\n", "", 1))

    def test_missing_file_fails(self):
        with self.assertRaisesRegex(DatabaseConfigError, "not found"):
            load_database_profile(path="/no/such/databases.yaml")


class Shipped(unittest.TestCase):

    def test_every_shipped_database_has_a_security_file(self):
        profile = load_database_profile("northwind", DATABASES_FILE)
        self.assertTrue(profile.security_file.is_file())
        self.assertTrue(profile.semantic_path.is_dir())
        self.assertEqual(profile.demo_roles, {"demo"})
        self.assertEqual(profile.repl_roles, {"sales"})


if __name__ == "__main__":
    unittest.main()
