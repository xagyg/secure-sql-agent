# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Database profiles (config/settings/databases.yaml, sqlagent/databases.py).

import os
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

from sqlagent.config_files import PROJECT_ROOT
from sqlagent.databases import (
    DATABASES_DIR,
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
        self.assertEqual(profile.security_file, DATABASES_DIR / "northwind" / "security.yaml")
        self.assertEqual(profile.semantic_path, DATABASES_DIR / "northwind" / "semantic")
        self.assertEqual(profile.repl_roles, {"sales"})

    def test_environment_selects_case_insensitively(self):
        profile = self.load(TWO, env={"SQLAGENT_DATABASE": "adventureworks"})
        self.assertEqual(profile.name, "adventureworks")
        self.assertEqual(profile.connection.database, "aw")
        self.assertEqual(profile.connection.port, 6543)
        self.assertEqual(profile.security_file, DATABASES_DIR / "adventureworks" / "security.yaml")
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


class OldLayout(unittest.TestCase):
    """Database folders moved from config/<name>/ to config/databases/<name>/."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.config = Path(self.tmp.name)
        patches = [
            mock.patch("sqlagent.databases.CONFIG_DIR", self.config),
            mock.patch("sqlagent.databases.DATABASES_DIR", self.config / "databases"),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(self.tmp.cleanup)

    def load(self):
        from sqlagent import databases
        spec = databases.DatabasesFile.model_validate(
            {"default": "legacy", "databases": {"legacy": {
                "connection": {"database": "legacy", "user": "u"},
                "repl_roles": ["a"], "demo_roles": ["a"]}}}).databases["legacy"]
        return databases.DatabaseProfile("legacy", spec, self.config / "databases")

    def test_folder_left_in_old_place_is_explained(self):
        (self.config / "legacy").mkdir()
        (self.config / "legacy" / "security.yaml").write_text("version: 1\n")
        with self.assertRaisesRegex(DatabaseConfigError, "have moved from .* to "):
            self.load()

    def test_new_place_wins(self):
        for folder in (self.config / "legacy", self.config / "databases" / "legacy"):
            folder.mkdir(parents=True)
            (folder / "security.yaml").write_text("version: 1\n")
        profile = self.load()
        self.assertEqual(profile.security_file,
                         self.config / "databases" / "legacy" / "security.yaml")


class LocalIdentities(unittest.TestCase):
    """DEMO ONLY: config/idp/<idp>.yaml, one file per organisation."""

    def load(self, extra="", security_dir=None):
        text = TWO.replace("    repl_roles: [sales]\n    demo_roles: [demo]\n  AdventureWorks",
                           f"    repl_roles: [sales]\n    demo_roles: [demo]\n{extra}  AdventureWorks")
        if security_dir is not None:
            text = text.replace("  northwind:\n", f"  northwind:\n    security_file: {security_dir.as_posix()}/security.yaml\n")
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder, "databases.yaml")
            path.write_text(textwrap.dedent(text), encoding="utf-8")
            return load_database_profile("northwind", path)

    def test_default_is_the_database_name(self):
        from sqlagent.databases import IDP_DIR
        from sqlagent.identities import identities_file
        profile = self.load()
        self.assertEqual(profile.idp, "northwind")
        self.assertEqual(identities_file(profile), IDP_DIR / "northwind.yaml")

    def test_idp_names_another_organisation(self):
        from sqlagent.databases import IDP_DIR
        profile = self.load("    idp: Contoso\n")
        self.assertEqual(profile.idp_file, IDP_DIR / "contoso.yaml")

    def test_idp_is_a_name_not_a_path(self):
        for bad in ("../secrets", "a/b", "x.yaml", "''"):
            with self.subTest(idp=bad), self.assertRaisesRegex(DatabaseConfigError, "idp"):
                self.load(f"    idp: {bad}\n")

    def test_old_identities_file_stops_startup(self):
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / "identities.yaml").write_text("version: 1\n")
            with self.assertRaisesRegex(DatabaseConfigError, "have moved to .*idp"):
                self.load(security_dir=Path(folder))
            (Path(folder) / "identities.yaml").unlink()
            self.load(security_dir=Path(folder))

    def test_shipped_groups_are_known_to_the_policy(self):
        # A misspelt group is silently ignored at sign-in (most of a user's
        # groups have nothing to do with this application), so check the
        # shipped files here. "contractor" is deliberately in no group.
        import contextlib, io
        from sqlagent.controls.security_policy import load_security_policy
        from sqlagent.identities import identities_file, load_identities
        for db in ("northwind", "northwind_mssql", "adventureworks"):
            profile = load_database_profile(db)
            with contextlib.redirect_stdout(io.StringIO()):
                policy = load_security_policy(profile.security_file)
            known = set(policy.group_roles) | set(policy.group_grants)
            for name, ident in load_identities(identities_file(profile)).items():
                if name == "contractor":
                    continue
                with self.subTest(db=db, identity=name):
                    groups = {g.lower() for g in ident.groups}
                    self.assertTrue(groups, "no groups")
                    self.assertLessEqual(groups, known)

    def test_both_northwinds_share_one_file(self):
        from sqlagent.identities import identities_file, load_identities
        files = {identities_file(load_database_profile(n)) for n in ("northwind", "northwind_mssql")}
        self.assertEqual(len(files), 1)
        people = load_identities(files.pop())
        self.assertEqual(people["steven"].attributes, {"employee_id": 5})


class Shipped(unittest.TestCase):

    def test_every_shipped_database_has_a_security_file(self):
        profile = load_database_profile("northwind", DATABASES_FILE)
        self.assertTrue(profile.security_file.is_file())
        self.assertTrue(profile.semantic_path.is_dir())
        self.assertEqual(profile.demo_roles, {"demo"})
        self.assertEqual(profile.repl_roles, {"sales"})


if __name__ == "__main__":
    unittest.main()
