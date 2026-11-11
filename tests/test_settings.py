# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Runtime settings (config/settings/*.yaml, sqlagent/settings.py) and the
# per-database identity in databases.yaml.

import os
import shutil
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

from sqlagent.config_files import load_yaml
from sqlagent.databases import DATABASES_FILE, DatabaseConfigError, load_database_profile
from sqlagent.settings import DEFAULT_SETTINGS_DIR, SettingsError, load_settings


class SettingsFolder:
    """A temporary copy of the shipped settings, with edits applied."""

    def __init__(self, **files):
        self.files = files

    def __enter__(self):
        self.tmp = tempfile.TemporaryDirectory()
        folder = Path(self.tmp.name)
        for path in DEFAULT_SETTINGS_DIR.glob("*.yaml"):
            shutil.copy(path, folder / path.name)
        for name, text in self.files.items():
            target = folder / f"{name}.yaml"
            if text is None:
                target.unlink()
            else:
                target.write_text(textwrap.dedent(text), encoding="utf-8")
        return folder

    def __exit__(self, *exc):
        self.tmp.cleanup()


class Shipped(unittest.TestCase):

    def test_shipped_settings_load(self):
        # The values come from the files, whatever they are set to: these
        # are meant to be tuned, so the test doesn't pin them.
        s = load_settings(environ={})
        raw = {name: load_yaml(DEFAULT_SETTINGS_DIR / f"{name}.yaml")
               for name in ("llm", "api", "query")}
        self.assertEqual(s.llm.model, raw["llm"]["model"])
        self.assertEqual(s.query.max_rows, raw["query"]["max_rows"])
        self.assertEqual(s.query.max_result_bytes, raw["query"]["max_result_bytes"])
        self.assertEqual(s.api.max_concurrency, raw["api"]["max_concurrency"])
        self.assertEqual(s.overridden, ())

    def test_shipped_values_match_previous_hard_coded_ones(self):
        r = load_settings(environ={}).retrieval.domains
        self.assertEqual((r.weights.what, r.weights.where, r.weights.who),
                         (0.45, 0.35, 0.20))
        self.assertEqual((r.sticky_bonus, r.min_domain_score, r.blend_margin),
                         (0.10, 0.25, 0.15))
        self.assertTrue(r.allow_who_tag)

    def test_databases_file_lives_in_settings(self):
        self.assertEqual(DATABASES_FILE.parent, DEFAULT_SETTINGS_DIR)
        self.assertTrue(DATABASES_FILE.is_file())


class Overrides(unittest.TestCase):

    def test_environment_beats_file(self):
        s = load_settings(environ={"OLLAMA_MODEL": "llama3",
                                   "DEMO_AGENT_TIMEOUT": "60",
                                   "DEMO_SESSION_RPM": "9"})
        self.assertEqual(s.llm.model, "llama3")
        self.assertEqual(s.api.agent_timeout, 60)
        self.assertEqual(s.api.rate_limits.session_per_minute, 9)
        self.assertEqual(set(s.overridden),
                         {"OLLAMA_MODEL", "DEMO_AGENT_TIMEOUT", "DEMO_SESSION_RPM"})

    def test_empty_variable_is_ignored(self):
        shipped = load_settings(environ={})
        s = load_settings(environ={"DEMO_ALLOWED_ORIGIN": "", "OLLAMA_MODEL": "  "})
        self.assertEqual(s.api.allowed_origins, shipped.api.allowed_origins)
        self.assertEqual(s.llm.model, shipped.llm.model)

    def test_origin_list_is_split(self):
        s = load_settings(environ={
            "DEMO_ALLOWED_ORIGIN": "https://a.example, https://b.example"})
        self.assertEqual(s.api.allowed_origins,
                         ["https://a.example", "https://b.example"])

    def test_bad_override_names_the_variable(self):
        with self.assertRaisesRegex(SettingsError, "DEMO_MAX_CONCURRENCY"):
            load_settings(environ={"DEMO_MAX_CONCURRENCY": "lots"})


class FailClosed(unittest.TestCase):

    def check(self, message, environ=None, **files):
        with SettingsFolder(**files) as folder:
            with self.assertRaisesRegex(SettingsError, message):
                load_settings(folder, environ=environ or {})

    def test_missing_file(self):
        self.check("not found", llm=None)

    def test_unknown_key(self):
        self.check("max_rowz", query="max_rowz: 10\n")

    def test_literal_password_rejected(self):
        self.check("never stored", llm="""
            model: m
            password: hunter2
        """)

    def test_nested_secret_rejected(self):
        self.check("never stored", api="rate_limits: {token: abc}\n")

    def test_authorization_header_rejected(self):
        self.check("secret", llm="""
            model: m
            headers: {Authorization: "Basic abc"}
        """)

    def test_wildcard_origin_rejected(self):
        self.check("wildcard", environ={"DEMO_ALLOWED_ORIGIN": "*"})

    def test_guardrail_bounds(self):
        self.check("max_rows", query="max_rows: 0\n")
        self.check("max_rows", query="max_rows: 10000000\n")

    def test_weights_must_add_up(self):
        self.check("add up to 1",
                   retrieval="domains: {weights: {what: 0.5, where: 0.5, who: 0.5}}\n")

    def test_table_match_order(self):
        self.check("full_name > partial_name",
                   retrieval="table_match: {full_name: 5, partial_name: 5}\n")

    def test_old_flat_layout_rejected(self):
        # A routing.yaml pasted in unchanged must not be half-applied.
        self.check("sticky_bonus", retrieval="sticky_bonus: 0.2\n")

    def test_statement_timeout_below_agent_timeout(self):
        self.check("statement_timeout_seconds",
                   environ={"PG_STATEMENT_TIMEOUT_SECONDS": "60",
                            "DEMO_AGENT_TIMEOUT": "30", "DEMO_MAX_SLOT_HOLD": "60"})

    def test_slot_hold_at_least_agent_timeout(self):
        self.check("max_slot_hold", environ={"DEMO_MAX_SLOT_HOLD": "10"})


class Secrets(unittest.TestCase):

    def test_llm_credentials_come_from_named_variables(self):
        s = load_settings(environ={})
        with mock.patch.dict(os.environ, {"OLLAMA_USERNAME": "u", "OLLAMA_PASSWORD": "p"}):
            self.assertEqual((s.llm.username(), s.llm.password()), ("u", "p"))

    def test_database_password_in_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder, "databases.yaml")
            path.write_text(textwrap.dedent("""
                version: 1
                default: x
                databases:
                  x:
                    connection: {database: x, user: u, password: hunter2}
                    repl_roles: [a]
                    demo_roles: [a]
            """), encoding="utf-8")
            with self.assertRaisesRegex(DatabaseConfigError, "never stored"):
                load_database_profile(path=path)

    def test_describe_says_where_the_password_comes_from(self):
        profile = load_database_profile("northwind")
        with mock.patch.dict(os.environ, {"PG_PASSWORD": "secret"}):
            text = profile.describe()
        self.assertIn("$PG_PASSWORD: set", text)
        self.assertNotIn("secret", text)


class Identity(unittest.TestCase):

    def test_shipped_identities(self):
        nw = load_database_profile("northwind")
        self.assertEqual(nw.display_name, "Northwind")
        self.assertIn("North Wind", nw.names)
        self.assertEqual(len(nw.example_questions), 3)
        aw = load_database_profile("adventureworks")
        self.assertEqual(aw.display_name, "AdventureWorks")
        self.assertTrue(aw.example_questions)

    def test_messages_follow_the_active_database(self):
        from sqlagent.controls import messages
        from sqlagent.controls.question_policy import is_overview_question
        aw = load_database_profile("adventureworks")
        with mock.patch.object(messages, "active_database", return_value=aw), \
             mock.patch("sqlagent.controls.question_policy.active_database",
                        return_value=aw):
            self.assertIn("AdventureWorks data", messages.off_topic_message())
            self.assertNotIn("Northwind", messages.overview_message(["Sales"]))
            self.assertNotIn("Germany", messages.no_query_message())
            self.assertTrue(is_overview_question("what does Adventure Works have?"))
            self.assertFalse(is_overview_question("what does Northwind have?"))

    def test_missing_identity_has_safe_defaults(self):
        from sqlagent.controls import messages
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder, "databases.yaml")
            path.write_text(textwrap.dedent("""
                version: 1
                default: erp
                databases:
                  erp:
                    connection: {database: erp, user: u}
                    repl_roles: [a]
                    demo_roles: [a]
            """), encoding="utf-8")
            profile = load_database_profile("erp", path)
        self.assertEqual(profile.names, ["erp"])
        with mock.patch.object(messages, "active_database", return_value=profile):
            self.assertEqual(messages.no_query_message(),
                             "I couldn't turn that into a database query, so "
                             "nothing was run. Try asking a question about the data.")
            self.assertTrue(messages.clarify_message(["Sales"]).endswith("about Sales."))


class IdentityFiles(unittest.TestCase):
    """config/<name>/identity.yaml, loaded with the database's profile."""

    DATABASES = """
        version: 1
        default: erp
        databases:
          erp:
            connection: {{database: erp, user: u}}
            {extra}
            repl_roles: [a]
            demo_roles: [a]
    """

    def load(self, identity=None, extra=""):
        """A profile for database "erp". With `identity`, its identity
        file is that text (via identity_file); without, there is none -
        config/erp/identity.yaml doesn't exist."""
        with tempfile.TemporaryDirectory() as folder:
            if identity is not None:
                target = Path(folder, "identity.yaml")
                target.write_text(textwrap.dedent(identity), encoding="utf-8")
                extra = f"identity_file: {target.as_posix()}"
            path = Path(folder, "databases.yaml")
            path.write_text(textwrap.dedent(self.DATABASES.format(extra=extra)),
                            encoding="utf-8")
            return load_database_profile("erp", path)

    def test_shipped_identity_files(self):
        for name in ("northwind", "adventureworks", "northwind_mssql"):
            profile = load_database_profile(name)
            self.assertEqual(profile.identity_file.name, "identity.yaml")
            self.assertEqual(profile.identity_file.parent.name, name)
            self.assertTrue(profile.identity_file.is_file())
            self.assertTrue(profile.sql_examples)

    def test_file_is_read(self):
        profile = self.load("""
            version: 1
            display_name: ERP
            names: [ERP, the ledger]
            sql_examples:
              - question: how many?
                sql: SELECT COUNT(*) FROM t
        """)
        self.assertEqual(profile.display_name, "ERP")
        self.assertEqual(profile.names, ["ERP", "the ledger"])
        self.assertEqual(profile.sql_examples[0].sql, "SELECT COUNT(*) FROM t")

    def test_missing_file_gives_defaults(self):
        profile = self.load()
        self.assertEqual((profile.display_name, profile.names), ("erp", ["erp"]))
        self.assertEqual(profile.sql_examples, [])
        self.assertIn("identity (none)", profile.describe())

    def test_invalid_file_stops_startup(self):
        with self.assertRaisesRegex(DatabaseConfigError, "display_nam"):
            self.load("display_nam: typo\n")
        with self.assertRaisesRegex(DatabaseConfigError, "sql"):
            self.load("sql_examples: [{question: q}]\n")

    def test_identity_block_in_databases_yaml_is_rejected(self):
        with self.assertRaisesRegex(DatabaseConfigError, "moved to config/<name>/identity.yaml"):
            self.load(extra="identity: {display_name: Old}")


if __name__ == "__main__":
    unittest.main()
