# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Tests for the security policy (security_policy.py): wildcard expansion,
# deny rules, several roles, and failing closed on a bad file. No
# database or LLM needed.
#
#     python -m unittest tests.test_security_policy -v

import contextlib
import io
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

from sqlagent.adaptive.schema_catalog import EmptyCatalogError, SchemaCatalog
from sqlagent.controls.security_context import SecurityContext

from sqlagent.controls.security_policy import (
    SecurityPolicy,
    SecurityPolicyError,
    load_security_policy,
)
from sqlagent.controls.security_utils import get_denied_columns, is_authorized_table
from tests.fixtures import NORTHWIND_SECURITY_FILE as DEFAULT_SECURITY_FILE
from tests.fixtures import NORTHWIND


NORTHWIND_TABLES = {f"public.{name}" for name in NORTHWIND}

ERP_TABLES = {
    "erp.emp_mst", "erp.emp_salary_hist", "erp.emp_leave",
    "erp.cust_mst", "semantic.employees_v",
}


def policy(text):
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder, "security.yaml")
        path.write_text(textwrap.dedent(text), encoding="utf-8")
        return load_security_policy(path)


ERP_POLICY = """
    version: 1
    default: deny
    roles:
      hr_analyst:
        allow: ["semantic.employees_v", "erp.emp_*"]
        deny:  ["erp.emp_salary_hist"]
        deny_columns:
          "erp.emp_*": [tax_file_no, bank_account]
      payroll:
        allow: ["erp.emp_*"]
        deny_columns:
          erp.emp_mst: [bank_account]
      sales:
        allow: [erp.cust_mst, erp.no_such_table]
    group_roles:
      HR-Team: [hr_analyst]
      Payroll: [payroll, hr_analyst]
"""


class ShippedPolicy(unittest.TestCase):

    def test_demo_role_matches_previous_hard_coded_context(self):
        context = load_security_policy(DEFAULT_SECURITY_FILE).build_context(
            "demo", {"demo"}, NORTHWIND_TABLES, log=False)
        self.assertEqual(context.tables, {
            "public.customers", "public.orders", "public.order_details",
            "public.products", "public.categories", "public.suppliers",
            "public.employees", "public.shippers",
        })
        self.assertEqual(context.denied_columns, {
            "public.customers": {"phone", "fax", "address"},
            "public.employees": {"home_phone"},
        })
        self.assertEqual(context.roles, {"demo"})

    def test_sales_role_matches_previous_main_py_context(self):
        context = load_security_policy(DEFAULT_SECURITY_FILE).build_context(
            "brad", {"Sales"}, NORTHWIND_TABLES, log=False)
        self.assertEqual(context.tables, NORTHWIND_TABLES)
        self.assertEqual(context.denied_columns, {
            "public.customers": {"phone"},
            "public.employees": {"home_phone"},
        })


class Resolution(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.policy = policy(ERP_POLICY)

    def test_wildcard_expands_and_deny_beats_allow(self):
        context = self.policy.build_context("u", {"hr_analyst"}, ERP_TABLES, log=False)
        self.assertEqual(context.tables, {
            "erp.emp_mst", "erp.emp_leave", "semantic.employees_v"})

    def test_wildcard_deny_columns(self):
        context = self.policy.build_context("u", {"hr_analyst"}, ERP_TABLES, log=False)
        self.assertEqual(get_denied_columns(context, "erp.emp_leave"),
                         {"tax_file_no", "bank_account"})
        self.assertEqual(get_denied_columns(context, "semantic.employees_v"), set())

    def test_query_time_check_is_the_resolved_list(self):
        # A table created after startup isn't granted until the policy is
        # resolved again, even though "erp.emp_*" would match it.
        context = self.policy.build_context("u", {"hr_analyst"}, ERP_TABLES, log=False)
        self.assertFalse(is_authorized_table(context, "erp.emp_new_table"))
        self.assertTrue(is_authorized_table(context, "ERP.Emp_Mst"))

    def test_several_roles_union_tables(self):
        context = self.policy.build_context(
            "u", {"hr_analyst", "payroll"}, ERP_TABLES, log=False)
        # payroll has no deny, so salary history is visible.
        self.assertIn("erp.emp_salary_hist", context.tables)

    def test_several_roles_column_hidden_only_if_every_role_hides_it(self):
        context = self.policy.build_context(
            "u", {"hr_analyst", "payroll"}, ERP_TABLES, log=False)
        # Both hide bank_account on emp_mst; only hr_analyst hides tax_file_no.
        self.assertEqual(get_denied_columns(context, "erp.emp_mst"), {"bank_account"})

    def test_missing_exact_table_is_skipped(self):
        context = self.policy.build_context("u", {"sales"}, ERP_TABLES, log=False)
        self.assertEqual(context.tables, {"erp.cust_mst"})

    def test_roles_for_groups(self):
        self.assertEqual(self.policy.roles_for_groups(["hr-team", "Everyone"]),
                         {"hr_analyst"})
        self.assertEqual(self.policy.roles_for_groups(["Payroll"]),
                         {"payroll", "hr_analyst"})
        self.assertEqual(self.policy.roles_for_groups([]), set())

    def test_no_roles_sees_nothing(self):
        context = self.policy.build_context("u", set(), ERP_TABLES, log=False)
        self.assertEqual(context.tables, set())


class FailClosed(unittest.TestCase):

    def assertRejected(self, text, message=None):
        with self.assertRaises(SecurityPolicyError) as ctx:
            policy(text)
        if message:
            self.assertIn(message, str(ctx.exception))

    def test_missing_file(self):
        with self.assertRaises(SecurityPolicyError):
            load_security_policy("/no/such/security.yaml")

    def test_default_must_be_stated(self):
        self.assertRejected("""
            roles: {demo: {allow: [public.orders]}}
        """, "default")

    def test_default_allow_is_rejected(self):
        self.assertRejected("""
            default: allow
            roles: {demo: {allow: [public.orders]}}
        """, "default")

    def test_unknown_key_is_rejected(self):
        self.assertRejected("""
            default: deny
            roles: {demo: {allow: [public.orders], deny_column: {}}}
        """, "deny_column")

    def test_duplicate_role_is_rejected(self):
        self.assertRejected("""
            default: deny
            roles:
              demo: {allow: [public.orders]}
              demo: {allow: ["*.*"]}
        """, "duplicate key")

    def test_deny_columns_typo_is_rejected(self):
        self.assertRejected("""
            default: deny
            roles:
              demo:
                allow: [public.employees]
                deny_columns:
                  public.employee: [home_phone]
        """, "typo")

    def test_group_mapped_to_unknown_role_is_rejected(self):
        self.assertRejected("""
            default: deny
            roles: {demo: {allow: [public.orders]}}
            group_roles: {Staff: [demo, staff]}
        """, "staff")

    def test_invalid_yaml_is_rejected(self):
        self.assertRejected("default: deny\nroles: [unclosed")

    def test_unknown_role_requested(self):
        loaded = policy(ERP_POLICY)
        with self.assertRaises(SecurityPolicyError):
            loaded.build_context("u", {"hr_analyst", "admin"}, ERP_TABLES, log=False)

    def test_from_dict(self):
        with self.assertRaises(SecurityPolicyError):
            SecurityPolicy.from_dict({"default": "deny"})


class EmptyCatalog(unittest.TestCase):
    """Startup stops when the role ends up with no tables (e.g. the
    database user was never granted SELECT on a newly loaded database)."""

    def refresh(self, security, tables):
        catalog = SchemaCatalog(connection_factory=None, security=security)
        with mock.patch.object(SchemaCatalog, "_load_tables", return_value=tables), \
             mock.patch.object(SchemaCatalog, "_load_foreign_keys", return_value=[]):
            catalog.refresh()
        return catalog

    def test_no_authorised_tables_stops_startup(self):
        security = SecurityContext(user_id="brad", roles={"sales"})
        with self.assertRaises(EmptyCatalogError) as ctx:
            self.refresh(security, {})
        self.assertIn("no tables are visible to user brad", str(ctx.exception))
        self.assertIn("SELECT", str(ctx.exception))

    def test_authorised_but_not_discovered_stops_startup(self):
        security = SecurityContext(user_id="brad", roles={"sales"},
                                   tables={"public.orders"})
        with self.assertRaises(EmptyCatalogError) as ctx:
            self.refresh(security, {})
        self.assertIn("sources.include", str(ctx.exception))

    def test_tables_present_loads(self):
        security = SecurityContext(user_id="brad", roles={"sales"},
                                   tables={"public.orders"})
        tables = {"public.orders": {"schema": "public", "name": "orders",
                                    "columns": [{"name": "order_id", "type": "int",
                                                 "nullable": False}]}}
        catalog = self.refresh(security, tables)
        self.assertEqual(set(catalog.tables), {"public.orders"})



INHERITING = """
    version: 1
    default: deny
    roles:
      hr_analyst:
        allow: ["semantic.employees_v", "erp.emp_*"]
        deny:  ["erp.emp_salary_hist"]
        deny_columns:
          "erp.emp_*": [tax_file_no, bank_account]
      hr_manager:
        extends: hr_analyst
        description: HR manager
        allow: [erp.cust_mst]
        deny_columns:
          erp.cust_mst: [phone]
      payroll_officer:
        extends: hr_analyst
        undeny: ["erp.emp_salary_hist"]
        undeny_columns:
          "erp.emp_*": [bank_account]
"""


class Inheritance(unittest.TestCase):
    """extends: a role starts as everything its parent has; only undeny /
    undeny_columns widen what the parent restricts."""

    def load(self, text=INHERITING, replace=None):
        for old, new in (replace or {}).items():
            self.assertIn(old, text)
            text = text.replace(old, new)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            pol = policy(text)
        return pol, out.getvalue()

    def test_child_inherits_and_adds(self):
        pol, _ = self.load()
        tables, denied = pol.resolve_role("hr_manager", ERP_TABLES)
        parent_tables, _ = pol.resolve_role("hr_analyst", ERP_TABLES)
        self.assertEqual(tables, parent_tables | {"erp.cust_mst"})
        self.assertNotIn("erp.emp_salary_hist", tables)          # parent's deny kept
        self.assertEqual(denied["erp.emp_mst"], {"tax_file_no", "bank_account"})
        self.assertEqual(denied["erp.cust_mst"], {"phone"})
        self.assertEqual(pol.roles["hr_manager"].description, "HR manager")

    def test_undeny_lifts_only_what_it_names_and_is_printed(self):
        pol, out = self.load()
        tables, denied = pol.resolve_role("payroll_officer", ERP_TABLES)
        self.assertIn("erp.emp_salary_hist", tables)
        self.assertEqual(denied["erp.emp_mst"], {"tax_file_no"})
        self.assertIn("WIDENS: payroll_officer undenies table erp.emp_salary_hist", out)
        self.assertIn("WIDENS: payroll_officer undenies column erp.emp_*.bank_account", out)
        self.assertIn("role hr_manager extends hr_analyst", out)

    def test_chain(self):
        pol, _ = self.load(INHERITING + """
      senior_payroll:
        extends: payroll_officer
        deny_columns:
          "erp.emp_*": [bank_account]
""")
        _, denied = pol.resolve_role("senior_payroll", ERP_TABLES)
        self.assertEqual(denied["erp.emp_mst"], {"tax_file_no", "bank_account"})  # hidden again

    def test_flattened_roles_behave_like_written_out_ones(self):
        pol, _ = self.load()
        written, _ = self.load(replace={
            "      hr_manager:\n        extends: hr_analyst\n":
            "      hr_manager:\n",
            "        allow: [erp.cust_mst]\n":
            "        allow: [\"semantic.employees_v\", \"erp.emp_*\", erp.cust_mst]\n"
            "        deny:  [\"erp.emp_salary_hist\"]\n",
            "          erp.cust_mst: [phone]\n":
            "          erp.cust_mst: [phone]\n          \"erp.emp_*\": [tax_file_no, bank_account]\n",
        })
        self.assertEqual(pol.resolve_role("hr_manager", ERP_TABLES),
                         written.resolve_role("hr_manager", ERP_TABLES))

    def check(self, replace, message):
        with self.assertRaisesRegex(SecurityPolicyError, message):
            self.load(replace=replace)

    def test_unknown_parent(self):
        self.check({"extends: hr_analyst\n        description": "extends: hr_anlyst\n        description"},
                   "undefined role 'hr_anlyst'")

    def test_cycle(self):
        self.check({"      hr_analyst:\n": "      hr_analyst:\n        extends: payroll_officer\n"},
                   "cycle")

    def test_undeny_must_name_a_parent_deny(self):
        self.check({'undeny: ["erp.emp_salary_hist"]': 'undeny: ["erp.emp_leave"]'},
                   "doesn't deny")

    def test_undeny_column_must_be_hidden_by_parent(self):
        self.check({"undeny_columns:\n          \"erp.emp_*\": [bank_account]":
                    "undeny_columns:\n          \"erp.emp_*\": [salary]"},
                   "doesn't hide")

    def test_undeny_columns_must_name_the_parents_table_key(self):
        self.check({"undeny_columns:\n          \"erp.emp_*\"": "undeny_columns:\n          erp.emp_mst"},
                   "hides none")

    def test_undeny_without_extends(self):
        self.check({"        extends: hr_analyst\n        undeny": "        undeny"}, "need extends")

    def test_scope_required_cannot_be_dropped(self):
        self.check({"      hr_analyst:\n": "      hr_analyst:\n        scope: required\n"},
                   "must say scope: required too")

    def test_deny_columns_typo_still_caught(self):
        self.check({"          erp.cust_mst: [phone]": "          erp.cust_mstt: [phone]"},
                   "doesn't grant")

    def test_shipped_sales_manager_extends_sales(self):
        from sqlagent.config_files import CONFIG_DIR
        for db in ("northwind", "northwind_mssql"):
            with contextlib.redirect_stdout(io.StringIO()):
                pol = load_security_policy(CONFIG_DIR / "databases" / db / "security.yaml")
            self.assertEqual(pol.roles["sales_manager"].extends, "sales")
            self.assertEqual(pol.roles["sales_manager"].scope, "required")
            self.assertEqual(pol.roles["sales"].scope, None)
            tables = NORTHWIND_TABLES if db == "northwind" else None
            if tables:
                self.assertEqual(pol.resolve_role("sales_manager", tables),
                                 pol.resolve_role("sales", tables))

if __name__ == "__main__":
    unittest.main()
