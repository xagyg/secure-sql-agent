# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Tests for the security policy (security_policy.py): wildcard expansion,
# deny rules, several roles, and failing closed on a bad file. No
# database or LLM needed.
#
#     python -m unittest tests.test_security_policy -v

import tempfile
import textwrap
import unittest
from pathlib import Path

from sqlagent.controls.security_policy import (
    DEFAULT_SECURITY_FILE,
    SecurityPolicy,
    SecurityPolicyError,
    load_security_policy,
)
from sqlagent.controls.security_utils import get_denied_columns, is_authorized_table
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


if __name__ == "__main__":
    unittest.main()
