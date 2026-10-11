# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Tests for the result-level security policy (result_policy.py) and the
# follow-up restricted-column check (question_policy.py). No
# database or LLM needed: column sources are given as execute_sql_with_sources()
# would report them.
#
#     python -m unittest tests.test_result_policy -v

import unittest

from sqlagent.controls.question_policy import follow_up_asks_restricted
from sqlagent.controls.result_policy import apply_result_policy
from sqlagent.controls.security_context import SecurityContext
from tests.fixtures import make_catalog


SECURITY = SecurityContext(
    user_id="test",
    roles={"demo"},
    tables={"public.customers", "public.suppliers", "public.shippers"},
    denied_columns={"public.customers": {"phone", "fax", "address"}},
)


class ResultPolicyTests(unittest.TestCase):

    def test_supplier_phone_is_kept(self):
        # The Tokyo Traders bug: customers.phone is denied, but that must
        # not remove suppliers.phone.
        rows = [{"phone": "(03) 3555-5011"}]
        sources = {"phone": [("public.suppliers", "phone")]}
        out, removed = apply_result_policy(rows, SECURITY, sources)
        self.assertEqual(out, rows)
        self.assertEqual(removed, [])

    def test_customer_phone_is_removed(self):
        rows = [{"company_name": "Ernst Handel", "phone": "7675-3425"}]
        sources = {"company_name": [("public.customers", "company_name")],
                   "phone": [("public.customers", "phone")]}
        out, removed = apply_result_policy(rows, SECURITY, sources)
        self.assertEqual(out, [{"company_name": "Ernst Handel"}])
        self.assertEqual(removed, ["phone"])

    def test_alias_is_traced_to_source(self):
        rows = [{"tel": "7675-3425"}]
        sources = {"tel": [("public.customers", "phone")]}
        out, removed = apply_result_policy(rows, SECURITY, sources)
        self.assertEqual(out, [{}])
        self.assertEqual(removed, ["tel"])

    def test_duplicate_name_with_one_denied_source_is_removed(self):
        rows = [{"phone": "?"}]
        sources = {"phone": [("public.suppliers", "phone"),
                             ("public.customers", "phone")]}
        _, removed = apply_result_policy(rows, SECURITY, sources)
        self.assertEqual(removed, ["phone"])

    def test_unauthorised_table_is_removed(self):
        rows = [{"secret": "x"}]
        sources = {"secret": [("public.payroll", "salary")]}
        _, removed = apply_result_policy(rows, SECURITY, sources)
        self.assertEqual(removed, ["secret"])

    def test_computed_column_with_denied_name_fails_closed(self):
        # UNION results and expressions have no source table.
        rows = [{"phone": "x", "total": 3}]
        sources = {"phone": [None], "total": [None]}
        out, removed = apply_result_policy(rows, SECURITY, sources)
        self.assertEqual(out, [{"total": 3}])
        self.assertEqual(removed, ["phone"])

    def test_no_sources_uses_name_rule(self):
        out, removed = apply_result_policy(
            [{"phone": "x", "city": "y"}], SECURITY, None)
        self.assertEqual(out, [{"city": "y"}])
        self.assertEqual(removed, ["phone"])

    def test_empty_rows(self):
        self.assertEqual(apply_result_policy([], SECURITY, {}), ([], []))


class FollowUpRestricted(unittest.TestCase):
    """The pre-check for follow-ups (see run_agent). The catalog is the
    static Northwind copy, which already omits customers.phone and
    employees.home_phone, as the demo role's catalog does."""

    CUSTOMERS = {"public.customers"}

    @classmethod
    def setUpClass(cls):
        cls.catalog = make_catalog()

    def asks(self, question, tables=None):
        return follow_up_asks_restricted(
            question, SECURITY, self.catalog, tables or self.CUSTOMERS)

    def test_restricted_on_conversation_table(self):
        self.assertTrue(self.asks("What is Thomas's address?"))
        self.assertTrue(self.asks("What is Thomas's phone number?"))
        self.assertTrue(self.asks("and their fax?"))

    def test_more_specific_allowed_column(self):
        # orders.ship_address is allowed.
        self.assertFalse(self.asks("what's their ship address?"))

    def test_allowed_column(self):
        self.assertFalse(self.asks("What is Thomas's job title?"))
        self.assertFalse(self.asks("Which city is Thomas in?"))

    def test_other_table_not_restricted(self):
        # suppliers.address is allowed: a suppliers conversation is fine.
        self.assertFalse(self.asks("What is their address?",
                                   tables={"public.suppliers"}))


if __name__ == "__main__":
    unittest.main()
