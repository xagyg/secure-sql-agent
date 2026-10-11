# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Tests for sql_policy.prepare_sql(): the parse-once preparation of
# model-generated SQL. No database or LLM needed.
#
#     python -m unittest tests.test_sql_policy -v

import unittest
from unittest import mock

from sqlagent.controls import sql_policy
from sqlagent.controls.security_context import SecurityContext
from sqlagent.controls.sql_policy import MAX_ROWS, prepare_sql
from tests.fixtures import make_catalog


class PrepareSql(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.catalog = make_catalog(exclude={"territories"})
        cls.security = SecurityContext(
            user_id="test",
            roles={"demo"},
            tables=set(cls.catalog.tables),
            denied_columns={"public.customers": {"phone", "fax", "address"}},
        )

    def prepare(self, sql):
        return prepare_sql(sql, self.security, self.catalog)

    def test_select_star_expanded_without_restricted_columns(self):
        p = self.prepare("SELECT * FROM customers")
        self.assertIsNone(p.failure_reason)
        self.assertTrue(p.rewritten)
        self.assertIn("customers.company_name", p.sql)
        self.assertNotIn("fax", p.sql)
        self.assertNotIn("address", p.sql)
        self.assertIn(f"LIMIT {MAX_ROWS}", p.sql)

    def test_restricted_column_stripped_from_select_list(self):
        p = self.prepare("SELECT company_name, fax FROM customers")
        self.assertIsNone(p.failure_reason)
        self.assertEqual(p.withheld, ["fax"])
        self.assertEqual(p.stripped_sql, "SELECT company_name FROM customers")
        self.assertNotIn("fax", p.sql)

    def test_restricted_column_elsewhere_blocked(self):
        p = self.prepare("SELECT company_name FROM customers WHERE fax LIKE '0%'")
        self.assertIn("not authorised", p.failure_reason)

    def test_only_restricted_column_blocked(self):
        p = self.prepare("SELECT fax FROM customers")
        self.assertEqual(p.withheld, [])
        self.assertIn("not authorised", p.failure_reason)

    def test_existing_limit_kept(self):
        p = self.prepare("SELECT company_name FROM customers LIMIT 5")
        self.assertTrue(p.sql.endswith("LIMIT 5"))

    def test_union_run_as_written(self):
        sql = "SELECT company_name FROM suppliers UNION SELECT company_name FROM customers"
        p = self.prepare(sql)
        self.assertIsNone(p.failure_reason)
        self.assertEqual(p.sql, sql)
        self.assertFalse(p.rewritten)

    def test_unauthorised_table(self):
        self.assertIn("not authorised", self.prepare("SELECT * FROM territories").failure_reason)

    def test_write_and_multiple_statements(self):
        self.assertIn("read-only", self.prepare("DELETE FROM customers").failure_reason)
        self.assertIn("Exactly one", self.prepare("SELECT 1; SELECT 2").failure_reason)

    def test_unparseable(self):
        self.assertIn("could not be parsed", self.prepare("SELECT FROM WHERE (").failure_reason)

    def test_parsed_once_plus_final_check(self):
        # One parse to transform, one to check the exact final text.
        real = sql_policy.sqlglot.parse
        with mock.patch.object(sql_policy.sqlglot, "parse", side_effect=real) as parse:
            p = self.prepare("SELECT company_name, fax FROM customers")
        self.assertIsNone(p.failure_reason)
        self.assertEqual(parse.call_count, 2)


if __name__ == "__main__":
    unittest.main()
