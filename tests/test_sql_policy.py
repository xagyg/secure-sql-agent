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

    def test_union_gets_row_limit(self):
        sql = "SELECT company_name FROM suppliers UNION SELECT company_name FROM customers"
        p = self.prepare(sql)
        self.assertIsNone(p.failure_reason)
        self.assertEqual(p.sql, f"{sql} LIMIT {MAX_ROWS}")
        self.assertTrue(p.rewritten)

    def test_union_star_expanded_in_every_branch(self):
        # Unexpanded, SELECT * in a UNION returned restricted columns and
        # only the result policy's name rule removed them.
        p = self.prepare("SELECT * FROM customers UNION ALL SELECT c.* FROM customers c")
        self.assertIsNone(p.failure_reason)
        self.assertNotIn("*", p.sql)
        for column in ("fax", "address"):
            self.assertNotIn(column, p.sql)
        self.assertIn("customers.company_name", p.sql)
        self.assertIn("c.company_name", p.sql)
        self.assertTrue(p.sql.endswith(f"LIMIT {MAX_ROWS}"))

    def test_union_restricted_column_still_blocked(self):
        # Not stripped from one branch (that would misalign the UNION).
        p = self.prepare("SELECT company_name, fax FROM customers "
                         "UNION SELECT company_name, fax FROM suppliers")
        self.assertEqual(p.withheld, [])
        self.assertIn("not authorised", p.failure_reason)

    def test_column_named_like_a_joined_table_is_a_column(self):
        # customers.region beside the region table: a column, not a
        # whole-row reference to region.
        p = self.prepare("SELECT region, region_description FROM customers, region")
        self.assertIsNone(p.failure_reason)

    def test_whole_row_reference_still_blocked(self):
        p = self.prepare("SELECT c FROM customers c")
        self.assertIn("Whole-row", p.failure_reason)

    def test_unauthorised_table(self):
        reason = self.prepare("SELECT * FROM territories").failure_reason
        self.assertIn("not authorised", reason)
        self.assertEqual(reason.code, sql_policy.TABLE_NOT_AUTHORISED)
        self.assertEqual(reason.table, "public.territories")

    def test_restricted_column_reason_code(self):
        reason = self.prepare("SELECT company_name FROM customers WHERE fax = '1'").failure_reason
        self.assertEqual(reason.code, sql_policy.COLUMN_NOT_AUTHORISED)

    def test_write_and_multiple_statements(self):
        reason = self.prepare("DELETE FROM customers").failure_reason
        self.assertIn("read-only", reason)
        self.assertEqual(reason.code, sql_policy.READ_ONLY)
        reason = self.prepare("SELECT 1; SELECT 2").failure_reason
        self.assertIn("Exactly one", reason)
        self.assertEqual(reason.code, sql_policy.SINGLE_STATEMENT)

    def test_unparseable(self):
        reason = self.prepare("SELECT FROM WHERE (").failure_reason
        self.assertIn("could not be parsed", reason)
        self.assertEqual(reason.code, sql_policy.UNPARSEABLE)

    def test_parsed_once_plus_final_check(self):
        # One parse to transform, one to check the exact final text.
        real = sql_policy.sqlglot.parse
        with mock.patch.object(sql_policy.sqlglot, "parse", side_effect=real) as parse:
            p = self.prepare("SELECT company_name, fax FROM customers")
        self.assertIsNone(p.failure_reason)
        self.assertEqual(parse.call_count, 2)



class RowLimit(unittest.TestCase):
    """A limit above max_rows is lowered to it; a smaller one is kept."""

    def limited(self, sql, dialect="postgres"):
        import sqlglot
        tree = sqlglot.parse_one(sql, read=dialect)
        sql_policy.apply_query_limits_tree(tree)
        return tree.sql(dialect=dialect)

    def test_no_limit_gets_max_rows(self):
        self.assertIn(f"LIMIT {MAX_ROWS}", self.limited("SELECT a FROM t"))

    def test_larger_limit_is_lowered(self):
        sql = self.limited(f"SELECT a FROM t LIMIT {MAX_ROWS * 10}")
        self.assertIn(f"LIMIT {MAX_ROWS}", sql)
        self.assertNotIn(str(MAX_ROWS * 10), sql)

    def test_smaller_limit_is_kept(self):
        self.assertIn("LIMIT 10", self.limited("SELECT a FROM t LIMIT 10"))

    def test_offset_is_kept(self):
        sql = self.limited(f"SELECT a FROM t LIMIT {MAX_ROWS * 10} OFFSET 5")
        self.assertIn(f"LIMIT {MAX_ROWS}", sql)
        self.assertIn("OFFSET 5", sql)

    def test_sql_server_top_and_fetch(self):
        top = self.limited(f"SELECT TOP {MAX_ROWS * 10} a FROM t", "tsql")
        self.assertIn(f"TOP {MAX_ROWS}", top)
        fetch = self.limited(f"SELECT a FROM t ORDER BY a OFFSET 0 ROWS "
                             f"FETCH NEXT {MAX_ROWS * 10} ROWS ONLY", "tsql")
        self.assertIn(f"FETCH NEXT {MAX_ROWS} ROWS ONLY", fetch)


class SelectStarSources(unittest.TestCase):
    """SELECT * expands to the columns of the tables the SELECT reads
    directly (FROM and JOINs), never those of tables in its subqueries."""

    @classmethod
    def setUpClass(cls):
        cls.catalog = make_catalog(exclude={"territories"})
        cls.security = SecurityContext(
            user_id="test", roles={"demo"}, tables=set(cls.catalog.tables),
            denied_columns={"public.customers": {"phone", "fax", "address"}},
        )

    def prepare(self, sql):
        return prepare_sql(sql, self.security, self.catalog)

    def select_list(self, sql):
        return sql.split(" FROM ", 1)[0]

    def test_exists_subquery_tables_are_not_expanded(self):
        # The bug: o.order_id, o.freight ... were added to the outer
        # SELECT list, and the query failed ("missing FROM-clause entry").
        p = self.prepare("SELECT * FROM customers c WHERE EXISTS "
                         "(SELECT 1 FROM orders o WHERE o.customer_id = c.customer_id)")
        self.assertIsNone(p.failure_reason)
        self.assertIn("c.company_name", self.select_list(p.sql))
        self.assertNotIn("o.", self.select_list(p.sql))

    def test_not_exists_with_a_join_inside(self):
        p = self.prepare(
            "SELECT * FROM customers WHERE NOT EXISTS (SELECT 1 FROM orders o "
            "JOIN employees e ON e.employee_id = o.employee_id "
            "WHERE o.customer_id = customers.customer_id)")
        listed = self.select_list(p.sql)
        self.assertIn("customers.company_name", listed)
        self.assertNotIn("o.", listed)
        self.assertNotIn("e.", listed)

    def test_joined_tables_are_still_expanded(self):
        p = self.prepare("SELECT * FROM customers c JOIN orders o "
                         "ON o.customer_id = c.customer_id")
        listed = self.select_list(p.sql)
        self.assertIn("c.company_name", listed)
        self.assertIn("o.order_id", listed)
        self.assertNotIn("fax", listed)

    def test_alias_star_beside_a_scalar_subquery(self):
        p = self.prepare("SELECT c.*, (SELECT COUNT(*) FROM orders o "
                         "WHERE o.customer_id = c.customer_id) AS n FROM customers c")
        self.assertIsNone(p.failure_reason)
        self.assertIn("c.company_name", p.sql)
        self.assertNotIn("o.order_id", p.sql)

    def test_star_over_a_derived_table_is_refused(self):
        # Left unexpanded, this would return the restricted columns.
        for sql in ("SELECT * FROM (SELECT * FROM customers) t",
                    "SELECT * FROM (SELECT company_name FROM customers) t"):
            with self.subTest(sql=sql), \
                    self.assertRaisesRegex(ValueError, "subquery or derived table"):
                self.prepare(sql)

    def test_alias_star_for_a_subquery_table_is_refused(self):
        with self.assertRaisesRegex(ValueError, "Unable to determine table for 'o.\\*'"):
            self.prepare("SELECT o.* FROM customers c WHERE EXISTS (SELECT 1 FROM orders o)")


if __name__ == "__main__":
    unittest.main()
