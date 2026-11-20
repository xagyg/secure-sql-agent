# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Tests for how rewritten SQL is laid out in the console log
# (repl.yaml sql_format, agent._pretty_sql). Display only.
#
#     python -m unittest tests.test_sql_format -v

import unittest
from unittest import mock

from pydantic import ValidationError

from sqlagent import agent
from sqlagent.settings import SqlFormat, get_settings

SQL = ("SELECT c.customer_id, c.company_name FROM customers AS c "
       "WHERE c.country = 'Germany' AND c.city = 'Berlin' LIMIT 100")


def pretty(sql=SQL, **fmt):
    settings = get_settings().model_copy(deep=True)
    settings.repl.sql_format = SqlFormat(**fmt)
    with mock.patch.object(agent, "get_settings", return_value=settings):
        return agent._pretty_sql(sql)


class SqlFormatTest(unittest.TestCase):

    def test_shipped_settings_use_four_space_indents(self):
        fmt = get_settings().repl.sql_format
        self.assertTrue(fmt.pretty)
        self.assertEqual((fmt.pad, fmt.indent), (4, 4))

    def test_default_layout(self):
        self.assertEqual(pretty(), (
            "SELECT\n"
            "    c.customer_id,\n"
            "    c.company_name\n"
            "FROM customers c\n"
            "WHERE c.country = 'Germany' AND c.city = 'Berlin'\n"
            "LIMIT 100"))

    def test_compact_layout(self):
        sql = ("SELECT EXTRACT(YEAR FROM o.order_date) AS order_year, "
               "SUM(od.quantity * od.unit_price * (1 - od.discount)) AS total_sales "
               "FROM orders o JOIN order_details od ON o.order_id = od.order_id "
               "GROUP BY EXTRACT(YEAR FROM o.order_date) HAVING COUNT(*) > 1 "
               "ORDER BY order_year")
        self.assertEqual(pretty(sql), (
            "SELECT\n"
            "    EXTRACT(YEAR FROM o.order_date) AS order_year,\n"
            "    SUM(od.quantity * od.unit_price * (1 - od.discount)) AS total_sales\n"
            "FROM orders o\n"
            "JOIN order_details od ON o.order_id = od.order_id\n"
            "GROUP BY EXTRACT(YEAR FROM o.order_date)\n"
            "HAVING COUNT(*) > 1\n"
            "ORDER BY order_year"))

    def test_compact_long_clause_keeps_sqlglot_layout(self):
        out = pretty(max_text_width=30)
        self.assertIn("\nWHERE\n    c.country = 'Germany'\n    AND c.city = 'Berlin'\n", out)

    def test_sqlglot_layout(self):
        self.assertEqual(pretty(layout="sqlglot"), (
            "SELECT\n"
            "    c.customer_id,\n"
            "    c.company_name\n"
            "FROM customers AS c\n"
            "WHERE\n"
            "    c.country = 'Germany' AND c.city = 'Berlin'\n"
            "LIMIT 100"))

    def test_sql_server_names_kept(self):
        settings = get_settings().model_copy(deep=True)
        with mock.patch.object(agent, "active_dialect", return_value="tsql"), \
                mock.patch.object(agent, "get_settings", return_value=settings):
            out = agent._pretty_sql("SELECT TOP 5 od.OrderID FROM dbo.[Order Details] od "
                                    "JOIN dbo.Orders o ON o.OrderID = od.OrderID")
        self.assertIn("FROM dbo.[Order Details] od\nJOIN dbo.Orders o ON o.OrderID = od.OrderID", out)
        self.assertIn("TOP 5", out)

    def test_options(self):
        out = pretty(pad=2, indent=2, leading_comma=True, max_text_width=30,
                     layout="sqlglot")
        self.assertIn("\n  c.customer_id\n  , c.company_name\n", out)
        self.assertIn("\n  c.country = 'Germany'\n  AND c.city = 'Berlin'\n", out)

    def test_pretty_off_leaves_sql_as_is(self):
        self.assertEqual(pretty(pretty=False), SQL)

    def test_unparseable_sql_left_as_is(self):
        self.assertEqual(pretty("SELECT FROM WHERE ("), "SELECT FROM WHERE (")

    def test_values_are_checked(self):
        with self.assertRaises(ValidationError):
            SqlFormat(indent=-1)
        with self.assertRaises(ValidationError):
            SqlFormat(max_text_width=5)
        with self.assertRaises(ValidationError):
            SqlFormat(colour=True)          # unknown key
        with self.assertRaises(ValidationError):
            SqlFormat(layout="fancy")


if __name__ == "__main__":
    unittest.main()
