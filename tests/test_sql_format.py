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
            "FROM customers AS c\n"
            "WHERE\n"
            "    c.country = 'Germany' AND c.city = 'Berlin'\n"
            "LIMIT 100"))

    def test_options(self):
        out = pretty(pad=2, indent=2, leading_comma=True, max_text_width=30)
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


if __name__ == "__main__":
    unittest.main()
