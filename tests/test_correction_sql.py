# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Tests for which SQL the correction prompt is shown (agent._sql_for_correction):
# the prepared SQL, unless that is too long (SELECT * expanded to every
# column), when the model's own SQL is used. No database or LLM needed.
#
#     python -m unittest tests.test_correction_sql -v

import contextlib
import io
import unittest
from unittest import mock

from sqlagent import agent
from tests.fixtures import make_catalog


class SqlForCorrection(unittest.TestCase):

    def pick(self, sql, generated, limit=100):
        with mock.patch.object(agent, "CORRECTION_SQL_CHARS", limit), \
             contextlib.redirect_stdout(io.StringIO()) as out:
            return agent._sql_for_correction(sql, generated), out.getvalue()

    def test_prepared_sql_is_used_when_short(self):
        chosen, out = self.pick("SELECT a FROM t LIMIT 100", "SELECT a FROM t")
        self.assertEqual(chosen, "SELECT a FROM t LIMIT 100")
        self.assertEqual(out, "")

    def test_model_sql_is_used_when_prepared_is_long(self):
        long_sql = "SELECT " + ", ".join(f"t.c{i}" for i in range(50)) + " FROM t"
        chosen, out = self.pick(long_sql, "SELECT * FROM t")
        self.assertEqual(chosen, "SELECT * FROM t")
        self.assertIn("showing the model its own SQL", out)

    def test_long_model_sql_is_kept(self):
        long_sql = "SELECT " + ", ".join(f"c{i}" for i in range(50)) + " FROM t"
        chosen, _ = self.pick(long_sql, long_sql)
        self.assertEqual(chosen, long_sql)

    def test_shipped_limit(self):
        self.assertEqual(agent.CORRECTION_SQL_CHARS, 4000)


class CorrectionPrompt(unittest.TestCase):
    """End to end: a SELECT * that expands past the limit and then fails
    is corrected from the model's own SQL."""

    def test_correction_sees_the_short_sql(self):
        catalog = make_catalog()
        security = mock.MagicMock(row_filters={}, denied_columns={},
                                  tables=set(catalog.tables), roles={"demo"})
        long_sql = "SELECT " + ", ".join(f"customers.c{i}" for i in range(400)) + \
                   " FROM customers LIMIT 100"
        with mock.patch.object(agent, "generate_sql", return_value="SELECT * FROM customers"), \
             mock.patch.object(agent, "_prepare_sql", return_value=(long_sql, [], None)), \
             mock.patch.object(agent, "_execute", side_effect=RuntimeError("boom")), \
             mock.patch.object(agent, "diagnose_sql_error", return_value=None), \
             mock.patch.object(agent, "json_correction_hint", return_value=""), \
             mock.patch.object(agent, "correct_sql",
                               return_value="SELECT * FROM customers") as correct, \
             contextlib.redirect_stdout(io.StringIO()):
            agent.run_agent("show me all customers", catalog, [], security)
        self.assertEqual(correct.call_args[0][2], "SELECT * FROM customers")


if __name__ == "__main__":
    unittest.main()
