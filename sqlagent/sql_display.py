# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# SQL laid out for the console log (repl.yaml sql_format). Display only:
# the SQL that runs, the history and the prompts keep the compact text.
#
# layout "sqlglot" is sqlglot's own pretty printer. layout "compact" is the
# same printer with a few rules closer to hand-written SQL:
#
#     SELECT                                SELECT
#         o.order_id,                           o.order_id,
#         SUM(x * (                             SUM(x * (1 - d)) AS total
#             1 - d                         FROM orders o
#         )) AS total                       JOIN order_details od ON o.order_id = od.order_id
#     FROM orders AS o                      GROUP BY o.order_id
#     JOIN order_details AS od              ORDER BY total
#         ON o.order_id = od.order_id
#     GROUP BY
#         o.order_id
#     ORDER BY
#         total
#
#   - a parenthesised expression that fits on one line stays on it;
#   - table aliases without AS;
#   - JOIN ... ON on one line;
#   - WHERE, HAVING, GROUP BY and ORDER BY on the keyword's line when the
#     clause fits in max_text_width (otherwise as sqlglot lays it out).
#
# The rules are overrides of sqlglot's Generator methods, on a subclass of
# the dialect's own generator, so dialect-specific rendering (TOP, [names])
# is unchanged.

from functools import lru_cache

import sqlglot
from sqlglot.dialects.dialect import Dialect


class _CompactLayout:
    """Generator overrides for layout "compact" (see the module comment)."""

    _in_join = 0

    def _fits(self, text, prefix=""):
        return "\n" not in text and len(prefix) + len(text) <= self.max_text_width

    def paren_sql(self, expression):
        inner = self.sql(expression, "this")
        if self._fits(inner):
            return f"({inner})"
        return super().paren_sql(expression)

    def table_sql(self, expression, sep=" AS "):
        return super().table_sql(expression, sep=" " if sep == " AS " else sep)

    def join_sql(self, expression):
        self._in_join += 1
        try:
            return super().join_sql(expression)
        finally:
            self._in_join -= 1

    def seg(self, sql, sep=" "):
        # sqlglot puts ON on its own line with seg(" " * pad); only
        # join_sql calls seg with that argument.
        if self._in_join and sql == " " * self.pad:
            return " "
        return super().seg(sql, sep)

    def _clause(self, keyword, expression, default):
        this = self.sql(expression, "this")
        if self._fits(this, keyword + " "):
            return f"{self.seg(keyword)} {this}"
        return default(expression)

    def where_sql(self, expression):
        return self._clause("WHERE", expression, super().where_sql)

    def having_sql(self, expression):
        return self._clause("HAVING", expression, super().having_sql)

    def op_expressions(self, op, expression, flat=False):
        # GROUP BY, ORDER BY, ...
        if not flat:
            items = self.expressions(expression, flat=True)
            if items and self._fits(items, op + " "):
                return f"{self.seg(op)} {items}"
        return super().op_expressions(op, expression, flat=flat)


@lru_cache(maxsize=None)
def _compact_generator(dialect_name):
    dialect = Dialect.get_or_raise(dialect_name)
    base = dialect.generator_class
    return dialect, type(f"Compact{base.__name__}", (_CompactLayout, base), {})


def format_sql(sql, dialect, fmt):
    """
    `sql` laid out by `fmt` (a settings.SqlFormat) in `dialect`, or
    unchanged when fmt.pretty is off or the SQL can't be parsed.
    """
    if not fmt.pretty:
        return sql
    options = dict(pretty=True, pad=fmt.pad, indent=fmt.indent,
                   leading_comma=fmt.leading_comma,
                   max_text_width=fmt.max_text_width)
    try:
        tree = sqlglot.parse_one(sql, read=dialect)
        if fmt.layout == "sqlglot":
            return tree.sql(dialect=dialect, **options)
        dialect_obj, generator = _compact_generator(dialect)
        return generator(dialect=dialect_obj, **options).generate(tree)
    except Exception:
        return sql
