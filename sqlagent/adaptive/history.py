# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Conversation history for the SQL-generation prompt.
#
# Each turn used to carry the explanation model's full prose answer. That
# was the noisiest part of the prompt: chatty wording, restated numbers and
# (for big results) long lists, all of which the model could copy into SQL
# or anchor on. Each turn now carries a short, deterministic summary of the
# result instead: row count, columns and a few sample rows, capped in size.
#
# By default only the most recent turn includes its SQL (sql_turns=1). It
# already holds every filter built up so far ("now only those in Germany"),
# so older SQL adds little but extra tables and joins for the model to reuse
# by mistake. sql_turns can be raised to test that against real questions.
#
# The summary is built from the rows AFTER the result policy has run, so a
# withheld column can never reach the prompt this way.

from datetime import date, datetime
from decimal import Decimal

ELLIPSIS = "..."


def _format_value(value, max_value_chars):
    if value is None:
        text = "null"
    elif isinstance(value, (datetime, date)):
        text = value.isoformat()
    elif isinstance(value, float):
        text = f"{value:g}"
    elif isinstance(value, Decimal):
        text = format(value.normalize(), "f")
    else:
        text = " ".join(str(value).split())
    if len(text) > max_value_chars:
        text = text[: max(1, max_value_chars - len(ELLIPSIS))] + ELLIPSIS
    return text


def summarise_result(results, *, sample_rows=3, max_value_chars=40,
                     max_chars=400, row_cap=None, withheld=()):
    """
    A compact, deterministic summary of a query result for the
    conversation history, e.g.

        1 row. ProductName=Perth Pasties; LastOrdered=1998-05-01

        12 rows. Columns: CompanyName, Country.
        First 3: CompanyName=Alfreds Futterkiste, Country=Germany | ...

    row_cap is the operational row limit: a result that reached it is
    marked as capped so the model doesn't treat it as the full count.
    max_chars bounds the whole summary.
    """
    count = len(results)
    if count == 0:
        text = "No rows returned."
    else:
        columns = []
        for row in results:
            for column in row:
                if column not in columns:
                    columns.append(column)

        def render(row):
            return ", ".join(
                f"{column}={_format_value(row.get(column), max_value_chars)}"
                for column in columns
            )

        noun = "row" if count == 1 else "rows"
        capped = (f" (capped at {row_cap}; there may be more)"
                  if row_cap and count >= row_cap else "")
        if count == 1:
            text = f"1 row. {render(results[0])}"
        else:
            shown = results[:max(0, sample_rows)]
            text = f"{count} {noun}{capped}. Columns: {', '.join(columns)}."
            if shown:
                label = "Rows" if len(shown) == count else f"First {len(shown)}"
                text += f"\n{label}: " + " | ".join(render(r) for r in shown)

    if withheld:
        text += f"\nWithheld by policy: {', '.join(withheld)}."

    if len(text) > max_chars:
        text = text[: max(1, max_chars - len(ELLIPSIS))] + ELLIPSIS
    return text


def format_history(history, turns, sql_turns=1):
    """
    The CONVERSATION CONTEXT block for the SQL prompt: the last `turns`
    turns, oldest first. Every turn gives its question and result summary;
    the last `sql_turns` of them also give their SQL (0: none). Turns
    stored before summaries existed fall back to their answer text.
    """
    if not history or turns <= 0:
        return ""

    recent = history[-turns:]
    first_with_sql = len(recent) - max(0, sql_turns)
    blocks = []
    for index, turn in enumerate(recent):
        latest = index == len(recent) - 1
        summary = turn.get("result_summary") or turn.get("answer", "")
        label = "Most recent" if latest else "Earlier"
        lines = [f"{label} question:", turn["question"]]
        if index >= first_with_sql and turn.get("sql"):
            lines += ["", f"{label} SQL:", turn["sql"]]
        lines += ["", f"{label} result:", summary]
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks)
