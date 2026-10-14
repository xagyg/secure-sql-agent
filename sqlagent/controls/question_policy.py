# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Checks on the user's QUESTION (not the SQL) for restricted columns:
# which message to show when the model can't answer, and the follow-up
# pre-check that answers "restricted" before the model is called. They
# choose messages; they never grant access. Split out of
# agent_controls.py.

import re

from sqlagent.adaptive.text_match import names_column, phrase_matches, tokenize


# ---------------------------------------------------------------------------
# Questions about the database itself
# ---------------------------------------------------------------------------
# "What does Northwind have?", "What data do you have?", "What can I ask?"
# These ask what the agent can answer, not for data. Sent to the model,
# they had no matching table, got the fallback schema, and the model
# guessed a filter ("WHERE category_name = 'North Wind'") or gave up.
# They are answered deterministically instead, from the Domain of
# Discourse labels this role can see.
#
# Kept deliberately narrow: only generic nouns may come between "what"
# and the verb, so "what products does Northwind have?" (a real data
# question) and "what information do you have about Jose?" (a record
# lookup) still go to the model.

_SUBJECT = (r"(?:you|northwind|north\s*wind|the\s+database|this\s+database|"
            r"the\s+system|this\s+system|it|we|i)")
_GENERIC_NOUN = (r"(?:(?:kinds?|sorts?|types?)\s+of\s+)?"
                 r"(?:data|information|info|tables?|records|stuff|things|"
                 r"questions|details)")

_OVERVIEW_PATTERNS = [
    # what (data) do you / does northwind have|hold|contain|...
    re.compile(
        rf"^(?:so\s+|ok\s+|okay\s+)?(?:what|which)(?:\s+{_GENERIC_NOUN})?\s+"
        rf"(?:do|does|can|is|are)\s+{_SUBJECT}\s+"
        r"(?:have|hold|contain|store|keep|know|cover|offer|got|ask|see|"
        r"access|query|show(?:\s+me)?)"
        r"(?:\s+(?:access\s+to|in\s+it|available|here|there|you))?\s*$",
        re.IGNORECASE),
    # what's in northwind / the database
    re.compile(
        r"^(?:what\s+is|what's|whats)\s+(?:in|inside)\s+"
        r"(?:northwind|north\s*wind|the\s+database|this\s+database|the\s+data)\s*$",
        re.IGNORECASE),
    # tell me about / describe / overview of northwind / the database
    re.compile(
        r"^(?:tell\s+me\s+about|describe|explain|give\s+me\s+an\s+overview\s+of|"
        r"overview\s+of)\s+(?:northwind|north\s*wind|the\s+database|"
        r"this\s+database|the\s+data|your\s+data)\s*$",
        re.IGNORECASE),
    # what can you do / help
    re.compile(r"^(?:what\s+can\s+you\s+do|help|what\s+can\s+i\s+ask(?:\s+you)?)\s*$",
               re.IGNORECASE),
    # what tables are there / are available
    re.compile(rf"^(?:what|which)\s+{_GENERIC_NOUN}\s+(?:are|is)\s+"
               r"(?:there|available)\s*$", re.IGNORECASE),
]


def is_overview_question(question):
    """True if the question asks what the database/agent covers rather
    than for data. Chooses a message only; it never grants access."""
    text = " ".join(question.strip().rstrip("?.! ").split())
    return any(p.match(text) for p in _OVERVIEW_PATTERNS)


def mentions_denied_column(question, security, tables=None):
    """
    True if the question names a column this role is denied, e.g.
    "phone" / "home phone" for home_phone, or "fax", "address".

    tables (a set of full table names) limits the check to columns denied
    on those tables; None checks every table.

    Used after the model has said it can't answer (the denied column is
    hidden from the schema it sees), to show "restricted data" instead of
    the vaguer "not available". Also used before the model is called, for
    a follow-up about a table on which the named column is restricted
    (see run_agent). It chooses a message; it never grants access.
    """
    return bool(denied_columns_named(question, security, tables))


def denied_columns_named(question, security, tables=None):
    """The (table, column) pairs denied to this role that the question
    names. tables (full names) limits the check to those tables."""
    text = question.lower()
    wanted = {t.lower() for t in tables} if tables is not None else None
    named = []

    for table, columns in security.denied_columns.items():
        if wanted is not None and table.lower() not in wanted:
            continue
        for column in columns:
            if names_column(text, column):
                named.append((table, column))
    return named


def follow_up_asks_restricted(question, security, catalog, tables):
    """
    True if a follow-up about `tables` asks for a column restricted on
    one of them, e.g. "What is Thomas's address?" after a customers
    query (customers.address denied).

    Not when the question names a MORE SPECIFIC authorised column that
    contains the same words: "what's their ship address?" means
    orders.ship_address, which is allowed, not customers.address.
    """
    terms = tokenize(question)

    for _table, column in denied_columns_named(question, security, tables):
        words = set(column.lower().split("_"))
        more_specific = any(
            set(c["name"].lower().split("_")) > words
            and phrase_matches(c["name"], terms)
            for t in catalog.tables.values()
            for c in t["columns"]
        )
        if not more_specific:
            return True
    return False
