# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Checks on the user's QUESTION (not the SQL) for restricted columns:
# which message to show when the model can't answer, and the follow-up
# pre-check that answers "restricted" before the model is called. They
# choose messages; they never grant access. Split out of
# agent_controls.py.

from sqlagent.adaptive.text_match import names_column, phrase_matches, tokenize


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
