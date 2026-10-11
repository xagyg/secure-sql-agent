# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# User-facing messages for blocked or unanswerable requests. Every message
# and label here is generic: none ever names a table or column, so all are
# safe to send to the browser. Detailed reasons stay in the server log.
# Split out of agent_controls.py.


# Each rule has a short label (shown as a tag in the UI) and a generic
# message. Neither ever names a table or column, so both are safe to send
# to the browser. Detailed reasons stay in the server log only.
BLOCK_RULES = {
    "restricted_data": {
        "label": "restricted data",
        "message": "That information is restricted, so this question can't be answered.",
    },
    # The query matched rows, but every column in them was withheld.
    # Deliberately doesn't say which: "restricted" would confirm the
    # record exists, which row-level rules on a real ERP may need to hide.
    "not_found_or_restricted": {
        "label": "not found or restricted",
        "message": (
            "The record does not exist or you do not have access to the "
            "data requested."
        ),
    },
    "read_only": {
        "label": "read-only",
        "message": (
            "I can't do that. You have read-only access, so adding, "
            "changing or deleting data isn't permitted. "
            "You can still ask questions about the data, e.g. "
            "\"How many customers are there in each country?\""
        ),
    },
    "single_statement": {
        "label": "one query only",
        "message": "Only one query is allowed at a time.",
    },
    "not_available": {
        "label": "not available",
        "message": (
            "That information isn't available to you, so I can't answer "
            "that. It may be restricted for your role, or not held in the "
            "database."
        ),
    },
    "unparseable": {
        "label": "not validated",
        "message": (
            "I couldn't produce a valid query for that, so nothing was run. "
            "Try rephrasing it as a question about the data."
        ),
    },
    "policy": {
        "label": "security policy",
        "message": "That request was stopped because it doesn't meet the security policy.",
    },
}


# Not a block: the model didn't return a query at all (e.g. it replied in
# prose). Reported as a technical "error", like an unparseable query.
NO_QUERY_MESSAGE = (
    "I couldn't turn that into a database query, so nothing was run. "
    "Try asking a question about the data, e.g. "
    "\"Which customers are in Germany?\""
)


# Not a block either: the message wasn't a question about the data
# (greeting, insult, small talk). reason=None, so the UI shows no tag.
OFF_TOPIC_MESSAGE = (
    "I can only answer questions about the Northwind data. Try something "
    "like \"Which products are low on stock?\""
)


# Shown after the answer when restricted columns were left out. Generic on
# purpose, like BLOCK_RULES: it never names a table or column.
WITHHELD_NOTE = (
    "Some requested fields are restricted for your role, so they were "
    "left out of this answer."
)
WITHHELD_RULE = "fields_withheld"
WITHHELD_LABEL = "fields withheld"


def block_rule(reason):
    """Map an internal validation reason to a stable rule code."""
    r = reason.lower()

    # Checked first: parser error text can echo arbitrary SQL, which might
    # contain words like "select" or "not authorised".
    if "could not be parsed" in r:
        return "unparseable"
    if "not authorised" in r:
        return "restricted_data"
    if "select into" in r or "read-only" in r:
        return "read_only"
    if "exactly one" in r:
        return "single_statement"
    return "policy"


def rule_label(rule):
    return BLOCK_RULES.get(rule, BLOCK_RULES["policy"])["label"]


def rule_message(rule):
    return BLOCK_RULES.get(rule, BLOCK_RULES["policy"])["message"]


def user_friendly_block_message(reason):
    return rule_message(block_rule(reason))
