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


# Example questions offered with the overview / clarification messages.
EXAMPLE_QUESTIONS = (
    "Which customers are in Germany?",
    "Which products are low on stock?",
    "Who are our top 5 customers by order value?",
)


def _areas_text(labels, conjunction="and"):
    """'Sales, Purchasing & Inventory and Shipping & Logistics'. Labels
    are the generic Domain of Discourse names, never table names."""
    labels = [l for l in labels if l]
    if not labels:
        return ""
    if len(labels) == 1:
        return labels[0]
    return ", ".join(labels[:-1]) + f" {conjunction} " + labels[-1]


def _examples_text():
    return ", ".join(f"\"{q}\"" for q in EXAMPLE_QUESTIONS[:2])


def overview_message(labels):
    """
    Answer to a question about the database itself ("What does Northwind
    have?", "What data can I ask about?"). Lists only the areas this
    role can see, by their generic labels, so nothing restricted is
    revealed. Not a block: no SQL is generated or run.
    """
    areas = _areas_text(labels)
    if not areas:
        return OFF_TOPIC_MESSAGE
    return (
        "Northwind is a sample trading company's database. The areas you "
        f"can ask about are {areas}. For example: {_examples_text()}"
    )


def clarify_message(labels):
    """
    The model couldn't tell what the question was after (it said so, or
    misused the read-only marker for a question with no write intent).
    Previously this was reported as "not available ... may be restricted
    for your role", which blamed security for what was really a vague
    question, and made genuine access denials less credible.
    """
    areas = _areas_text(labels, "or")
    hint = f" about {areas}" if areas else " about the data"
    return (
        "I'm not sure what you're asking, so nothing was run. Try a more "
        f"specific question{hint}, for example: {_examples_text()}"
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
