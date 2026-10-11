# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Text matching shared by schema search (schema_catalog.py), domain
# routing (domains.py) and the restricted-column checks on questions
# (question_policy.py), so a word "matches" in exactly the same way in all
# three. Nothing here knows about security or the database.

import re


# Everyday words that say nothing about WHICH table is wanted. They are
# ignored when matching a question to tables, so e.g. "show me Margaret's
# details" doesn't pull in order_details just because of the word
# "details". Keep this to generic words, never real table/column names.
GENERIC_TERMS = frozenset({
    "show", "list", "give", "get", "find", "tell", "display",
    "me", "all", "any", "the", "about", "their", "his", "her",
    "what", "who", "which", "whose", "how", "many", "much",
    "detail", "details", "info", "information", "data",
    "record", "records", "everything",
})

# Scores used to rank tables against a question (see
# SchemaCatalog.score_table). FULL_NAME_MATCH is also the line between a
# strong match (a table named in full or by alias) and a weak one (only
# partial names or column words), used by schema search and routing.
FULL_NAME_MATCH = 20    # per name part, when EVERY part of the name matched
                        # (e.g. "employees", or "order details" for order_details)
PARTIAL_NAME_MATCH = 5  # per name part, when only SOME parts matched
                        # (e.g. just "order" for order_details)
COLUMN_MATCH = 3        # per matching column-name word
ALIAS_MATCH = FULL_NAME_MATCH  # an alias (or label) counts as naming the table in full
TERM_MATCH = FULL_NAME_MATCH   # a business term ("shipped late") points at its table


def tokenize(text):
    """
    The set of word forms in text: lowercase, CamelCase split, words of
    two or more characters, plus a simple singular for plurals
    ("categories" -> "category", "addresses" -> "address",
    "orders" -> "order").
    """
    # Split CamelCase/PascalCase identifiers.
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)

    tokens = re.findall(r"[A-Za-z0-9]+", text.lower())

    result = set()

    for token in tokens:
        if len(token) < 2:
            continue

        result.add(token)

        if token.endswith("ies") and len(token) > 4:
            result.add(token[:-3] + "y")

        elif token.endswith("ses") and len(token) > 4:
            result.add(token[:-2])

        elif (
            token.endswith("s")
            and not token.endswith("ss")
            and len(token) > 3
        ):
            result.add(token[:-1])

    return result


def phrase_parts(phrase):
    """
    The word forms of each part of a name or phrase, split on "_" and
    spaces: "order_details" -> [{"order"}, {"details", "detail"}].
    Parts with no usable word are dropped.
    """
    return [
        tokenize(part)
        for part in re.split(r"[_\s]+", phrase)
        if tokenize(part)
    ]


def phrase_matches(phrase, terms):
    """
    True when every word of the phrase is in terms (from tokenize()).
    "sales_rep" matches "sales rep", "sales reps" and "SalesRep".
    Used for table and column aliases, domain names and locations.
    """
    parts = phrase_parts(phrase)
    return bool(parts) and all(terms & forms for forms in parts)


def names_column(text, column):
    """
    True if the lowercase text names the column: "home phone",
    "home_phone", or its last word ("phone"), singular or plural.

    Deliberately a word-boundary regex rather than tokenize(): it must
    accept "faxes" for "fax", which tokenize()'s simple singular rule
    turns into "faxe".
    """
    parts = column.lower().split("_")
    terms = {" ".join(parts), column.lower(), parts[-1]}
    return any(
        re.search(rf"\b{re.escape(term)}(es|s)?\b", text) for term in terms
    )
