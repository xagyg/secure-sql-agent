# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Text matching shared by schema search (schema_catalog.py), domain
# routing (domains.py) and the restricted-column checks on questions
# (question_policy.py), so a word "matches" in exactly the same way in all
# three. Nothing here knows about security or the database.

import re

from sqlagent.settings import get_settings


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
# SchemaCatalog.score_table). The values are set under table_match: in
# config/settings/retrieval.yaml. FULL_NAME_MATCH is also the line between
# a strong match (a table named in full or by alias) and a weak one (only
# partial names or column words), used by schema search and routing.
_POINTS = get_settings().retrieval.table_match
FULL_NAME_MATCH = _POINTS.full_name        # per name part, when EVERY part of the name matched
                                           # (e.g. "employees", or "order details" for order_details)
PARTIAL_NAME_MATCH = _POINTS.partial_name  # per name part, when only SOME parts matched
                                           # (e.g. just "order" for order_details)
COLUMN_MATCH = _POINTS.column              # per matching column-name word
ALIAS_MATCH = FULL_NAME_MATCH  # an alias (or label) counts as naming the table in full
TERM_MATCH = FULL_NAME_MATCH   # a business term ("shipped late") points at its table


def words(text):
    """
    The words of text in order, lowercase, with CamelCase/PascalCase
    split ("OrderDate" -> "order", "date"). No singulars and no length
    filter: tokenize() adds those.
    """
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    return re.findall(r"[A-Za-z0-9]+", text.lower())


def tokenize(text):
    """
    The set of word forms in text: lowercase, CamelCase split, words of
    two or more characters, plus a simple singular for plurals
    ("categories" -> "category", "addresses" -> "address",
    "orders" -> "order").
    """
    result = set()

    for token in words(text):
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


# ---------------------------------------------------------------------------
# Typo correction
# ---------------------------------------------------------------------------
# Matching above is exact, so one typo ("custmers", "suplier") means the
# word matches nothing. correct_words() maps such a word to the closest
# word in the catalog's vocabulary (table and column names, aliases,
# labels, terms, domain names), using RapidFuzz. It only ever ADDS a
# vocabulary word: the question itself is not changed, and a word that
# already matches is never touched. The vocabulary comes from the
# security-filtered catalog, so a correction can't point anywhere the
# role can't already see. Settings: typo_correction in
# config/settings/retrieval.yaml.

try:
    from rapidfuzz import fuzz, process
except ImportError:          # optional: without it, matching stays exact
    fuzz = process = None


def fuzzy_available():
    return process is not None


def correct_words(text, known, candidates, *, min_score, min_length, margin,
                  skip=frozenset()):
    """
    Corrections for the words of text that match nothing.

    known       every word form that already matches something (words
                with their tokenize() forms); such words are left alone
    candidates  the vocabulary words a typo may be corrected to
    min_score   lowest RapidFuzz ratio (0-100) accepted
    min_length  shorter words are never corrected ("po", "id", "ship")
    margin      if another candidate with a different meaning scores
                within this many points of the best, the word is
                ambiguous and left alone
    skip        words never corrected (e.g. GENERIC_TERMS)

    Words containing a digit (codes such as PUR0410) are never corrected.

    Returns (corrections, ambiguous): corrections maps word ->
    (vocabulary word, score); ambiguous maps word -> the tied candidates.
    """
    corrections, ambiguous = {}, {}
    if process is None or not candidates:
        return corrections, ambiguous

    for word in dict.fromkeys(words(text)):   # unique, in order
        if (len(word) < min_length or word in skip
                or any(ch.isdigit() for ch in word)):
            continue
        forms = tokenize(word)
        if forms & known or forms & skip:
            continue

        found = process.extract(word, candidates, scorer=fuzz.ratio,
                                score_cutoff=min_score, limit=5)
        if not found:
            continue
        best, best_score, _ = found[0]
        best_forms = tokenize(best)
        rivals = [
            cand for cand, score, _ in found[1:]
            if score >= best_score - margin and not (tokenize(cand) & best_forms)
        ]
        if rivals:
            ambiguous[word] = [best] + rivals
            continue
        corrections[word] = (best, round(best_score))

    return corrections, ambiguous
