# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Tests for typo correction of question words (text_match.correct_words,
# SchemaCatalog.question_terms) and its effect on schema search and
# Domain of Discourse routing. No database or LLM needed.
#
#     python -m unittest tests.test_typo_correction -v

import unittest
from types import SimpleNamespace
from unittest import mock

from pydantic import ValidationError

from sqlagent.adaptive.text_match import (
    GENERIC_TERMS, correct_words, fuzzy_available, is_common_word, tokenize,
    word_frequency_available)
from sqlagent.settings import TypoCorrection
from tests.fixtures import make_catalog


class Dependency(unittest.TestCase):

    # wordfreq is pinned too: without it, real words get "corrected".
    def test_wordfreq_installed(self):
        self.assertTrue(
            word_frequency_available(),
            "wordfreq not installed (pip install -r requirements.txt)")

    # rapidfuzz is a pinned requirement, so a missing install is a broken
    # environment: fail here rather than skip the typo tests and report
    # OK. The agent itself still runs without it (matching stays exact,
    # with a warning); test_without_rapidfuzz_matching_stays_exact
    # covers that path.
    def test_rapidfuzz_installed(self):
        self.assertTrue(
            fuzzy_available(),
            "rapidfuzz not installed (pip install -r requirements.txt)")


def fresh_terms(catalog, question):
    catalog._last_terms = (None, frozenset())
    return catalog.question_terms(question)


def top_table(catalog, question):
    catalog._last_terms = (None, frozenset())
    return catalog.search(question, limit=1)[0][1]["name"]


def corrections(text, candidates, **kw):
    options = dict(min_score=85, min_length=5, margin=3, skip=GENERIC_TERMS)
    options.update(kw)
    known = set()
    for c in candidates:
        known |= tokenize(c)
    return correct_words(text, known, sorted(candidates), **options)


class CorrectWords(unittest.TestCase):

    def test_typo_is_corrected(self):
        fixed, _ = corrections("list custmers", {"customers", "orders"})
        self.assertEqual(fixed["custmers"][0], "customers")

    def test_known_word_is_left_alone(self):
        fixed, _ = corrections("list customers and orders", {"customers", "orders"})
        self.assertEqual(fixed, {})

    def test_known_by_singular_is_left_alone(self):
        # "categories" -> "category" is already a match.
        fixed, _ = corrections("show categories", {"category"})
        self.assertEqual(fixed, {})

    def test_short_words_never_corrected(self):
        fixed, _ = corrections("ordr", {"order"})
        self.assertEqual(fixed, {})

    def test_words_with_digits_never_corrected(self):
        fixed, _ = corrections("PUR0411", {"pur0410", "purchase"})
        self.assertEqual(fixed, {})

    def test_generic_words_never_corrected(self):
        fixed, _ = corrections("informations", {"formation"}, min_score=60)
        self.assertEqual(fixed, {})

    def test_real_word_inside_a_vocabulary_word_is_left_alone(self):
        # "located" scores 88 against "allocated", above min_score.
        fixed, _ = corrections("customers located in Australia",
                               {"customers", "allocated"})
        self.assertNotIn("located", fixed)

    def test_first_letter_rule_can_be_turned_off(self):
        fixed, _ = corrections("customers located in Australia",
                               {"customers", "allocated"},
                               same_first_letter=False)
        self.assertEqual(fixed["located"][0], "allocated")

    def test_below_threshold_not_corrected(self):
        fixed, _ = corrections("Margaret", {"market"})
        self.assertEqual(fixed, {})

    def test_tie_between_different_words_is_ambiguous(self):
        fixed, tied = corrections("shaps", {"ships", "shops"}, min_score=75)
        self.assertEqual(fixed, {})
        self.assertEqual(set(tied["shaps"]), {"ships", "shops"})

    def test_singular_and_plural_are_not_a_tie(self):
        fixed, tied = corrections("custmers", {"customer", "customers"})
        self.assertIn(fixed["custmers"][0], {"customer", "customers"})
        self.assertEqual(tied, {})


class CommonWords(unittest.TestCase):

    def test_real_words_are_common(self):
        for word in ("currently", "located", "contract", "supplied"):
            with self.subTest(word=word):
                self.assertTrue(is_common_word(word, 3.0))

    def test_typos_are_not(self):
        for word in ("custmers", "suplier", "prodcuts", "shiped",
                     "employes", "territores", "purchsing"):
            with self.subTest(word=word):
                self.assertFalse(is_common_word(word, 3.0))

    def test_zero_turns_the_check_off(self):
        self.assertFalse(is_common_word("currently", 0))

    def test_common_word_is_left_alone(self):
        # "currently" scores 88 against "current", same first letter.
        fixed, _ = corrections("products currently out of stock",
                               {"products", "current"}, common_word_zipf=3.0)
        self.assertNotIn("currently", fixed)

    def test_without_the_check_it_is_corrected(self):
        fixed, _ = corrections("products currently out of stock",
                               {"products", "current"}, common_word_zipf=0)
        self.assertEqual(fixed["currently"][0], "current")

    def test_typo_still_corrected_with_the_check(self):
        fixed, _ = corrections("list custmers", {"customers", "orders"},
                               common_word_zipf=3.0)
        self.assertEqual(fixed["custmers"][0], "customers")


class CatalogQuestionTerms(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.catalog = make_catalog()

    def test_typos_against_northwind(self):
        cases = {
            "list all custmers in Germany": "customer",
            "which supliers are in Japan": "supplier",
            "show me the prodcuts": "product",
            "orders shiped late": "shipped",
            "how many employes are there": "employee",
            "show territores": "territory",
        }
        for question, expected in cases.items():
            with self.subTest(question=question):
                self.assertIn(expected, fresh_terms(self.catalog, question))

    def test_question_words_are_kept(self):
        terms = fresh_terms(self.catalog, "list all custmers in Germany")
        self.assertIn("custmers", terms)
        self.assertIn("germany", terms)

    def test_names_and_places_are_not_corrected(self):
        questions = [
            "Show Nancy Davolio's details",
            "Margaret Peacock orders",
            "Seattle London Tokyo Berlin Mexico France",
            "Laura Callahan Robert King Steven Buchanan Andrew Fuller",
            "Exotic Liquids, Speedy Express, United Package",
            "Chai Chang Tofu Ikura Konbu Pavlova",
        ]
        for question in questions:
            with self.subTest(question=question):
                self.assertEqual(
                    fresh_terms(self.catalog, question),
                    tokenize(question) - GENERIC_TERMS)

    def test_vocabulary_is_only_what_the_role_can_see(self):
        # territories and employee_territories not authorised: nothing
        # else has a "territory" word, so the typo has no target.
        catalog = make_catalog(exclude=("territories", "employee_territories"))
        self.assertNotIn("territory", fresh_terms(catalog, "show territores"))
        _, candidates = catalog.vocabulary()
        self.assertNotIn("territories", candidates)
        self.assertNotIn("territory", candidates)

    def test_disabled_in_settings(self):
        off = SimpleNamespace(retrieval=SimpleNamespace(
            typo_correction=TypoCorrection(enabled=False)))
        with mock.patch("sqlagent.adaptive.schema_catalog.get_settings",
                        return_value=off):
            terms = fresh_terms(self.catalog, "list all custmers")
        self.assertNotIn("customer", terms)

    def test_without_rapidfuzz_matching_stays_exact(self):
        with mock.patch("sqlagent.adaptive.schema_catalog.fuzzy_available",
                        return_value=False):
            terms = fresh_terms(self.catalog, "list all custmers")
        self.assertNotIn("customer", terms)


class SearchAndRouting(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.catalog = make_catalog()

    def test_search_finds_the_misspelled_table(self):
        self.assertEqual(top_table(self.catalog, "list all custmers in Germany"),
                         "customers")
        self.assertEqual(top_table(self.catalog, "which supliers are in Japan"),
                         "suppliers")
        self.assertEqual(top_table(self.catalog, "how many employes are there"),
                         "employees")

    def test_routing_follows_a_misspelled_domain_name(self):
        self.catalog._last_terms = (None, frozenset())
        decision = self.catalog.domain_resolver.resolve(
            "list the purchsing contacts")
        self.assertEqual(decision.domains, ["purchasing"])

    def test_routing_with_typo_matches_routing_without(self):
        for typo, clean in [
            ("which supliers are in Japan", "which suppliers are in Japan"),
            ("how many employes are there", "how many employees are there"),
        ]:
            with self.subTest(question=typo):
                self.catalog._last_terms = (None, frozenset())
                a = self.catalog.domain_resolver.resolve(typo).domains
                self.catalog._last_terms = (None, frozenset())
                b = self.catalog.domain_resolver.resolve(clean).domains
                self.assertEqual(a, b)


class Settings(unittest.TestCase):

    def test_defaults(self):
        t = TypoCorrection()
        self.assertTrue(t.enabled)
        self.assertEqual((t.min_score, t.min_length, t.margin), (85, 5, 3))
        self.assertTrue(t.same_first_letter)
        self.assertEqual(t.common_word_zipf, 3.0)

    def test_limits(self):
        for bad in ({"min_score": 40}, {"min_score": 101},
                    {"min_length": 2}, {"margin": -1}, {"unknown": 1}):
            with self.subTest(bad=bad):
                with self.assertRaises(ValidationError):
                    TypoCorrection(**bad)


if __name__ == "__main__":
    unittest.main()
