# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Tests for how the partial schema is widened: hub-aware relationship
# walks, tables named outside the chosen domain, blending of the top two
# domains, and the context summary in the log. No database or LLM needed.
#
#     python -m unittest tests.test_relationship_walk -v

import dataclasses
import unittest
from pathlib import Path

from sqlagent.adaptive.semantic_model import SemanticModelError, load_semantic_model
from sqlagent.settings import RelationshipWalk, load_settings
from tests.fixtures import NORTHWIND, make_catalog
from tests.test_domains import route, tables_in
from tests.test_semantic_model import model_from

ODOO_SEMANTIC_PATH = (Path(__file__).resolve().parent.parent
                      / "config" / "databases" / "odoo" / "semantic")


def odoo_like_catalog(retrieval=None, pointing_at_company=20):
    """
    A small Odoo-shaped graph:

        t01 .. tNN -> company          (company is a hub)
        partner    -> company, country
        sale_order -> partner
    """
    names = (["company", "country", "partner", "sale_order"]
             + [f"t{n:02d}" for n in range(1, pointing_at_company + 1)])
    catalog = make_catalog(
        exclude=set(NORTHWIND),
        extra_tables={f"public.{n}": ["id", "company_id"] for n in names},
    )
    if retrieval is not None:
        with_retrieval(catalog, retrieval)

    def fk(a, b):
        return {"from_table": f"public.{a}", "from_columns": ("x",),
                "to_table": f"public.{b}", "to_columns": ("id",)}

    catalog.foreign_keys = (
        [fk(f"t{n:02d}", "company") for n in range(1, pointing_at_company + 1)]
        + [fk("partner", "company"), fk("partner", "country"),
           fk("sale_order", "partner")]
    )
    return catalog


def with_retrieval(catalog, retrieval):
    """Give the catalog its own copy of the semantic model with these
    retrieval overrides (the default model is shared between tests)."""
    catalog.semantic = dataclasses.replace(catalog.semantic, retrieval=retrieval)
    return catalog


def short(names):
    return {n.split(".", 1)[1] for n in names}


class HubTables(unittest.TestCase):

    def test_hub_is_found_by_count(self):
        catalog = odoo_like_catalog()
        self.assertEqual(short(catalog.hub_tables()), {"company"})

    def test_at_threshold_is_not_a_hub(self):
        # 15 tables + partner = 16 > 15 is a hub; 14 + partner = 15 is not.
        self.assertEqual(odoo_like_catalog(pointing_at_company=14).hub_tables(),
                         frozenset())

    def test_threshold_zero_turns_it_off(self):
        catalog = odoo_like_catalog(retrieval={"hub_threshold": 0})
        self.assertEqual(catalog.hub_tables(), frozenset())

    def test_hub_and_not_hub_lists(self):
        catalog = odoo_like_catalog(retrieval={
            "hub_tables": ["partner"], "not_hub_tables": ["company"]})
        self.assertEqual(short(catalog.hub_tables()), {"partner"})

    def test_self_references_do_not_count(self):
        catalog = odoo_like_catalog(pointing_at_company=0)
        catalog.foreign_keys = [
            {"from_table": "public.partner", "from_columns": ("x",),
             "to_table": "public.partner", "to_columns": ("id",)}
        ] * 30
        self.assertEqual(catalog.hub_tables(), frozenset())

    def test_cache_follows_the_graph(self):
        catalog = odoo_like_catalog()
        self.assertTrue(catalog.hub_tables())
        catalog.foreign_keys = []
        self.assertEqual(catalog.hub_tables(), frozenset())

    def test_northwind_has_no_hubs(self):
        self.assertEqual(make_catalog().hub_tables(), frozenset())


class Walk(unittest.TestCase):

    def test_hub_is_reached_but_not_fanned_out_from(self):
        related = short(odoo_like_catalog().get_related_tables({"public.partner"}))
        # Outward: company and country. Inward: sale_order (partner isn't
        # a hub). Not the 20 tables that point at company.
        self.assertEqual(related, {"partner", "company", "country", "sale_order"})

    def test_selected_hub_keeps_only_itself_and_its_own_keys(self):
        related = short(odoo_like_catalog().get_related_tables({"public.company"}))
        self.assertEqual(related, {"company"})

    def test_without_hubs_the_walk_fans_out(self):
        catalog = odoo_like_catalog(retrieval={"hub_threshold": 0})
        related = catalog.get_related_tables({"public.company"})
        self.assertEqual(len(related), 1 + 20 + 1)   # company, t01..t20, partner

    def test_two_hops_still_respect_hubs(self):
        related = short(odoo_like_catalog().get_related_tables(
            {"public.sale_order"}, depth=2))
        self.assertEqual(related, {"sale_order", "partner", "company", "country"})


class NamedOutsideDomain(unittest.TestCase):

    # HR only (blend off); "categories" is outside HR, and one hop from it
    # is products, which nothing in HR reaches.
    QUESTION = "list the categories and employees [where=staff records]"

    def schema_for(self, mode):
        catalog = make_catalog()
        catalog.domain_resolver.blend = False
        with_retrieval(catalog, {"named_outside_domain": mode})
        ctx, decision = route(catalog, self.QUESTION)
        self.assertEqual(decision.domains, ["hr"])
        scope = catalog.domain_resolver.scope(decision)
        return tables_in(catalog.discover_schema(ctx.question, scope=scope))

    def test_walk_adds_table_and_its_neighbours(self):
        tables = self.schema_for("walk")
        self.assertIn("categories", tables)
        self.assertIn("products", tables)

    def test_add_adds_only_the_table(self):
        tables = self.schema_for("add")
        self.assertIn("categories", tables)
        self.assertNotIn("products", tables)
        self.assertIn("employees", tables)

    def test_note_leaves_the_domain_schema_alone(self):
        tables = self.schema_for("note")
        self.assertNotIn("categories", tables)
        self.assertIn("employees", tables)

    def test_shipped_default_is_add(self):
        self.assertEqual(RelationshipWalk().named_outside_domain, "add")


class Blending(unittest.TestCase):

    QUESTION = "list the shippers [where=staff records]"   # Logistics vs HR

    def test_close_domains_blend_by_default(self):
        _, decision = route(make_catalog(), self.QUESTION)
        self.assertEqual(decision.mode, "blended")
        self.assertEqual(len(decision.domains), 2)

    def test_blend_off_uses_the_top_domain(self):
        catalog = make_catalog()
        catalog.domain_resolver.blend = False
        _, decision = route(catalog, self.QUESTION)
        self.assertEqual(decision.mode, "single")
        self.assertEqual(decision.domains, ["logistics"])

    def test_database_override_turns_blending_off(self):
        semantic = model_from(**{"r.yaml": "retrieval: {blend: false}"})
        self.assertFalse(make_catalog(semantic=semantic).domain_resolver.blend)

    def test_odoo_does_not_blend(self):
        model = load_semantic_model(ODOO_SEMANTIC_PATH)
        self.assertEqual(model.retrieval, {"blend": False,
                                           "hub_tables": [], "not_hub_tables": []})


class RetrievalOverrides(unittest.TestCase):

    def test_only_set_keys_are_kept(self):
        model = model_from(**{"r.yaml": "retrieval: {hub_threshold: 30}"})
        self.assertEqual(model.retrieval["hub_threshold"], 30)
        self.assertNotIn("blend", model.retrieval)

    def test_unknown_key_is_an_error(self):
        with self.assertRaises(SemanticModelError):
            model_from(**{"r.yaml": "retrieval: {hops: 2}"})

    def test_bad_mode_is_an_error(self):
        with self.assertRaises(SemanticModelError):
            model_from(**{"r.yaml": "retrieval: {named_outside_domain: skip}"})

    def test_defined_twice_is_an_error(self):
        with self.assertRaises(SemanticModelError):
            model_from(**{"a.yaml": "retrieval: {blend: false}",
                          "b.yaml": "retrieval: {hub_threshold: 5}"})

    def test_shipped_global_settings(self):
        r = load_settings(environ={}).retrieval
        self.assertEqual(r.relationships.hub_threshold, 15)
        self.assertEqual(r.relationships.named_outside_domain, "add")
        self.assertTrue(r.domains.blend)


class ContextSummary(unittest.TestCase):

    def test_counts_tables_and_largest(self):
        schema = "\n".join([
            "TABLE public.small",
            "  - id integer NOT NULL",
            "",
            "TABLE public.big  -- the big one",
            "  - a text NULL",
            "  - b text NULL",
            "  - c text NULL",
            "",
            "RELATIONSHIPS",
            "  - public.small(id) -> public.big(a)",
            "  - public.small(id) -> public.big(b)",
        ])
        catalog = make_catalog()
        self.assertEqual(catalog.context_summary(schema),
                         "2 table(s); largest: public.big (4), public.small (2)")

    def test_empty(self):
        self.assertEqual(make_catalog().context_summary(""), "0 tables")


if __name__ == "__main__":
    unittest.main()
