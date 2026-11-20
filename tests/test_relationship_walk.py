# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Tests for how the partial schema is widened: hub-aware relationship
# walks, tables named outside the chosen domain, blending of the top two
# domains, and the context summary in the log. No database or LLM needed.
#
#     python -m unittest tests.test_relationship_walk -v

import contextlib
import dataclasses
import io
import unittest
from pathlib import Path

from sqlagent.adaptive.schema_catalog import typed_in_full
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

    def test_add_brings_the_link_table(self):
        # "Which territories have the highest sales?" in the Sales domain:
        # territories is added on its own, and employee_territories
        # (-> employees and -> territories) is the only way to join it.
        catalog = make_catalog()
        links = catalog._link_tables({"public.territories"},
                                     {"public.territories", "public.employees",
                                      "public.orders"})
        self.assertEqual(links, {"public.employee_territories"})

    def test_link_tables_are_only_joins(self):
        catalog = make_catalog()
        # region is next to territories but joins it to nothing present.
        links = catalog._link_tables({"public.territories"},
                                     {"public.territories", "public.employees"})
        self.assertNotIn("public.region", links)
        # Nothing present to join to: no link table.
        self.assertEqual(catalog._link_tables(
            {"public.territories"}, {"public.territories", "public.shippers"}), set())

    def test_shipped_default_is_add(self):
        self.assertEqual(RelationshipWalk().named_outside_domain, "add")

    def test_column_words_alone_do_not_name_a_table(self):
        # A wide table whose column names repeat a question word scores as
        # high as a named table (Odoo's res_company on "sales"), but the
        # question doesn't name it, so it isn't added.
        catalog = make_catalog(extra_tables={
            "public.audit_log": [f"category_note_{i}" for i in range(10)]})
        catalog.domain_resolver.blend = False
        with_retrieval(catalog, {"named_outside_domain": "add"})
        ctx, decision = route(catalog, self.QUESTION)
        scope = catalog.domain_resolver.scope(decision)
        terms = catalog.question_terms(ctx.question)
        wide = catalog.tables["public.audit_log"]
        self.assertGreaterEqual(catalog.score_table(wide, terms), 20)
        self.assertEqual(catalog.name_score(wide, terms), 0)
        tables = tables_in(catalog.discover_schema(ctx.question, scope=scope))
        self.assertIn("categories", tables)
        self.assertNotIn("audit_log", tables)


def orders_catalog(retrieval=None):
    """
    Odoo's shape for the word "order": sale_order has the one-word alias
    "order" (so "order" names it in full), purchase_order only has
    "order" in its name (a partial match). Both point at partner.
    """
    catalog = make_catalog(exclude=set(NORTHWIND), extra_tables={
        "public.sale_order": ["id", "partner_id", "date_order"],
        "public.purchase_order": ["id", "partner_id", "date_order"],
        "public.partner": ["id", "name"],
    })
    catalog.tables["public.sale_order"].update(
        label="sales order", aliases=["order", "quotation", "sale"])
    catalog.tables["public.purchase_order"].update(
        label="purchase order", aliases=["po", "rfq"])
    catalog.tables["public.partner"].update(
        label="partner", aliases=["customer", "vendor", "supplier"])

    def fk(a):
        return {"from_table": f"public.{a}", "from_columns": ("partner_id",),
                "to_table": "public.partner", "to_columns": ("id",)}

    catalog.foreign_keys = [fk("sale_order"), fk("purchase_order")]
    with_retrieval(catalog, retrieval or {})
    return catalog


PURCHASING = ({"public.purchase_order", "public.partner"},
              ["public.purchase_order", "public.partner"], 1)
SALES = ({"public.sale_order", "public.partner"},
         ["public.sale_order", "public.partner"], 1)


class NamedOutsideDomainDistinct(unittest.TestCase):
    """named_outside_domain_distinct: a word the domain also uses doesn't
    name a table outside it."""

    def tables(self, question, scope, retrieval=None):
        catalog = orders_catalog(retrieval)
        return tables_in(catalog.discover_schema(question, scope=scope))

    def test_shared_word_stays_in_the_domain(self):
        # "order" is sale_order's alias, but it is also part of
        # purchase_order's name: from Purchasing it means a purchase order.
        tables = self.tables("What was the last order from Acme?", PURCHASING)
        self.assertNotIn("sale_order", tables)
        self.assertIn("purchase_order", tables)

    def test_switch_off_restores_the_old_behaviour(self):
        tables = self.tables("What was the last order from Acme?", PURCHASING,
                             {"named_outside_domain_distinct": False})
        self.assertIn("sale_order", tables)

    def test_distinct_word_still_names_the_outside_table(self):
        # "sales" is in no Purchasing table name, label or alias.
        tables = self.tables("What was the last sales order from Acme?",
                             PURCHASING)
        self.assertIn("sale_order", tables)
        self.assertIn("purchase_order", tables)

    def test_distinct_one_word_alias(self):
        tables = self.tables("Show the last quotation", PURCHASING)
        self.assertIn("sale_order", tables)

    def test_the_other_way_round(self):
        # From Sales, "purchase order" names purchase_order ("purchase" is
        # not a Sales word); plain "order" stays with sale_order.
        self.assertIn("purchase_order",
                      self.tables("What was the last purchase order?", SALES))
        tables = self.tables("What was the last order?", SALES)
        self.assertIn("sale_order", tables)
        self.assertNotIn("purchase_order", tables)

    def test_naming_phrases_follow_name_score(self):
        catalog = orders_catalog()
        table = catalog.tables["public.sale_order"]
        terms = catalog.question_terms("the last sales order")
        self.assertEqual(set(catalog._naming_phrases(table, terms)),
                         {"sale_order", "sales order", "order", "sale"})
        terms = catalog.question_terms("the last order")
        self.assertEqual(catalog._naming_phrases(table, terms), ["order"])

    def test_domain_words_ignore_columns(self):
        catalog = orders_catalog()
        words = catalog._domain_words(PURCHASING[0])
        self.assertEqual(set(words), {"public.purchase_order", "public.partner"})
        self.assertIn("order", words["public.purchase_order"])
        self.assertIn("vendor", words["public.partner"])
        everything = set().union(*words.values())
        self.assertNotIn("date", everything)     # date_order is a column
        self.assertNotIn("sale", everything)

    def test_log_names_the_domain_table(self):
        catalog = orders_catalog()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            catalog.discover_schema("What was the last order from Acme?",
                                    scope=PURCHASING)
        self.assertIn("not added: sale_order (as purchase_order)", out.getvalue())

    def test_northwind_category_from_hr_is_still_added(self):
        # The existing case: "categories" is no HR word.
        catalog = make_catalog()
        catalog.domain_resolver.blend = False
        ctx, decision = route(catalog, NamedOutsideDomain.QUESTION)
        scope = catalog.domain_resolver.scope(decision)
        self.assertIn("categories",
                      tables_in(catalog.discover_schema(ctx.question, scope=scope)))

    def test_shipped_default_is_on(self):
        self.assertTrue(RelationshipWalk().named_outside_domain_distinct)
        self.assertTrue(load_settings(environ={}).retrieval.relationships
                        .named_outside_domain_distinct)

    def test_database_override(self):
        model = model_from(**{"r.yaml":
                              "retrieval: {named_outside_domain_distinct: false}"})
        self.assertIs(model.retrieval["named_outside_domain_distinct"], False)
        with self.assertRaises(SemanticModelError):
            model_from(**{"r.yaml":
                          "retrieval: {named_outside_domain_distinct: maybe}"})


def moves_catalog():
    """
    An Accounting-shaped domain where "stock" and "move" each belong to a
    different table (stock_valuation_layer, account_move), but no single
    domain table is a "stock move". stock_move is outside the domain.
    A sales domain has sale_order_line ("sales order line"), whose words
    cover sale_order's label "sales order".
    """
    catalog = make_catalog(exclude=set(NORTHWIND), extra_tables={
        "public.account_move": ["id", "partner_id"],
        "public.stock_valuation_layer": ["id", "product_id"],
        "public.stock_move": ["id", "product_id"],
        "public.sale_order": ["id", "partner_id"],
        "public.sale_order_line": ["id", "order_id"],
        "public.mrp_bom": ["id", "product_id"],
        "public.bill_material": ["id"],
    })
    catalog.tables["public.account_move"].update(
        label="journal entry", aliases=["move", "invoice", "bill"])
    catalog.tables["public.stock_valuation_layer"].update(
        label="stock valuation", aliases=["valuation"])
    catalog.tables["public.stock_move"].update(label="stock move")
    catalog.tables["public.sale_order"].update(label="sales order")
    catalog.tables["public.sale_order_line"].update(label="sales order line")
    catalog.tables["public.mrp_bom"].update(label="bill of materials",
                                            aliases=["bom"])
    catalog.tables["public.bill_material"].update(label="bill material")
    catalog.foreign_keys = []
    with_retrieval(catalog, {})
    return catalog


ACCOUNTING = ({"public.account_move", "public.stock_valuation_layer"},
              ["public.account_move", "public.stock_valuation_layer"], 1)
ORDER_LINES = ({"public.sale_order_line"}, ["public.sale_order_line"], 1)


class CoveredByOneDomainTable(unittest.TestCase):
    """named_outside_domain_distinct checks one domain table at a time,
    exempts phrases typed out in full, and ignores filler words."""

    def tables(self, question, scope):
        catalog = moves_catalog()
        return tables_in(catalog.discover_schema(question, scope=scope))

    def test_words_spread_over_two_domain_tables_still_name(self):
        # "stock" (stock_valuation_layer) and "move" (account_move) are
        # both Accounting words, but no Accounting table is a stock move.
        # The words aren't side by side, so this is the per-table check.
        tables = self.tables("Which moves changed stock this week?", ACCOUNTING)
        self.assertIn("stock_move", tables)

    def test_one_table_covering_the_words_still_wins(self):
        # "order" and "sales" scattered: sale_order_line has both, so
        # from that domain they mean order lines, not sale_order.
        tables = self.tables("Which orders came from sales reps?", ORDER_LINES)
        self.assertNotIn("sale_order", tables)

    def test_phrase_typed_in_full_is_kept(self):
        for question in ("List the sales orders for Acme",
                         "List rows of sale_order for Acme"):
            with self.subTest(question=question):
                self.assertIn("sale_order", self.tables(question, ORDER_LINES))

    def test_table_name_typed_as_identifier(self):
        self.assertIn("stock_move",
                      self.tables("count the rows in stock_move", ACCOUNTING))

    def test_one_word_phrase_is_never_exempt(self):
        catalog = moves_catalog()
        catalog.tables["public.stock_move"]["aliases"] = ["move"]
        terms = catalog.question_terms("show the last move")
        words = catalog._domain_words(ACCOUNTING[0])
        self.assertEqual(
            catalog._covered_by(catalog.tables["public.stock_move"], terms,
                                words, "show the last move"),
            "account_move")

    def test_filler_words_do_not_decide(self):
        # "bill of materials" with its words apart: bill_material covers
        # "bill" and "material"; "of" doesn't make the phrase distinct.
        catalog = moves_catalog()
        question = "which bill has materials of steel"
        terms = catalog.question_terms(question)
        words = catalog._domain_words({"public.bill_material"})
        self.assertNotIn("of", words["public.bill_material"])
        self.assertEqual(
            catalog._covered_by(catalog.tables["public.mrp_bom"], terms,
                                words, question),
            "bill_material")

    def test_filler_never_counts_as_a_domain_word(self):
        catalog = moves_catalog()
        catalog.tables["public.account_move"]["label"] = "journal of entries"
        words = catalog._domain_words(ACCOUNTING[0])
        self.assertNotIn("of", words["public.account_move"])


class TypedInFull(unittest.TestCase):

    def test_matches(self):
        self.assertTrue(typed_in_full("stock_move", "rows in stock_move"))
        self.assertTrue(typed_in_full("stock_move", "show stock moves"))
        self.assertTrue(typed_in_full("sales order", "List the Sales Orders"))
        self.assertTrue(typed_in_full("bill of materials",
                                      "the bill of materials for X"))

    def test_words_apart_or_out_of_order(self):
        self.assertFalse(typed_in_full("stock_move", "moves of stock"))
        self.assertFalse(typed_in_full("stock_move", "stock that moved"))
        self.assertFalse(typed_in_full("sales order", "sales by order"))
        self.assertFalse(typed_in_full("", "anything"))


def products_catalog(partner_is_hub=True):
    """
    Question 9's shape on Odoo: "contact details for customers who have
    purchased products", routed to Contacts, adds product_product and
    product_template (named, outside the domain) without a walk.

        product_product -> product_template, company
        product_template -> company
        sale_order_line -> product_product, partner, company   (the real join)
        stock_move      -> product_product, product_template, company
        mrp_bom         -> product_template, company
        t01..t20        -> company, partner (and partner is a hub too,
                           unless partner_is_hub is false)
    """
    fillers = [f"t{n:02d}" for n in range(1, 21)]
    names = ["company", "partner", "country", "product_product",
             "product_template", "sale_order_line", "stock_move",
             "mrp_bom"] + fillers
    catalog = make_catalog(
        exclude=set(NORTHWIND),
        extra_tables={f"public.{n}": ["id"] for n in names})

    def fk(a, b):
        return {"from_table": f"public.{a}", "from_columns": ("x",),
                "to_table": f"public.{b}", "to_columns": ("id",)}

    catalog.foreign_keys = (
        [fk(t, "company") for t in fillers]
        + ([fk(t, "partner") for t in fillers] if partner_is_hub else [])
        + [fk("partner", "company"), fk("partner", "country"),
           fk("product_product", "product_template"),
           fk("product_product", "company"), fk("product_template", "company"),
           fk("sale_order_line", "product_product"),
           fk("sale_order_line", "partner"), fk("sale_order_line", "company"),
           fk("stock_move", "product_product"),
           fk("stock_move", "product_template"), fk("stock_move", "company"),
           fk("mrp_bom", "product_template"), fk("mrp_bom", "company")]
    )
    return catalog


ADDED = {"public.product_product", "public.product_template"}


class LinkTables(unittest.TestCase):
    """_link_tables(): only real joins, not hubs or the added tables
    themselves."""

    def test_question_9_shape(self):
        catalog = products_catalog()
        self.assertTrue({"public.company", "public.partner"}
                        <= catalog.hub_tables())
        present = {"public.partner", "public.company", "public.country"} | ADDED
        links = catalog._link_tables(ADDED, present, matched={"public.partner"})
        # Not stock_move (product -> product_template), not mrp_bom
        # (product_template -> company), not the 20 tables that point at
        # the company: only the join to the customer.
        self.assertEqual(short(links), {"sale_order_line"})

    def test_hub_reached_only_by_the_walk_is_not_a_join(self):
        catalog = products_catalog()
        present = {"public.partner", "public.company", "public.country"} | ADDED
        # partner wasn't matched (it came in through the walk), so the only
        # targets are company (a hub) and country: nothing joins them.
        links = catalog._link_tables(ADDED, present, matched={"public.country"})
        self.assertEqual(links, set())

    def test_non_hub_target_is_always_a_join(self):
        catalog = products_catalog(partner_is_hub=False)
        self.assertNotIn("public.partner", catalog.hub_tables())
        present = {"public.partner", "public.company"} | ADDED
        self.assertEqual(short(catalog._link_tables(ADDED, present)),
                         {"sale_order_line"})

    def test_added_tables_are_not_join_targets_for_each_other(self):
        catalog = products_catalog()
        # Only the added tables and a hub: stock_move points at both added
        # tables, but that is not a join to the schema.
        present = {"public.company"} | ADDED
        self.assertEqual(catalog._link_tables(ADDED, present), set())

    def test_added_table_joined_directly_needs_no_link(self):
        catalog = products_catalog()
        catalog.foreign_keys.append(
            {"from_table": "public.product_template", "from_columns": ("x",),
             "to_table": "public.country", "to_columns": ("id",)})
        present = {"public.partner", "public.company", "public.country"} | ADDED
        # product_template joins country directly, and product_product
        # joins through product_template: nothing to link.
        self.assertEqual(catalog._link_tables(
            ADDED, present, matched={"public.partner"}), set())

    def test_northwind_territories_unchanged(self):
        catalog = make_catalog()
        self.assertEqual(catalog.hub_tables(), frozenset())
        links = catalog._link_tables({"public.territories"},
                                     {"public.territories", "public.employees",
                                      "public.orders"})
        self.assertEqual(links, {"public.employee_territories"})


def many_links_catalog(retrieval=None):
    """
    Eight genuine links between product (added) and partner (matched):
    l1..l7 have more columns the wider their number; sales_line is the
    widest but has a column the question names ("quantity").
    """
    fillers = {f"l{n}": ["id", "product_id", "partner_id"]
               + [f"c{i}" for i in range(n)] for n in range(1, 8)}
    tables = {"product": ["id"], "partner": ["id"], **fillers,
              "sales_line": ["id", "product_id", "partner_id", "quantity"]
              + [f"c{i}" for i in range(20)]}
    catalog = make_catalog(exclude=set(NORTHWIND), extra_tables={
        f"public.{n}": cols for n, cols in tables.items()})

    def fk(a, b):
        return {"from_table": f"public.{a}", "from_columns": ("x",),
                "to_table": f"public.{b}", "to_columns": ("id",)}

    catalog.foreign_keys = [fk(t, end) for t in [*fillers, "sales_line"]
                            for end in ("product", "partner")]
    with_retrieval(catalog, retrieval or {})
    return catalog


class LinkTablesCap(unittest.TestCase):
    """link_tables_max: the best matches to the question, then the
    narrowest."""

    ADDED = {"public.product"}
    PRESENT = {"public.product", "public.partner"}

    def links(self, retrieval=None, question="total quantity by partner"):
        catalog = many_links_catalog(retrieval)
        terms = catalog.question_terms(question)
        return short(catalog._link_tables(self.ADDED, self.PRESENT,
                                          matched={"public.partner"},
                                          terms=terms))

    def test_question_match_first_then_narrowest(self):
        self.assertEqual(self.links({"link_tables_max": 3}),
                         {"sales_line", "l1", "l2"})

    def test_without_a_match_the_narrowest_win(self):
        self.assertEqual(self.links({"link_tables_max": 3}, question="show"),
                         {"l1", "l2", "l3"})

    def test_shipped_default_is_five(self):
        self.assertEqual(RelationshipWalk().link_tables_max, 5)
        self.assertEqual(load_settings(environ={}).retrieval.relationships
                         .link_tables_max, 5)
        self.assertEqual(len(self.links()), 5)

    def test_zero_is_no_limit(self):
        self.assertEqual(len(self.links({"link_tables_max": 0})), 8)

    def test_under_the_cap_keeps_all(self):
        self.assertEqual(len(self.links({"link_tables_max": 8})), 8)

    def log(self, verbose):
        import io
        from contextlib import redirect_stdout
        from unittest import mock
        from sqlagent.settings import get_settings
        out = io.StringIO()
        with redirect_stdout(out), \
             mock.patch.object(get_settings().llm, "verbose", verbose):
            self.links({"link_tables_max": 2})
        return out.getvalue()

    def test_log_names_only_the_kept(self):
        log = self.log(False)
        self.assertIn("(2 of 8): l1, sales_line", log)
        self.assertNotIn("dropped", log)
        self.assertNotIn("(6)", log)

    def test_verbose_log_lists_kept_and_dropped_with_scores(self):
        log = self.log(True)
        self.assertIn("(2 of 8): sales_line (6), l1 (3); dropped: l2 (3)", log)

    def test_database_override(self):
        model = model_from(**{"r.yaml": "retrieval: {link_tables_max: 2}"})
        self.assertEqual(model.retrieval["link_tables_max"], 2)
        with self.assertRaises(SemanticModelError):
            model_from(**{"r.yaml": "retrieval: {link_tables_max: -1}"})


class WeakMatch(unittest.TestCase):
    """No table named in full: the fallback tables plus the best few weak
    matches, without a relationship walk (weak_match_tables)."""

    def tables(self, question, retrieval=None, fallbacks=("public.employees",)):
        catalog = make_catalog()
        with_retrieval(catalog, retrieval or {})
        if not fallbacks:
            catalog.fallback_table_names = set()   # no global list either
        scope = (set(catalog.tables), list(fallbacks), 1)
        return tables_in(catalog.discover_schema(question, scope=scope))

    def test_weak_match_is_not_walked(self):
        # "freight" is only a column of orders. A walk from orders would
        # bring customers, shippers and order_details.
        self.assertEqual(self.tables("total freight this year"),
                         {"employees", "orders"})

    def test_only_the_best_few_weak_matches(self):
        # "cities" is a column word of four tables (3 points each): with a
        # limit of 1 the first is kept, and orders joins it to employees.
        self.assertEqual(self.tables("which cities?", {"weak_match_tables": 1}),
                         {"customers", "employees", "orders"})

    def test_zero_keeps_every_weak_match(self):
        self.assertEqual(self.tables("which cities?", {"weak_match_tables": 0}),
                         {"customers", "employees", "orders", "suppliers"})

    def test_without_any_fallback_tables_the_walk_is_unchanged(self):
        tables = self.tables("total freight this year", fallbacks=())
        self.assertIn("shippers", tables)
        self.assertIn("order_details", tables)

    def test_named_table_still_walks(self):
        self.assertIn("territories", self.tables("list each region"))

    def test_shipped_default_is_three(self):
        self.assertEqual(RelationshipWalk().weak_match_tables, 3)
        self.assertEqual(load_settings(environ={}).retrieval.relationships
                         .weak_match_tables, 3)

    def test_database_override(self):
        model = model_from(**{"r.yaml": "retrieval: {weak_match_tables: 1}"})
        self.assertEqual(model.retrieval["weak_match_tables"], 1)


class OdooSalespeople(unittest.TestCase):
    """"Which salespeople generated the most revenue this year?" named no
    table: "salespeople" isn't a form of the salesperson alias."""

    def test_salespeople_names_res_users(self):
        from sqlagent.adaptive.text_match import phrase_matches, tokenize
        model = load_semantic_model(ODOO_SEMANTIC_PATH)
        users = model.tables["public.res_users"]
        aliases = users["aliases"] if isinstance(users, dict) else users.aliases
        terms = tokenize("Which salespeople generated the most revenue this year?")
        self.assertTrue(any(phrase_matches(a, terms) for a in aliases))
        terms = tokenize("top sales people")
        self.assertTrue(any(phrase_matches(a, terms) for a in aliases))


class OnlyAHubIsNamed(unittest.TestCase):
    """"Which salespeople generated the most revenue this year?" on Odoo:
    "salespeople" names res_users, a hub, which the walk doesn't go back
    from - so the best other match (sale_order, on its revenue column) is
    kept too."""

    QUESTION = "Which salespeople generated the most revenue this year?"

    def catalog(self, users_is_hub=True):
        fillers = [f"t{n:02d}" for n in range(1, 21)]
        tables = {"res_users": ["id", "partner_id", "login"],
                  "res_partner": ["id", "name"],
                  "sale_order": ["id", "user_id", "partner_id",
                                 "revenue_total", "date_order"],
                  "sale_order_line": ["id", "order_id"]}
        tables.update({t: ["id", "create_uid"] for t in fillers})
        catalog = make_catalog(exclude=set(NORTHWIND), extra_tables={
            f"public.{n}": cols for n, cols in tables.items()})
        catalog.tables["public.res_users"]["aliases"] = ["salesperson", "salespeople"]

        def fk(a, b):
            return {"from_table": f"public.{a}", "from_columns": ("x",),
                    "to_table": f"public.{b}", "to_columns": ("id",)}

        catalog.foreign_keys = (
            ([fk(t, "res_users") for t in fillers] if users_is_hub else [])
            + [fk("sale_order", "res_users"), fk("sale_order", "res_partner"),
               fk("sale_order_line", "sale_order"),
               fk("res_users", "res_partner")])
        with_retrieval(catalog, {})
        return catalog

    def tables(self, catalog):
        scope = ({"public.sale_order", "public.sale_order_line",
                  "public.res_partner", "public.res_users"},
                 ["public.sale_order", "public.sale_order_line",
                  "public.res_partner"], 1)
        return tables_in(catalog.discover_schema(self.QUESTION, scope=scope))

    def test_best_other_match_is_kept(self):
        catalog = self.catalog()
        self.assertIn("public.res_users", catalog.hub_tables())
        tables = self.tables(catalog)
        self.assertTrue({"res_users", "sale_order", "res_partner",
                         "sale_order_line"} <= tables)
        self.assertNotIn("t01", tables)

    def test_a_named_non_hub_is_unchanged(self):
        # res_users not a hub: the walk goes back to sale_order anyway.
        tables = self.tables(self.catalog(users_is_hub=False))
        self.assertTrue({"res_users", "sale_order"} <= tables)


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
