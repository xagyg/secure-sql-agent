# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Tests for the semantic model (semantic_model.py) and how the catalog
# uses it: discovery patterns, labels, declared (composite) relationships,
# terms and diagnostics. No database or LLM needed.
#
#     python -m unittest tests.test_semantic_model -v

import tempfile
import textwrap
import unittest
from pathlib import Path

from sqlagent.adaptive.semantic_model import (
    SemanticModelError,
    load_semantic_model,
    parse_endpoint,
)
from sqlagent.execution.sql_diagnostics import get_column_alias
from tests.fixtures import NORTHWIND, make_catalog


def write_files(folder, files):
    for name, text in files.items():
        Path(folder, name).write_text(textwrap.dedent(text), encoding="utf-8")


def model_from(**files):
    """Load a semantic model from YAML strings, one per file name."""
    with tempfile.TemporaryDirectory() as folder:
        write_files(folder, files)
        return load_semantic_model(folder)


# A small ERP: cryptic names, no foreign keys, a view with a flag.
ERP_TABLES = {
    "erp.cust_mst": ["cm_id", "cm_name", "cm_cr_lim", "cm_tax_no"],
    "erp.so_hdr": ["company_id", "order_no", "cm_id", "salesperson_id", "order_dt"],
    "erp.so_line": ["company_id", "order_no", "line_no", "item_code", "qty"],
    "semantic.employees_v": ["employee_id", "first_name", "last_name",
                             "end_date", "enabled", "is_terminated"],
}

ERP_MODEL = """
    version: 1
    sources:
      include: ["erp.*", "semantic.*"]
      exclude: ["erp.audit_*"]
      use_database_foreign_keys: false

    tables:
      erp.cust_mst:
        label: customers
        aliases: [client]
        description: customer master
        columns:
          cm_cr_lim: {label: credit_limit, aliases: [credit]}
          cm_name:   {label: customer_name}
      erp.so_hdr:
        label: sales_orders
      erp.so_line:
        label: sales_order_lines
        aliases: [line_item]

    relationships:
      - from: erp.so_line(company_id, order_no)
        to:   erp.so_hdr(company_id, order_no)
        cardinality: many_to_one
      - from: erp.so_hdr(cm_id)
        to:   erp.cust_mst(cm_id)
      - from: erp.so_hdr(salesperson_id)
        to:   semantic.employees_v(employee_id)
      - from: erp.so_hdr(no_such_column)
        to:   erp.cust_mst(cm_id)

    terms:
      terminated:
        table: semantic.employees_v
        column: is_terminated
        aliases: [former_employee, ex_employee]
        description: left the company or account disabled
      big_order:
        table: erp.so_line
        predicate: qty >= 100
      sneaky:
        table: erp.so_line
        predicate: qty > (SELECT max(cm_cr_lim) FROM erp.cust_mst)
      uses_hidden_column:
        table: erp.cust_mst
        predicate: cm_secret > 0
"""


def erp_catalog(exclude_tables=(), drop_columns=None):
    """The ERP catalog. exclude_tables / drop_columns act like security
    filtering (a table or column the role can't see is never loaded)."""
    extra = {
        name: [c for c in cols if c not in (drop_columns or {}).get(name, ())]
        for name, cols in ERP_TABLES.items()
        if name not in exclude_tables
    }
    return make_catalog(
        exclude=set(NORTHWIND),   # an ERP-only database
        semantic=model_from(**{"erp.yaml": ERP_MODEL}),
        extra_tables=extra,
    )


def tables_in(schema):
    return {line.split()[1] for line in schema.splitlines() if line.startswith("TABLE ")}


class Loading(unittest.TestCase):

    def test_shipped_model_loads(self):
        model = load_semantic_model()
        self.assertIn("public.employees", model.tables)
        self.assertIn("sales", model.domains)
        self.assertEqual(model.include, ("public.*",))

    def test_sub_folders_are_not_read(self):
        # config/semantic/erp/ next to config/semantic/northwind/ must
        # never be merged into either.
        with tempfile.TemporaryDirectory() as folder:
            write_files(folder, {"model.yaml": "tables: {customers: {aliases: [client]}}"})
            Path(folder, "erp").mkdir()
            write_files(Path(folder, "erp"), {"model.yaml": "tables: {erp.x: {label: x}}"})
            model = load_semantic_model(folder)
        self.assertEqual(set(model.tables), {"public.customers"})

    def test_default_paths_are_per_database(self):
        from sqlagent.adaptive.semantic_model import DEFAULT_SEMANTIC_PATH
        from sqlagent.controls.security_policy import DEFAULT_SECURITY_FILE
        self.assertEqual(DEFAULT_SEMANTIC_PATH.parts[-2:], ("semantic", "northwind"))
        self.assertEqual(DEFAULT_SECURITY_FILE.parts[-2:], ("security", "northwind.yaml"))
        self.assertTrue((DEFAULT_SEMANTIC_PATH / "model.yaml").is_file())
        self.assertTrue((DEFAULT_SEMANTIC_PATH / "domains.yaml").is_file())
        self.assertTrue(DEFAULT_SECURITY_FILE.is_file())

    def test_missing_path_gives_empty_model(self):
        model = load_semantic_model("/no/such/folder")
        self.assertEqual(model.tables, {})
        self.assertTrue(model.discovers("anything.at_all"))

    def test_unknown_key_is_an_error(self):
        with self.assertRaises(SemanticModelError) as ctx:
            model_from(**{"a.yaml": """
                tables:
                  public.customers:
                    alias: [client]
            """})
        self.assertIn("alias", str(ctx.exception))

    def test_duplicate_yaml_key_is_an_error(self):
        with self.assertRaises(SemanticModelError):
            model_from(**{"a.yaml": """
                tables:
                  public.customers: {aliases: [client]}
                  public.customers: {aliases: [buyer]}
            """})

    def test_table_defined_in_two_files_is_an_error(self):
        with self.assertRaises(SemanticModelError) as ctx:
            model_from(**{
                "a.yaml": "tables: {customers: {aliases: [client]}}",
                "b.yaml": "tables: {public.customers: {aliases: [buyer]}}",
            })
        self.assertIn("more than once", str(ctx.exception))

    def test_sources_defined_twice_is_an_error(self):
        with self.assertRaises(SemanticModelError):
            model_from(**{
                "a.yaml": "sources: {include: ['public.*']}",
                "b.yaml": "sources: {include: ['erp.*']}",
            })

    def test_files_are_merged(self):
        model = model_from(**{
            "a.yaml": "tables: {customers: {aliases: [client]}}",
            "b.yaml": "tables: {suppliers: {aliases: [vendor]}}",
        })
        self.assertEqual(set(model.tables), {"public.customers", "public.suppliers"})

    def test_relationship_column_counts_must_match(self):
        with self.assertRaises(SemanticModelError):
            model_from(**{"a.yaml": """
                relationships:
                  - from: erp.a(x, y)
                    to:   erp.b(x)
            """})

    def test_term_needs_exactly_one_definition(self):
        with self.assertRaises(SemanticModelError):
            model_from(**{"a.yaml": """
                terms:
                  late: {table: orders, column: is_late, predicate: "a > b"}
            """})

    def test_parse_endpoint(self):
        self.assertEqual(parse_endpoint("erp.so_line(company_id, order_no)"),
                         ("erp.so_line", ("company_id", "order_no")))
        self.assertEqual(parse_endpoint("orders(order_id)"),
                         ("public.orders", ("order_id",)))
        with self.assertRaises(ValueError):
            parse_endpoint("erp.so_line")


class Discovery(unittest.TestCase):

    def test_include_and_exclude(self):
        model = model_from(**{"erp.yaml": ERP_MODEL})
        self.assertTrue(model.discovers("erp.cust_mst"))
        self.assertTrue(model.discovers("SEMANTIC.Employees_V"))
        self.assertFalse(model.discovers("erp.audit_log"))
        self.assertFalse(model.discovers("public.customers"))

    def test_bare_pattern_is_in_public(self):
        model = model_from(**{"a.yaml": "sources: {include: ['*']}"})
        self.assertTrue(model.discovers("public.orders"))
        self.assertFalse(model.discovers("erp.orders"))

    def test_star_dot_star_is_everything(self):
        model = model_from(**{"a.yaml": "sources: {include: ['*.*']}"})
        self.assertTrue(model.discovers("erp.orders"))


class Labels(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.catalog = erp_catalog()

    def test_label_finds_cryptic_table(self):
        matches = self.catalog.search("which customers have the biggest credit limit?")
        self.assertEqual(matches[0][1]["name"], "cust_mst")

    def test_label_and_description_shown_to_model(self):
        context = self.catalog._format_context({"erp.cust_mst"})
        self.assertIn("TABLE erp.cust_mst  -- customers: customer master", context)
        self.assertIn("cm_cr_lim text NULL  -- credit limit  (aka: credit)", context)

    def test_column_label_maps_back_in_diagnostics(self):
        semantic = self.catalog.semantic
        self.assertEqual(get_column_alias("erp.cust_mst", "credit_limit", semantic), "cm_cr_lim")
        self.assertEqual(get_column_alias("erp.cust_mst", "credit", semantic), "cm_cr_lim")
        self.assertEqual(
            get_column_alias("semantic.employees_v", "terminated", semantic), "is_terminated")
        self.assertIsNone(get_column_alias("erp.so_hdr", "credit", semantic))


class Relationships(unittest.TestCase):

    def test_composite_relationship(self):
        catalog = erp_catalog()
        rel = next(r for r in catalog.foreign_keys if r["from_table"] == "erp.so_line")
        self.assertEqual(rel["from_columns"], ("company_id", "order_no"))
        self.assertEqual(rel["source"], "declared")
        context = catalog._format_context({"erp.so_line", "erp.so_hdr"})
        self.assertIn(
            "erp.so_line(company_id, order_no) -> erp.so_hdr(company_id, order_no) "
            "(many-to-one)", context)

    def test_relationship_walk_uses_declared_joins(self):
        catalog = erp_catalog()
        related = catalog.get_related_tables({"erp.so_line"}, depth=2)
        self.assertEqual(related, {"erp.so_line", "erp.so_hdr", "erp.cust_mst",
                                   "semantic.employees_v"})

    def test_relationship_with_unknown_column_is_skipped(self):
        catalog = erp_catalog()
        self.assertFalse(any("no_such_column" in r["from_columns"]
                             for r in catalog.foreign_keys))

    def test_relationship_to_hidden_table_is_skipped(self):
        catalog = erp_catalog(exclude_tables={"semantic.employees_v"})
        self.assertFalse(any(r["to_table"] == "semantic.employees_v"
                             for r in catalog.foreign_keys))

    def test_relationship_on_denied_column_is_skipped(self):
        # salesperson_id hidden from the role: the join must not reveal it.
        catalog = erp_catalog(drop_columns={"erp.so_hdr": ["salesperson_id"]})
        self.assertFalse(any("salesperson_id" in r["from_columns"]
                             for r in catalog.foreign_keys))

    def test_database_keys_keep_original_format(self):
        catalog = make_catalog()
        context = catalog._format_context({"public.orders", "public.customers"})
        self.assertIn("  - public.orders.customer_id -> public.customers.customer_id",
                      context)


class Terms(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.catalog = erp_catalog()

    def term_names(self, table):
        return {t["name"] for t in self.catalog.tables[table]["terms"]}

    def test_column_term(self):
        self.assertEqual(self.term_names("semantic.employees_v"), {"terminated"})
        context = self.catalog._format_context({"semantic.employees_v"})
        self.assertIn("TERMS", context)
        self.assertIn("terminated, former employee, ex employee: "
                      "semantic.employees_v WHERE is_terminated is true", context)

    def test_term_finds_its_table(self):
        matches = self.catalog.search("list the terminated staff")
        self.assertEqual(matches[0][1]["name"], "employees_v")

    def test_predicate_term(self):
        self.assertEqual(self.term_names("erp.so_line"), {"big_order"})
        context = self.catalog._format_context({"erp.so_line"})
        self.assertIn("big order: erp.so_line WHERE qty >= 100", context)

    def test_predicate_with_subquery_is_rejected(self):
        self.assertNotIn("sneaky", self.term_names("erp.so_line"))

    def test_predicate_on_unloaded_column_is_rejected(self):
        self.assertNotIn("uses_hidden_column", self.term_names("erp.cust_mst"))

    def test_term_on_hidden_column_is_skipped(self):
        catalog = erp_catalog(drop_columns={"semantic.employees_v": ["is_terminated"]})
        self.assertEqual(catalog.tables["semantic.employees_v"]["terms"], [])

    def test_shipped_northwind_term(self):
        catalog = make_catalog()
        matches = catalog.search("which orders shipped late?")
        self.assertEqual(matches[0][1]["name"], "orders")


if __name__ == "__main__":
    unittest.main()
