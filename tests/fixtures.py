# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Shared test fixtures: a static copy of the Northwind (Postgres) schema
# and a SchemaCatalog built from it, so tests need no database. The
# customers.phone and employees.home_phone columns are left out, as the
# demo role's security-filtered catalog does. The semantic model is the
# real one in config/semantic/northwind/, so the tests cover the shipped vocabulary.

from sqlagent.adaptive.domains import DomainResolver
from sqlagent.adaptive.schema_catalog import SchemaCatalog


NORTHWIND = {
    "categories": ["category_id", "category_name", "description", "picture"],
    "customer_customer_demo": ["customer_id", "customer_type_id"],
    "customer_demographics": ["customer_type_id", "customer_desc"],
    "customers": ["customer_id", "company_name", "contact_name", "contact_title",
                  "address", "city", "region", "postal_code", "country", "fax"],
    "employees": ["employee_id", "last_name", "first_name", "title",
                  "title_of_courtesy", "birth_date", "hire_date", "address",
                  "city", "region", "postal_code", "country", "extension",
                  "photo", "notes", "reports_to", "photo_path"],
    "employee_territories": ["employee_id", "territory_id"],
    "order_details": ["order_id", "product_id", "unit_price", "quantity", "discount"],
    "orders": ["order_id", "customer_id", "employee_id", "order_date",
               "required_date", "shipped_date", "ship_via", "freight",
               "ship_name", "ship_address", "ship_city", "ship_region",
               "ship_postal_code", "ship_country"],
    "products": ["product_id", "product_name", "supplier_id", "category_id",
                 "quantity_per_unit", "unit_price", "units_in_stock",
                 "units_on_order", "reorder_level", "discontinued"],
    "region": ["region_id", "region_description"],
    "shippers": ["shipper_id", "company_name", "phone"],
    "suppliers": ["supplier_id", "company_name", "contact_name", "contact_title",
                  "address", "city", "region", "postal_code", "country",
                  "phone", "fax", "homepage"],
    "territories": ["territory_id", "territory_description", "region_id"],
}

FKS = [
    ("customer_customer_demo", "customer_id", "customers", "customer_id"),
    ("customer_customer_demo", "customer_type_id", "customer_demographics", "customer_type_id"),
    ("employee_territories", "employee_id", "employees", "employee_id"),
    ("employee_territories", "territory_id", "territories", "territory_id"),
    ("employees", "reports_to", "employees", "employee_id"),
    ("order_details", "order_id", "orders", "order_id"),
    ("order_details", "product_id", "products", "product_id"),
    ("orders", "customer_id", "customers", "customer_id"),
    ("orders", "employee_id", "employees", "employee_id"),
    ("orders", "ship_via", "shippers", "shipper_id"),
    ("products", "category_id", "categories", "category_id"),
    ("products", "supplier_id", "suppliers", "supplier_id"),
    ("territories", "region_id", "region", "region_id"),
]


def make_catalog(exclude=(), semantic=None, extra_tables=None):
    """A SchemaCatalog loaded from the static schema. `exclude` drops
    tables, as if the role weren't authorised for them. `semantic`
    replaces the default semantic model; `extra_tables` adds tables as
    {"schema.table": [columns]}."""
    catalog = SchemaCatalog(connection_factory=None, security=None,
                            semantic=semantic)
    catalog.tables = {
        f"public.{name}": {
            "schema": "public",
            "name": name,
            "columns": [{"name": c, "type": "text", "nullable": True} for c in cols],
        }
        for name, cols in NORTHWIND.items()
        if name not in exclude
    }
    for full_name, cols in (extra_tables or {}).items():
        schema, name = full_name.split(".", 1)
        catalog.tables[full_name] = {
            "schema": schema,
            "name": name,
            "columns": [{"name": c, "type": "text", "nullable": True} for c in cols],
        }
    catalog._attach_semantics()
    catalog.foreign_keys = catalog._build_relationships([
        {"from_table": f"public.{a}", "from_columns": (b,),
         "to_table": f"public.{c}", "to_columns": (d,),
         "cardinality": None, "source": "database"}
        for a, b, c, d in FKS
        if a not in exclude and c not in exclude
    ])
    catalog.fallback_schema = catalog._build_fallback_schema()
    catalog.domain_resolver = DomainResolver(catalog)
    return catalog
