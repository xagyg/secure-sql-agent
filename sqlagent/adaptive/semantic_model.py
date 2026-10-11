# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# The semantic model: what the data MEANS, kept in YAML next to the code
# (config/semantic/northwind/ by default, or SQLAGENT_SEMANTIC_PATH).
# One folder per database.
#
# The database says what exists (tables, views, columns). The semantic
# model adds what it doesn't say, which on an ERP is most of it:
#
#   sources        Which tables and views to discover ("erp.*"), and
#                  which to leave out ("erp.audit_*").
#   tables         Per table: a business label ("cust_mst" -> customers),
#                  aliases (other words people use), a description, and
#                  the same for its columns.
#   relationships  Joins the database has no foreign keys for, including
#                  composite keys and cardinality.
#   terms          Words that pick ROWS rather than a table or a column
#                  ("terminated", "shipped late"): a boolean column (best,
#                  usually from a view) or a SQL condition.
#   domains        Domains of Discourse (see domains.py), with their role
#                  and function-code vocabularies.
#   fallback_tables  Tables used when a question names no table.
#
# Nothing here grants access. The model is applied to the catalog AFTER
# security filtering, so a label, alias, relationship or term on a table
# or column the role can't see is skipped and never shown. Access is
# decided only by the security policy, config/security/<database>.yaml
# (controls/security_policy.py).
#
# Loading rules:
#   - A path can be one YAML file or a folder of them (merged; e.g. one
#     file per domain so each area's owners review their own file).
#   - A structural error (unknown key, wrong type, a name defined twice)
#     stops startup with the file and the offending key.
#   - A name that doesn't exist in the database is skipped with a log
#     line at startup, as before.
#   - No file at all means an empty model: discovery only, no vocabulary.

import fnmatch
import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, ValidationError, model_validator

from sqlagent.config_files import (
    CONFIG_DIR,
    DEFAULT_DATABASE,
    ConfigFileError,
    format_validation_error,
    load_yaml,
)
from sqlagent.controls.security_utils import full_table_name


DEFAULT_SEMANTIC_PATH = CONFIG_DIR / "semantic" / DEFAULT_DATABASE

# Discover everything (the behaviour before the semantic model existed).
INCLUDE_EVERYTHING = ("*.*",)


class SemanticModelError(ConfigFileError):
    """The semantic model files are invalid. Startup should stop."""


# ---------------------------------------------------------------------------
# File structure (validated with pydantic; unknown keys are errors, so a
# typo such as "alias:" fails loudly instead of being ignored)
# ---------------------------------------------------------------------------

class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


def _words(values):
    """Aliases and phrases are matched case-insensitively."""
    return [v.strip().lower() for v in values if v and v.strip()]


# A list of words or phrases ("sales_rep" or "sales rep"), lowercased.
Words = Annotated[list[str], AfterValidator(_words)]


class ColumnSpec(_Strict):
    label: str | None = None
    aliases: Words = []
    description: str | None = None


class TableSpec(_Strict):
    label: str | None = None
    aliases: Words = []
    description: str | None = None
    columns: dict[str, ColumnSpec] = {}


_ENDPOINT = re.compile(r"^\s*([A-Za-z0-9_.$]+)\s*\(\s*([^()]+?)\s*\)\s*$")


def parse_endpoint(text):
    """
    "erp.order_lines(company_id, order_no)" -> ("erp.order_lines",
    ("company_id", "order_no")). A bare table name is put in the default
    schema, as everywhere else.
    """
    match = _ENDPOINT.match(text or "")
    if not match:
        raise ValueError(
            f"{text!r} is not of the form schema.table(column[, column...])")
    columns = tuple(c.strip() for c in match.group(2).split(","))
    if not all(columns):
        raise ValueError(f"{text!r} has an empty column name")
    return full_table_name(match.group(1)), columns


class RelationshipSpec(_Strict):
    from_: str = Field(alias="from")
    to: str
    cardinality: Literal["many_to_one", "one_to_one", "one_to_many"] = "many_to_one"
    description: str | None = None

    @model_validator(mode="after")
    def _check(self):
        _, from_cols = parse_endpoint(self.from_)
        _, to_cols = parse_endpoint(self.to)
        if len(from_cols) != len(to_cols):
            raise ValueError(
                f"'{self.from_}' and '{self.to}' have different numbers of columns")
        return self


class TermSpec(_Strict):
    table: str
    column: str | None = None       # a boolean column, e.g. from a view
    predicate: str | None = None    # a SQL condition on the table's columns
    aliases: Words = []
    description: str | None = None

    @model_validator(mode="after")
    def _one_definition(self):
        if bool(self.column) == bool(self.predicate):
            raise ValueError("give exactly one of 'column' or 'predicate'")
        return self


class DomainSpec(_Strict):
    label: str
    aliases: Words = []
    tables: list[str]
    roles: dict[str, float] = {}
    where: Words = []
    hops: int = Field(default=1, ge=0, le=3)
    fallback_tables: list[str] = []


class SourcesSpec(_Strict):
    include: list[str] = list(INCLUDE_EVERYTHING)
    exclude: list[str] = []
    use_database_foreign_keys: bool = True


class SemanticFile(_Strict):
    version: Literal[1] = 1
    sources: SourcesSpec | None = None
    fallback_tables: list[str] | None = None
    tables: dict[str, TableSpec] = {}
    relationships: list[RelationshipSpec] = []
    terms: dict[str, TermSpec] = {}
    domains: dict[str, DomainSpec] = {}
    role_aliases: dict[str, Words] = {}
    function_aliases: dict[str, Words] = {}


# ---------------------------------------------------------------------------
# The loaded model, as used by the catalog, routing and diagnostics
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Relationship:
    from_table: str
    from_columns: tuple
    to_table: str
    to_columns: tuple
    cardinality: str = "many_to_one"
    description: str | None = None


@dataclass(frozen=True)
class Term:
    name: str
    table: str
    column: str | None
    predicate: str | None
    aliases: tuple
    description: str | None

    @property
    def phrases(self):
        return (self.name,) + self.aliases


def _pattern(text):
    """A discovery pattern on "schema.table", lowercase. A pattern with no
    schema is in the default schema, like a bare table name."""
    return full_table_name(text.strip()).lower()


@dataclass
class SemanticModel:
    include: tuple = INCLUDE_EVERYTHING
    exclude: tuple = ()
    use_database_foreign_keys: bool = True
    fallback_tables: tuple = ()
    tables: dict = field(default_factory=dict)          # full name (lower) -> TableSpec
    relationships: list = field(default_factory=list)   # Relationship
    terms: dict = field(default_factory=dict)           # name -> Term
    domains: dict = field(default_factory=dict)         # key -> dict (see domains.py)
    role_aliases: dict = field(default_factory=dict)    # role -> set of names
    function_aliases: dict = field(default_factory=dict)  # code -> set of names
    sources: tuple = ()                                 # files it was loaded from

    @classmethod
    def empty(cls):
        return cls()

    # -- discovery -----------------------------------------------------

    def discovers(self, full_name):
        """True if the table/view is in sources.include and not in
        sources.exclude (fnmatch patterns on "schema.table")."""
        name = full_name.lower()
        included = any(fnmatch.fnmatchcase(name, _pattern(p)) for p in self.include)
        excluded = any(fnmatch.fnmatchcase(name, _pattern(p)) for p in self.exclude)
        return included and not excluded

    # -- lookup --------------------------------------------------------

    def table_spec(self, full_name):
        return self.tables.get(full_name.lower())

    def column_spec(self, full_name, column):
        spec = self.table_spec(full_name)
        if spec is None:
            return None
        wanted = column.lower()
        return next(
            (c for name, c in spec.columns.items() if name.lower() == wanted),
            None,
        )

    def physical_column_for(self, full_name, word):
        """
        The column on this table that `word` is another name for: a
        column label or alias, or a column term ("terminated" ->
        is_terminated). Used by sql_diagnostics when the model writes a
        business word as if it were a column. Reads the unfiltered model
        on purpose, so a denied column can be reported as restricted
        rather than as missing.
        """
        spec = self.table_spec(full_name)
        wanted = word.strip().lower()
        if spec is not None:
            for name, column in spec.columns.items():
                names = set(column.aliases)
                if column.label:
                    names.add(column.label.strip().lower().replace(" ", "_"))
                if wanted in names or wanted.replace(" ", "_") in names:
                    return name
        for term in self.terms.values():
            if term.column and term.table.lower() == full_name.lower() \
                    and wanted in term.phrases:
                return term.column
        return None


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def _files(path):
    path = Path(path)
    if path.is_dir():
        return sorted(p for p in path.iterdir()
                      if p.suffix.lower() in (".yaml", ".yml") and p.is_file())
    return [path]


def _set_once(target, key, value, where, what):
    if key in target:
        raise SemanticModelError(f"{where}: {what} '{key}' is defined more than once")
    target[key] = value


def load_semantic_model(path=None):
    """
    Load the semantic model from a YAML file or a folder of YAML files.
    path defaults to SQLAGENT_SEMANTIC_PATH, then config/semantic/northwind/.
    Only the files directly in the folder are read, so another
    database's folder alongside it is never merged in. A
    missing path gives an empty model (logged). Invalid files raise
    SemanticModelError.
    """
    if path is None:
        path = os.environ.get("SQLAGENT_SEMANTIC_PATH") or DEFAULT_SEMANTIC_PATH
    path = Path(path)

    if not path.exists():
        print(f"[semantic] No semantic model at {path} - "
              "discovering every table, no business vocabulary")
        return SemanticModel.empty()

    files = _files(path)
    model = SemanticModel(sources=tuple(str(f) for f in files))
    seen_sources = seen_fallback = None
    tables, terms, domains, role_aliases, function_aliases = {}, {}, {}, {}, {}

    for file in files:
        try:
            data = load_yaml(file)
        except ConfigFileError as ex:
            raise SemanticModelError(str(ex)) from ex
        try:
            parsed = SemanticFile.model_validate(data)
        except ValidationError as ex:
            raise SemanticModelError(format_validation_error(file, ex)) from ex

        if parsed.sources is not None:
            if seen_sources:
                raise SemanticModelError(
                    f"{file}: 'sources' is already defined in {seen_sources}")
            seen_sources = file
            model.include = tuple(parsed.sources.include)
            model.exclude = tuple(parsed.sources.exclude)
            model.use_database_foreign_keys = parsed.sources.use_database_foreign_keys

        if parsed.fallback_tables is not None:
            if seen_fallback:
                raise SemanticModelError(
                    f"{file}: 'fallback_tables' is already defined in {seen_fallback}")
            seen_fallback = file
            model.fallback_tables = tuple(parsed.fallback_tables)

        for name, spec in parsed.tables.items():
            _set_once(tables, full_table_name(name).lower(), spec, file, "table")

        for spec in parsed.relationships:
            from_table, from_cols = parse_endpoint(spec.from_)
            to_table, to_cols = parse_endpoint(spec.to)
            model.relationships.append(Relationship(
                from_table, from_cols, to_table, to_cols,
                spec.cardinality, spec.description))

        for name, spec in parsed.terms.items():
            term = Term(
                name=name.strip().lower(),
                table=full_table_name(spec.table),
                column=spec.column,
                predicate=spec.predicate,
                aliases=tuple(spec.aliases),
                description=spec.description,
            )
            _set_once(terms, term.name, term, file, "term")

        for key, spec in parsed.domains.items():
            _set_once(domains, key.lower(), {
                "label": spec.label,
                "aliases": set(spec.aliases),
                "tables": set(spec.tables),
                "roles": {r.lower(): v for r, v in spec.roles.items()},
                "where": set(spec.where),
                "hops": spec.hops,
                "fallback_tables": tuple(spec.fallback_tables),
            }, file, "domain")

        for role, names in parsed.role_aliases.items():
            _set_once(role_aliases, role.lower(), set(_words(names)), file, "role alias")

        for code, names in parsed.function_aliases.items():
            _set_once(function_aliases, code.upper(), set(_words(names)),
                      file, "function alias")

    model.tables = tables
    model.terms = terms
    model.domains = domains
    model.role_aliases = role_aliases
    model.function_aliases = function_aliases

    print(f"[semantic] Loaded {len(files)} file(s) from {path}: "
          f"{len(tables)} table(s), {len(model.relationships)} relationship(s), "
          f"{len(terms)} term(s), {len(domains)} domain(s)")
    return model


@lru_cache(maxsize=1)
def default_semantic_model():
    """The model at the default path, loaded once per process."""
    return load_semantic_model()
