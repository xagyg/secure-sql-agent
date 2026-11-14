# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# The catalog queries themselves (columns, foreign keys) are the database
# engine's (sqlagent/execution/engines/), which returns rows as dicts with
# lowercase keys whatever the driver, so this module is engine-neutral.
#
# Load order (refresh):
#   1. Discover tables and views: the semantic model's sources.include /
#      exclude, then the SecurityContext (unauthorised tables and denied
#      columns are never loaded).
#   2. Attach the semantic model (labels, aliases, terms) to what was
#      loaded. Vocabulary for anything that wasn't loaded is skipped, so
#      it can't reveal a hidden table or column.
#   3. Relationships: the database's foreign keys (if enabled) plus the
#      semantic model's declared relationships, each kept only when both
#      tables and every column are in the loaded catalog.
#   4. Fallback schema and Domains of Discourse, from the semantic model.
#
# The vocabulary that used to be defined here (TABLE_ALIASES, COLUMN_ALIASES,
# DEFAULT_FALLBACK_TABLES) now lives in config/databases/<database>/semantic/
# (see semantic_model.py).

from contextlib import closing

from sqlagent.adaptive.domains import DomainResolver
from sqlagent.adaptive.semantic_model import default_semantic_model
from sqlagent.execution.engines import active_dialect, active_engine
from sqlagent.controls.security_utils import (
    contains_case_insensitive,
    full_table_name,
    get_denied_columns,
    is_authorized_table,
)
from sqlagent.adaptive.text_match import (
    ALIAS_MATCH,
    COLUMN_MATCH,
    FULL_NAME_MATCH,
    GENERIC_TERMS,
    PARTIAL_NAME_MATCH,
    TERM_MATCH,
    correct_words,
    fuzzy_available,
    word_frequency_available,
    phrase_matches,
    phrase_parts,
    tokenize,
    words,
)
from sqlagent.settings import get_settings


# json/jsonb columns get JSON_NOTE in the schema shown to the model, unless
# their description already explains how to read them (_json_note).
JSON_TYPES = ("json", "jsonb")
JSON_NOTE = "JSON: not plain text or a number"

_warned_no_fuzzy = False
_warned_no_wordfreq = False


def _warn_no_fuzzy():
    """Say once that typo correction is on but can't run."""
    global _warned_no_fuzzy
    _warned_no_fuzzy = True
    print("[schema] Typo correction is enabled but rapidfuzz is not "
          "installed - matching stays exact (pip install -r requirements.txt)")


def _warn_no_wordfreq():
    """Say once that the common-word check is on but can't run."""
    global _warned_no_wordfreq
    _warned_no_wordfreq = True
    print("[schema] Typo correction: wordfreq is not installed, so real "
          "English words may be 'corrected' (pip install -r requirements.txt)")


class EmptyCatalogError(RuntimeError):
    """
    The catalog loaded no tables, so the agent would have nothing to
    ground the model in. Startup stops instead of letting the model guess
    a schema (the authorisation check would block the guess, but a user
    would only ever see "restricted").
    """


def _words_of(name):
    """A label or phrase for display: "credit_limit" -> "credit limit"."""
    return name.replace("_", " ").strip()


class SchemaCatalog:

    def __init__(self, connection_factory, security=None, semantic=None,
                 fallback_tables=None, engine=None):
        self.connection_factory = connection_factory
        # The database engine whose catalog queries are used (the active
        # database's unless one is passed in).
        self._engine = engine
        self.security = security
        # The semantic model (the active database's unless one is passed in).
        self.semantic = semantic if semantic is not None else default_semantic_model()
        self.fallback_tables = (
            tuple(fallback_tables) if fallback_tables is not None
            else self.semantic.fallback_tables
        )

        self.tables = {}
        self.foreign_keys = []

        self.fallback_schema = ""
        self.fallback_table_names = set()
        self.last_schema = ""
        self.domain_resolver = None
        # Typo-correction vocabulary, built on first use from the loaded
        # tables and domains (see question_terms). Reset by refresh().
        self._vocabulary = None
        self._last_terms = (None, frozenset())
        # Hub tables (see hub_tables()), worked out on first use from the
        # relationship graph and cached until it changes.
        self._hubs = (None, frozenset())

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def get_table(self, name):
        """
        The loaded table for a name, matched case-insensitively. A bare
        name is looked up in the default schema. Returns None for a table
        that isn't loaded (missing, or not authorised for this role).
        """
        full_name = full_table_name(name)
        table = self.tables.get(full_name)
        if table is not None:
            return table
        wanted = full_name.lower()
        return next(
            (t for key, t in self.tables.items() if key.lower() == wanted),
            None,
        )

    def resolve_table_name(self, name):
        """The catalog's key for a table name (see get_table), or None."""
        table = self.get_table(name)
        return f"{table['schema']}.{table['name']}" if table else None

    @staticmethod
    def _find_column(table, name):
        """The loaded column of a table, matched case-insensitively."""
        wanted = name.lower()
        return next((c for c in table["columns"] if c["name"].lower() == wanted), None)

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def refresh(self):
        self.tables = self._load_tables()
        if not self.tables:
            raise EmptyCatalogError(self._empty_reason())
        self._attach_semantics()

        database_keys = (
            self._load_foreign_keys()
            if self.semantic.use_database_foreign_keys else []
        )
        self.foreign_keys = self._build_relationships(database_keys)
        self.fallback_schema = self._build_fallback_schema()

        # Domains of Discourse are mapped onto THIS catalog, i.e. only
        # onto tables the role is authorised for.
        self.domain_resolver = DomainResolver(self)
        self._vocabulary = None
        self._last_terms = (None, frozenset())
        self._hubs = (None, frozenset())
        hubs = sorted(self.hub_tables())
        if hubs:
            shown = ", ".join(hubs[:10])
            more = f" and {len(hubs) - 10} more" if len(hubs) > 10 else ""
            print(f"[schema] {len(hubs)} hub table(s), not walked back from: "
                  f"{shown}{more}")

    def _empty_reason(self):
        """Why no tables loaded, as a hint for whoever reads the startup log."""
        security = self.security
        if security is not None and not security.tables:
            roles = ", ".join(sorted(security.roles)) or "(none)"
            return (
                f"no tables are visible to user {security.user_id} "
                f"(roles: {roles}). Either the database user has no SELECT "
                "grant on the tables the security policy allows, or the "
                "policy's allow lists name no tables that exist. The "
                "[security] lines above list each allowed table that wasn't "
                "found.")
        if security is not None:
            return (
                f"{len(security.tables)} table(s) are authorised, but none "
                "of them is discovered. Check sources.include / "
                "sources.exclude in the semantic model.")
        return ("the database has no tables matching sources.include / "
                "sources.exclude in the semantic model.")

    def _attach_semantics(self):
        """
        Copy the semantic model onto the loaded (discovery- and
        security-filtered) tables and columns:

            table["label"], table["aliases"], table["description"]
            column["label"], column["aliases"], column["description"]
            table["terms"]   terms whose table and columns are all loaded

        A name in the model that isn't loaded (missing from the database,
        excluded from discovery, or denied for this role) is skipped with
        a log line, so its vocabulary is never used or shown.
        """
        semantic = self.semantic

        for table in self.tables.values():
            full_name = f"{table['schema']}.{table['name']}"
            spec = semantic.table_spec(full_name)
            table["label"] = spec.label if spec else None
            table["aliases"] = tuple(sorted(spec.aliases)) if spec else ()
            table["description"] = spec.description if spec else None
            table["terms"] = []
            for column in table["columns"]:
                column_spec = semantic.column_spec(full_name, column["name"])
                column["label"] = column_spec.label if column_spec else None
                column["aliases"] = (
                    tuple(sorted(column_spec.aliases)) if column_spec else ())
                column["description"] = (
                    column_spec.description if column_spec else None)

        tables_done = columns_done = 0
        for key, spec in semantic.tables.items():
            table = self.get_table(key)
            if table is None:
                print(f"[schema] Semantic table '{key}' not available - skipped")
                continue
            tables_done += bool(spec.label or spec.aliases or spec.description)
            for column_name in spec.columns:
                if self._find_column(table, column_name) is None:
                    print(f"[schema] Column alias '{key}.{column_name}' "
                          "not available - skipped")
                else:
                    columns_done += 1

        terms_done = self._attach_terms()

        print(f"[schema] Semantic model attached: {tables_done} table(s), "
              f"{columns_done} column(s), {terms_done} term(s)")

    def _attach_terms(self):
        """
        Attach each term to its table, if the table and every column the
        term uses are loaded. A predicate is a condition on the table's own
        columns, optionally with EXISTS / NOT EXISTS subqueries ("a
        customer is a partner with a confirmed order"). Every table and
        column a predicate uses must be in the loaded (authorised) catalog,
        so a term can't be used to reach data the catalog doesn't show.
        An EXISTS only says whether matching rows exist; other subqueries
        (scalar, IN (SELECT ...)) and SELECT * are rejected. The term is
        text for the model: the SQL it ends up in is validated like any
        other.
        """
        import sqlglot
        from sqlglot import exp

        attached = 0
        for term in self.semantic.terms.values():
            table = self.get_table(term.table)
            if table is None:
                print(f"[schema] Term '{term.name}': table '{term.table}' "
                      "not available - skipped")
                continue

            if term.column:
                column = self._find_column(table, term.column)
                if column is None:
                    print(f"[schema] Term '{term.name}': column "
                          f"'{term.table}.{term.column}' not available - skipped")
                    continue
                definition = f"{column['name']} is true"
            else:
                try:
                    condition = sqlglot.parse_one(term.predicate, read=active_dialect())
                except Exception:
                    print(f"[schema] Term '{term.name}': predicate can't be "
                          "parsed - skipped")
                    continue
                problem = self._predicate_problem(condition, table, exp)
                if problem:
                    print(f"[schema] Term '{term.name}': {problem} - skipped")
                    continue
                missing = self._predicate_missing_columns(condition, table, exp)
                if missing:
                    print(f"[schema] Term '{term.name}': column(s) "
                          f"{', '.join(sorted(set(missing)))} not available - skipped")
                    continue
                definition = condition.sql(dialect=active_dialect())

            table["terms"].append({
                "name": term.name,
                "phrases": term.phrases,
                "definition": definition,
                "description": term.description,
            })
            attached += 1
        return attached

    def _predicate_problem(self, condition, table, exp):
        """Why a term predicate isn't allowed, or None. Subqueries must be
        the direct argument of EXISTS (NOT EXISTS is NOT over EXISTS),
        and every table they read must be loaded."""
        if any(condition.find_all(exp.Star)):
            return "predicate may not use SELECT *"
        for select in condition.find_all(exp.Select):
            parent = select.parent
            if isinstance(parent, exp.Subquery):
                parent = parent.parent
            if not isinstance(parent, exp.Exists):
                return ("predicate may only use the table's own columns and "
                        "EXISTS / NOT EXISTS subqueries")
        for ref in condition.find_all(exp.Table):
            name = f"{ref.db}.{ref.name}" if ref.db else ref.name
            if self.resolve_table_name(name) is None:
                return f"table '{name}' not available"
        return None

    def _predicate_missing_columns(self, condition, table, exp):
        """Columns a predicate uses that aren't loaded. A qualified column
        (so.partner_id, res_partner.id) is checked against the table its
        qualifier names; an unqualified one must be in the term's table or
        one of the tables the predicate reads."""
        own = f"{table['schema']}.{table['name']}"
        by_qualifier = {table["name"].lower(): own}
        for ref in condition.find_all(exp.Table):
            full = self.resolve_table_name(
                f"{ref.db}.{ref.name}" if ref.db else ref.name)
            by_qualifier[ref.name.lower()] = full
            if ref.alias:
                by_qualifier[ref.alias.lower()] = full
        readable = set(by_qualifier.values())

        missing = []
        for column in condition.find_all(exp.Column):
            if column.table:
                target = by_qualifier.get(column.table.lower())
                if target is None or self._find_column(
                        self.tables[target], column.name) is None:
                    missing.append(f"{column.table}.{column.name}")
            elif not any(self._find_column(self.tables[t], column.name)
                         for t in readable):
                missing.append(column.name)
        return missing

    def _build_fallback_schema(self):
        """
        Build the fallback schema from the configured table names, using
        the real (security-filtered) columns loaded above. Built once per
        refresh, i.e. at startup, and reused until restart.
        """
        selected = set()

        for table in self.fallback_tables:
            match = self.resolve_table_name(table)

            if match:
                selected.add(match)
            else:
                # Missing from the DB, or not authorised for this role.
                print(f"[schema] Fallback table '{full_table_name(table)}' "
                      "not available - skipped")

        self.fallback_table_names = selected
        print(f"[schema] Fallback schema built from {len(selected)} table(s)")
        return self._format_context(selected) if selected else ""

    @property
    def engine(self):
        return self._engine if self._engine is not None else active_engine()

    def _load_tables(self):
        # The engine's column query covers tables AND views, so a view
        # such as semantic.employees_v is discovered like any table.
        tables = {}
        not_discovered = set()
        seen_columns = {}   # full name -> every column name, before denial

        # closing(): a DB-API "with connection" block (psycopg2, pyodbc)
        # only ends the transaction, it does not close the connection.
        with closing(self.connection_factory()) as conn:
            for row in self.engine.column_rows(conn):
                full_name = f"{row['table_schema']}.{row['table_name']}"

                # ------------------------------------------------------
                # Discovery: the semantic model's sources
                # ------------------------------------------------------
                if not self.semantic.discovers(full_name):
                    not_discovered.add(full_name)
                    continue

                # ------------------------------------------------------
                # Security: table discovery
                # ------------------------------------------------------
                if (
                    self.security
                    and not is_authorized_table(self.security, full_name)
                ):
                    continue

                seen_columns.setdefault(full_name, set()).add(
                    row["column_name"].lower())

                denied = set()

                if self.security:
                    denied = get_denied_columns(self.security, full_name)

                # ------------------------------------------------------
                # Security: column discovery
                # ------------------------------------------------------
                if contains_case_insensitive(denied, row["column_name"]):
                    continue

                if full_name not in tables:
                    tables[full_name] = {
                        "schema": row["table_schema"],
                        "name": row["table_name"],
                        "columns": [],
                    }

                tables[full_name]["columns"].append({
                    "name": row["column_name"],
                    "type": row["data_type"],
                    "nullable": (row["is_nullable"] == "YES"),
                })

        if not_discovered:
            print(f"[schema] {len(not_discovered)} table(s)/view(s) outside "
                  "the semantic model's sources - not loaded")

        self._check_denied_columns(seen_columns)
        return tables

    def _check_denied_columns(self, seen_columns):
        """
        Warn about a denied column that doesn't exist on its table. It may
        have been dropped, but it is more often a typo in the security policy -
        and then the column it was meant to hide is visible.
        """
        if not self.security:
            return
        for full_name, columns in seen_columns.items():
            for denied in get_denied_columns(self.security, full_name):
                if denied.lower() not in columns:
                    print(f"[security] WARNING: denied column "
                          f"'{full_name}.{denied}' does not exist - check "
                          "the security policy for a typo")

    def _load_foreign_keys(self):
        # The engine returns each foreign key's columns in order, so a
        # composite key (company_id, order_no) becomes one relationship
        # rather than one per column.
        by_constraint = {}

        # closing(): a DB-API "with connection" block (psycopg2, pyodbc)
        # only ends the transaction, it does not close the connection.
        with closing(self.connection_factory()) as conn:
            for row in self.engine.foreign_key_rows(conn):
                parent = f"{row['parent_schema']}.{row['parent_table']}"
                referenced = f"{row['referenced_schema']}.{row['referenced_table']}"

                # ------------------------------------------------------
                # Security: don't expose relationships involving
                # unauthorised tables. (_build_relationships also
                # drops any that use a column the role can't see.)
                # ------------------------------------------------------
                if self.security:
                    if not is_authorized_table(self.security, parent):
                        continue

                    if not is_authorized_table(self.security, referenced):
                        continue

                key = row["constraint_id"]
                if key not in by_constraint:
                    by_constraint[key] = {
                        "from_table": parent,
                        "from_columns": [],
                        "to_table": referenced,
                        "to_columns": [],
                        "cardinality": None,
                        "source": "database",
                    }
                by_constraint[key]["from_columns"].append(row["parent_column"])
                by_constraint[key]["to_columns"].append(row["referenced_column"])

        return [
            dict(r, from_columns=tuple(r["from_columns"]),
                 to_columns=tuple(r["to_columns"]))
            for r in by_constraint.values()
        ]

    def _build_relationships(self, database_keys):
        """
        The relationship graph: the database's foreign keys plus the
        semantic model's declared relationships. Each is kept only when
        both tables and every column are in the loaded catalog, so a
        relationship can't reveal a table or column the role can't see.
        Table and column names are normalised to the catalog's own.
        """
        candidates = list(database_keys) + [
            {
                "from_table": r.from_table,
                "from_columns": r.from_columns,
                "to_table": r.to_table,
                "to_columns": r.to_columns,
                "cardinality": r.cardinality,
                "description": r.description,
                "source": "declared",
            }
            for r in self.semantic.relationships
        ]

        relationships = []
        seen = set()
        declared = 0

        for candidate in candidates:
            label = (f"{candidate['from_table']}({', '.join(candidate['from_columns'])})"
                     f" -> {candidate['to_table']}({', '.join(candidate['to_columns'])})")
            from_table = self.get_table(candidate["from_table"])
            to_table = self.get_table(candidate["to_table"])

            from_columns = [
                self._find_column(from_table, c) if from_table else None
                for c in candidate["from_columns"]
            ]
            to_columns = [
                self._find_column(to_table, c) if to_table else None
                for c in candidate["to_columns"]
            ]

            if from_table is None or to_table is None \
                    or None in from_columns or None in to_columns:
                # Database keys are skipped quietly (there can be
                # hundreds); a declared one is worth a log line.
                if candidate["source"] == "declared":
                    print(f"[schema] Relationship {label} not available - skipped")
                continue

            relationship = dict(
                candidate,
                from_table=f"{from_table['schema']}.{from_table['name']}",
                from_columns=tuple(c["name"] for c in from_columns),
                to_table=f"{to_table['schema']}.{to_table['name']}",
                to_columns=tuple(c["name"] for c in to_columns),
            )

            key = (
                relationship["from_table"].lower(),
                tuple(c.lower() for c in relationship["from_columns"]),
                relationship["to_table"].lower(),
                tuple(c.lower() for c in relationship["to_columns"]),
            )
            if key in seen:
                continue
            seen.add(key)
            relationships.append(relationship)
            declared += relationship["source"] == "declared"

        if self.semantic.relationships:
            print(f"[schema] Declared relationships in use: {declared} of "
                  f"{len(self.semantic.relationships)}")
        return relationships

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

    def search(self, question, limit=10, restrict_to=None):
        """
        Rank tables against the question. restrict_to (a set of full
        table names) limits the search to a Domain of Discourse.
        """
        terms = self.question_terms(question)
        scores = []

        for full_name, table in self.tables.items():
            if restrict_to is not None and full_name not in restrict_to:
                continue

            score = self.score_table(table, terms)

            if score > 0:
                scores.append((score, full_name))

        scores.sort(key=lambda x: x[0], reverse=True)

        return [
            (score, self.tables[name])
            for score, name in scores[:limit]
        ]

    # ------------------------------------------------------------------
    # Question words (with typo correction)
    # ------------------------------------------------------------------

    def vocabulary(self):
        """
        (known, candidates) for typo correction. candidates are the words
        of every loaded table and column name, alias, label and business
        term, plus the aliases of the domains that have loaded tables -
        exactly the words a question word can match. known adds their
        tokenize() forms.

        Built from this (security-filtered) catalog only, so a correction
        can never name something the role can't see.
        """
        if self._vocabulary is not None:
            return self._vocabulary

        names = []
        for table in self.tables.values():
            names.append(table["name"])
            names.extend(table.get("aliases", ()))
            if table.get("label"):
                names.append(table["label"])
            for term in table.get("terms", ()):
                names.extend(term["phrases"])
            for column in table["columns"]:
                names.append(column["name"])
                names.extend(column.get("aliases", ()))
                if column.get("label"):
                    names.append(column["label"])

        resolver = self.domain_resolver
        if resolver is not None:
            for key, domain in resolver.domains.items():
                if not resolver.domain_tables.get(key):
                    continue
                # Only aliases: they are what a question word is matched
                # against (DomainResolver.resolve). Location phrases are
                # matched against the [where=...] tag, not the question.
                names.extend(domain.get("aliases", ()))

        candidates = sorted({
            w for name in names for w in words(name.replace("_", " "))
            if len(w) >= 3 and not any(ch.isdigit() for ch in w)
        })
        known = set()
        for w in candidates:
            known |= tokenize(w)
        self._vocabulary = (frozenset(known), candidates)
        return self._vocabulary

    def question_terms(self, question):
        """
        The words of a question used for matching tables and domains:
        tokenize(question) minus GENERIC_TERMS, plus the correction of
        any word that matches nothing ("custmers" -> "customers"). The
        question itself is not changed.

        Settings: typo_correction in config/settings/retrieval.yaml.
        """
        last_question, last_terms = self._last_terms
        if question == last_question:
            return set(last_terms)

        terms = tokenize(question) - GENERIC_TERMS
        config = get_settings().retrieval.typo_correction

        if config.enabled and not fuzzy_available() and not _warned_no_fuzzy:
            _warn_no_fuzzy()
        if (config.enabled and config.common_word_zipf
                and not word_frequency_available() and not _warned_no_wordfreq):
            _warn_no_wordfreq()

        if config.enabled and fuzzy_available() and self.tables:
            known, candidates = self.vocabulary()
            corrections, ambiguous = correct_words(
                question, known, candidates,
                min_score=config.min_score, min_length=config.min_length,
                margin=config.margin, skip=GENERIC_TERMS,
                same_first_letter=config.same_first_letter,
                common_word_zipf=config.common_word_zipf)
            for word, (fixed, score) in corrections.items():
                print(f"[schema] Typo correction: {word} -> {fixed} ({score})")
                terms |= tokenize(fixed)
            for word, tied in ambiguous.items():
                print(f"[schema] Typo correction: {word} is ambiguous "
                      f"({', '.join(tied)}) - not corrected")

        self._last_terms = (question, frozenset(terms))
        return terms

    # ------------------------------------------------------------------
    # Context
    # ------------------------------------------------------------------

    def tables_in_sql(self, sql):
        """
        The catalog tables a SQL statement reads from, as full names.

        Used for weak follow-ups (see get_context's anchors). Only tables
        in this (security-filtered) catalog are returned, so a table the
        role can't see never comes back. Unparseable SQL gives an empty
        set.
        """
        import sqlglot
        from sqlglot import exp

        if not sql:
            return set()

        try:
            tree = sqlglot.parse_one(sql, read=active_dialect())
        except Exception:
            return set()

        found = set()
        for table in tree.find_all(exp.Table):
            match = self.resolve_table_name(full_table_name(table.name, table.db))
            if match:
                found.add(match)
        return found

    def get_context(self, question, table_limit=10, relationship_depth=1,
                    scope=None, anchors=None):
        """
        Build the partial schema for a question.

        anchors (a set of full table names) replaces the keyword search:
        the schema is those tables plus their relationship hops, with no
        fallback tables. The agent passes the previous query's tables for
        a follow-up such as "What is Thomas's full name?", so the
        model starts from the table the conversation is about (customers)
        rather than every table with a "name" column.

        scope is None (search the whole catalog, the original behaviour)
        or a (domain_tables, domain_fallbacks, hops) tuple from
        DomainResolver.scope(). With a scope:

          - anchors are searched for within the domain's tables only;
          - a table OUTSIDE the domain that the question names in full
            (e.g. "shippers") is still added - the domain is where the
            search starts, not a wall;
          - the relationship walk uses the full foreign-key graph, to the
            domain's hop limit, so it can cross into other domains;
          - weak matches top up with the domain's fallback tables instead
            of the global list.
        """
        fallback_names = self.fallback_table_names
        unwalked = set()   # added to the schema, but not walked from

        if anchors:
            selected = {name for name in anchors if name in self.tables}
            if selected:
                depth = scope[2] if scope is not None else relationship_depth
                selected = self.get_related_tables(selected, depth=depth)
                return self._format_context(selected)

        if scope is None:
            matches = self.search(question, limit=table_limit)
        else:
            domain_tables, domain_fallbacks, relationship_depth = scope
            if domain_fallbacks:
                fallback_names = domain_fallbacks

            matches = self.search(
                question, limit=table_limit, restrict_to=domain_tables)

            outside = [
                (score, table)
                for score, table in self.search(question, limit=table_limit)
                if f"{table['schema']}.{table['name']}" not in domain_tables
                and score >= FULL_NAME_MATCH
            ]
            if outside:
                names = ", ".join(t["name"] for _, t in outside)
                outside_mode = self._retrieval_setting("named_outside_domain")
                if outside_mode == "note":
                    print(f"[schema] Named outside the domain, not added: {names}")
                elif outside_mode == "add":
                    print(f"[schema] Named outside the domain, added "
                          f"(no relationship walk): {names}")
                    unwalked = {f"{t['schema']}.{t['name']}" for _, t in outside}
                else:
                    print(f"[schema] Named outside the domain, added: {names}")
                    matches = sorted(matches + outside, key=lambda m: m[0],
                                     reverse=True)

        selected = {
            f"{table['schema']}.{table['name']}"
            for _, table in matches
        }

        if not selected:
            if scope is not None and fallback_names:
                # Nothing in the domain matched the words (e.g. "show me
                # Nancy's details"), but we do know the area: use the
                # domain's fallback tables rather than the global list.
                print("[schema] No table match in domain - using fallback tables")
                return self._format_context(set(fallback_names) | unwalked)
            if unwalked:
                return self._format_context(unwalked)
            return ""

        selected = self.get_related_tables(selected, depth=relationship_depth)

        # A weak match (no table named in full, only a partial name or a
        # column word) is a poor signal on its own, so the fallback tables
        # are added alongside it. e.g. "Margaret's order history": "order"
        # only partly matches order_details, and employees comes from the
        # fallback list.
        best_score = matches[0][0]
        if best_score < FULL_NAME_MATCH:
            print("[schema] Weak table match - adding fallback tables")
            selected |= set(fallback_names)

        return self._format_context(selected | unwalked)

    def discover_schema(self, question, scope=None, anchors=None):
        """
        Discover the relevant schema for a question.

        Fallback order:

            1. Relevant schema (tables matching the question's words,
               within the Domain of Discourse when scope is given - see
               domains.py)
            2. Fallback schema: the fallback_tables list, with real
               columns read at startup (e.g. "show me Nancy's information"
               names a person, not a table, so nothing matches by keyword)

        Step 2 used to be "the last schema discovered". The catalog is
        shared by every API session, so that meant one visitor's previous
        question decided what the next visitor's question could see, and
        usually left out the table that was needed.
        """
        schema = self.get_context(
            question,
            table_limit=10,
            relationship_depth=1,
            scope=scope,
            anchors=anchors,
        )

        if schema and schema.strip():
            self.last_schema = schema
            return schema

        print(
            "[schema] No relevant schema found - "
            "using fallback schema"
        )

        return self.get_fallback_schema()

    # ------------------------------------------------------------------
    # Relationship walk
    # ------------------------------------------------------------------

    def _retrieval_setting(self, key):
        """A retrieval.relationships setting, with the database's own
        override (semantic retrieval: section) taking precedence."""
        overrides = getattr(self.semantic, "retrieval", None) or {}
        if key in overrides:
            return overrides[key]
        return getattr(get_settings().retrieval.relationships, key)

    def hub_tables(self):
        """
        Tables that many others point at, such as Odoo's res_company and
        res_users (nearly every table has company_id, create_uid and
        write_uid). Walking INTO such a table is fine; walking back OUT
        to every table that points at it pulls most of the schema into
        the prompt. A hub is one with more than hub_threshold distinct
        tables pointing at it (self-references don't count), plus the
        database's hub_tables, minus its not_hub_tables.
        """
        cache_key = (id(self.foreign_keys), len(self.foreign_keys))
        if self._hubs[0] == cache_key:
            return self._hubs[1]

        threshold = self._retrieval_setting("hub_threshold")
        overrides = getattr(self.semantic, "retrieval", None) or {}

        pointing_at = {}
        for relationship in self.foreign_keys:
            source, target = relationship["from_table"], relationship["to_table"]
            if source != target:
                pointing_at.setdefault(target, set()).add(source)

        hubs = set()
        if threshold:
            hubs = {t for t, sources in pointing_at.items() if len(sources) > threshold}
        for name in overrides.get("hub_tables", ()):
            match = self.resolve_table_name(name)
            if match:
                hubs.add(match)
        for name in overrides.get("not_hub_tables", ()):
            hubs.discard(self.resolve_table_name(name))

        self._hubs = (cache_key, frozenset(hubs))
        return self._hubs[1]

    def get_related_tables(self, selected, depth=1):
        """
        selected plus the tables within `depth` relationship hops.

        A foreign key is followed outward (from the table that holds it to
        the table it points at) from any table. It is followed inward
        (from the table pointed at back to the table holding the key)
        only from a table that isn't a hub (hub_tables()). A hub itself is
        always included when selected or reached.
        """
        hubs = self.hub_tables()
        related = set(selected)

        for _ in range(depth):
            expanded = set(related)

            for relationship in self.foreign_keys:
                source, target = relationship["from_table"], relationship["to_table"]
                if source in related:
                    expanded.add(target)
                if target in related and target not in hubs:
                    expanded.add(source)

            related = expanded

        return related

    # ------------------------------------------------------------------
    # Formatting
    # ------------------------------------------------------------------

    @staticmethod
    def context_summary(schema, largest=5):
        """
        A one-line summary of a partial schema for the log: how many
        tables, and the largest by line count, e.g.
        "23 table(s); largest: res_partner (181), account_move (140)".
        """
        sizes, current = [], None
        for line in schema.splitlines():
            if line.startswith("TABLE "):
                name = line[len("TABLE "):].split("  --")[0].strip()
                current = [name, 1]
                sizes.append(current)
            elif current and line.startswith(" "):
                current[1] += 1
            elif line.strip():
                current = None     # RELATIONSHIPS, TERMS, ...
        if not sizes:
            return "0 tables"
        top = sorted(sizes, key=lambda s: -s[1])[:largest]
        return (f"{len(sizes)} table(s); largest: "
                + ", ".join(f"{name} ({count})" for name, count in top))

    def _format_context(self, selected):
        lines = []
        terms = []

        for full_name in sorted(selected):
            table = self.tables.get(full_name)

            if not table:
                continue

            header = f"TABLE {self.engine.display_table(full_name)}"
            notes = self._notes(table)
            if notes:
                header += f"  -- {notes}"
            lines.append(header)

            for column in table["columns"]:
                nullable = "NULL" if column["nullable"] else "NOT NULL"

                line = (f"  - {self.engine.quote_name(column['name'])} "
                        f"{column['type']} {nullable}")

                notes = self._notes(column)
                json_note = self._json_note(column, notes)
                if json_note:
                    notes = f"{notes}; {json_note}" if notes else json_note
                if notes:
                    line += f"  -- {notes}"

                aliases = column.get("aliases", ())
                if aliases:
                    words = ", ".join(_words_of(a) for a in aliases)
                    line += f"  (aka: {words})"

                lines.append(line)

            lines.append("")

            for term in table.get("terms", ()):
                terms.append((full_name, term))

        relationships = [
            relationship
            for relationship in self.foreign_keys
            if (
                relationship["from_table"] in selected
                and relationship["to_table"] in selected
            )
        ]

        if relationships:
            lines.append("RELATIONSHIPS")

            for relationship in relationships:
                lines.append(f"  - {self._format_relationship(relationship)}")

        if terms:
            if relationships:
                lines.append("")
            lines.append("TERMS (business words and the rows they mean)")
            for full_name, term in terms:
                words = ", ".join(_words_of(p) for p in term["phrases"])
                line = (f"  - {words}: {self.engine.display_table(full_name)} "
                        f"WHERE {term['definition']}")
                if term.get("description"):
                    line += f"  -- {term['description']}"
                lines.append(line)

        return "\n".join(lines)

    @staticmethod
    def _json_note(column, notes):
        """
        A short warning for a json/jsonb column, from its discovered type,
        so models don't compare it with text or use it in arithmetic. None
        for other columns, or when the column's own description already
        explains its JSON (e.g. "JSONB by language: use name->>'en_US'").
        """
        if str(column.get("type", "")).lower() not in JSON_TYPES:
            return None
        if "json" in (notes or "").lower():
            return None
        return JSON_NOTE

    @staticmethod
    def _notes(item):
        """The label and description shown after a table or column."""
        parts = []
        if item.get("label"):
            parts.append(_words_of(item["label"]))
        if item.get("description"):
            parts.append(item["description"])
        return ": ".join(parts)

    def _format_relationship(self, relationship):
        """
        One relationship line. A single-column key keeps the original
        "a.col -> b.col" form; a composite key is written
        "a(col1, col2) -> b(col1, col2)". Declared relationships show
        their cardinality, which helps the model avoid joins that
        double-count.
        """
        quote = self.engine.quote_name
        from_table = self.engine.display_table(relationship["from_table"])
        to_table = self.engine.display_table(relationship["to_table"])
        from_cols = [quote(c) for c in relationship["from_columns"]]
        to_cols = [quote(c) for c in relationship["to_columns"]]
        if len(from_cols) == 1:
            text = f"{from_table}.{from_cols[0]} -> {to_table}.{to_cols[0]}"
        else:
            text = (f"{from_table}({', '.join(from_cols)}) -> "
                    f"{to_table}({', '.join(to_cols)})")
        if relationship.get("cardinality"):
            text += f" ({relationship['cardinality'].replace('_', '-')})"
        if relationship.get("description"):
            text += f"  -- {relationship['description']}"
        return text

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def score_table(self, table, terms):
        """
        How well a table matches a question's terms (from
        text_match.tokenize). See the score constants in text_match.py.
        """
        score = 0

        # Table name, part by part: order_details -> "order", "details".
        # Each part counts as matched if any of its forms (e.g. singular)
        # is in the question.
        name_parts = phrase_parts(table["name"])
        matched_parts = sum(1 for forms in name_parts if terms & forms)

        if matched_parts and matched_parts == len(name_parts):
            score += matched_parts * FULL_NAME_MATCH
        else:
            score += matched_parts * PARTIAL_NAME_MATCH

        # Label and aliases: other words for this table (from the
        # semantic model). A multi-word alias ("sales_rep") matches only
        # when every word is in the question, the same rule as for table
        # names. The label counts as an alias.
        names = list(table.get("aliases", ()))
        if table.get("label"):
            names.append(table["label"])
        if any(phrase_matches(name, terms) for name in names):
            score += ALIAS_MATCH

        # Terms: a business word for some of this table's rows
        # ("shipped late") points at the table as strongly as an alias.
        if any(
            phrase_matches(phrase, terms)
            for term in table.get("terms", ())
            for phrase in term["phrases"]
        ):
            score += TERM_MATCH

        # Column matches, by name word and by label or alias.
        for column in table["columns"]:
            column_tokens = tokenize(column["name"])
            score += len(terms & column_tokens) * COLUMN_MATCH

            names = list(column.get("aliases", ()))
            if column.get("label"):
                names.append(column["label"])
            if any(phrase_matches(name, terms) for name in names):
                score += COLUMN_MATCH

        return score

    # ------------------------------------------------------------------
    # Fallback schema
    # ------------------------------------------------------------------
    # Built at startup by _build_fallback_schema() from the table names in
    # fallback_tables, with the real column names from the database. This
    # replaces the old hard-coded schema, whose column names were a guess.

    def get_fallback_schema(self):
        if not self.fallback_schema:
            print(
                "[schema] Fallback schema is empty - check fallback_tables "
                "and that the catalog loaded"
            )
        return self.fallback_schema
