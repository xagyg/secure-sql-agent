# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Ported from SQL Server's INFORMATION_SCHEMA / sys.foreign_key_columns
# to PostgreSQL's information_schema. Row access changed from pyodbc's
# attribute-style rows (row.TABLE_SCHEMA) to psycopg2 RealDictCursor's
# dict-style rows (row["table_schema"]) — Postgres's information_schema
# columns are lowercase.
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
# The vocabulary that used to be defined here (TABLE_ALIASES,
# COLUMN_ALIASES, DEFAULT_FALLBACK_TABLES) now lives in config/semantic/<database>/
# (see semantic_model.py).

from contextlib import closing

from sqlagent.adaptive.domains import DomainResolver
from sqlagent.adaptive.semantic_model import default_semantic_model
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
    phrase_matches,
    phrase_parts,
    tokenize,
)


def _words_of(name):
    """A label or phrase for display: "credit_limit" -> "credit limit"."""
    return name.replace("_", " ").strip()


class SchemaCatalog:

    def __init__(self, connection_factory, security=None, semantic=None,
                 fallback_tables=None):
        self.connection_factory = connection_factory
        self.security = security
        # The semantic model (config/semantic/northwind/ unless one is passed in).
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
        term uses are loaded. A predicate must be a plain condition on the
        table's own columns (no subqueries, no other tables), so a term
        can't be used to reach data the catalog doesn't show.
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
                    condition = sqlglot.parse_one(term.predicate, read="postgres")
                except Exception:
                    print(f"[schema] Term '{term.name}': predicate can't be "
                          "parsed - skipped")
                    continue
                if any(condition.find_all(exp.Select, exp.Table, exp.Star)):
                    print(f"[schema] Term '{term.name}': predicate may only use "
                          "the table's own columns - skipped")
                    continue
                missing = [
                    c.name for c in condition.find_all(exp.Column)
                    if self._find_column(table, c.name) is None
                ]
                if missing:
                    print(f"[schema] Term '{term.name}': column(s) "
                          f"{', '.join(sorted(set(missing)))} not available - skipped")
                    continue
                definition = condition.sql(dialect="postgres")

            table["terms"].append({
                "name": term.name,
                "phrases": term.phrases,
                "definition": definition,
                "description": term.description,
            })
            attached += 1
        return attached

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

    def _load_tables(self):
        # information_schema.columns covers tables AND views, so a view
        # such as semantic.employees_v is discovered like any table.
        sql = """
        SELECT
            c.table_schema,
            c.table_name,
            c.column_name,
            c.data_type,
            c.is_nullable,
            c.ordinal_position
        FROM information_schema.columns c
        WHERE c.table_schema NOT IN ('pg_catalog', 'information_schema')
        ORDER BY
            c.table_schema,
            c.table_name,
            c.ordinal_position
        """

        tables = {}
        not_discovered = set()
        seen_columns = {}   # full name -> every column name, before denial

        # closing(): a psycopg2 "with connection" block only ends the
        # transaction, it does not close the connection.
        with closing(self.connection_factory()) as conn:
            with conn.cursor() as cursor:
                cursor.execute(sql)

                for row in cursor.fetchall():
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
        # pg_constraint gives each foreign key once, with its columns in
        # order, so a composite key (company_id, order_no) comes back as
        # one relationship rather than one per column.
        sql = """
        SELECT
            con.oid AS constraint_id,
            pn.nspname AS parent_schema,
            pc.relname AS parent_table,
            pa.attname AS parent_column,
            rn.nspname AS referenced_schema,
            rc.relname AS referenced_table,
            ra.attname AS referenced_column
        FROM pg_constraint con
        CROSS JOIN LATERAL unnest(con.conkey, con.confkey)
            WITH ORDINALITY AS k(parent_attnum, ref_attnum, ord)
        JOIN pg_class pc     ON pc.oid = con.conrelid
        JOIN pg_namespace pn ON pn.oid = pc.relnamespace
        JOIN pg_attribute pa ON pa.attrelid = con.conrelid  AND pa.attnum = k.parent_attnum
        JOIN pg_class rc     ON rc.oid = con.confrelid
        JOIN pg_namespace rn ON rn.oid = rc.relnamespace
        JOIN pg_attribute ra ON ra.attrelid = con.confrelid AND ra.attnum = k.ref_attnum
        WHERE con.contype = 'f'
        ORDER BY pn.nspname, pc.relname, con.conname, k.ord
        """

        by_constraint = {}

        # closing(): a psycopg2 "with connection" block only ends the
        # transaction, it does not close the connection.
        with closing(self.connection_factory()) as conn:
            with conn.cursor() as cursor:
                cursor.execute(sql)

                for row in cursor.fetchall():
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
        terms = tokenize(question) - GENERIC_TERMS
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
            tree = sqlglot.parse_one(sql, read="postgres")
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
                return self._format_context(set(fallback_names))
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

        return self._format_context(selected)

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

    def get_related_tables(self, selected, depth=1):
        related = set(selected)

        for _ in range(depth):
            expanded = set(related)

            for relationship in self.foreign_keys:
                if (
                    relationship["from_table"] in related
                    or relationship["to_table"] in related
                ):
                    expanded.add(relationship["from_table"])
                    expanded.add(relationship["to_table"])

            related = expanded

        return related

    # ------------------------------------------------------------------
    # Formatting
    # ------------------------------------------------------------------

    def _format_context(self, selected):
        lines = []
        terms = []

        for full_name in sorted(selected):
            table = self.tables.get(full_name)

            if not table:
                continue

            header = f"TABLE {full_name}"
            notes = self._notes(table)
            if notes:
                header += f"  -- {notes}"
            lines.append(header)

            for column in table["columns"]:
                nullable = "NULL" if column["nullable"] else "NOT NULL"

                line = f"  - {column['name']} {column['type']} {nullable}"

                notes = self._notes(column)
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
                line = f"  - {words}: {full_name} WHERE {term['definition']}"
                if term.get("description"):
                    line += f"  -- {term['description']}"
                lines.append(line)

        return "\n".join(lines)

    @staticmethod
    def _notes(item):
        """The label and description shown after a table or column."""
        parts = []
        if item.get("label"):
            parts.append(_words_of(item["label"]))
        if item.get("description"):
            parts.append(item["description"])
        return ": ".join(parts)

    @staticmethod
    def _format_relationship(relationship):
        """
        One relationship line. A single-column key keeps the original
        "a.col -> b.col" form; a composite key is written
        "a(col1, col2) -> b(col1, col2)". Declared relationships show
        their cardinality, which helps the model avoid joins that
        double-count.
        """
        from_cols = relationship["from_columns"]
        to_cols = relationship["to_columns"]
        if len(from_cols) == 1:
            text = (f"{relationship['from_table']}.{from_cols[0]} -> "
                    f"{relationship['to_table']}.{to_cols[0]}")
        else:
            text = (f"{relationship['from_table']}({', '.join(from_cols)}) -> "
                    f"{relationship['to_table']}({', '.join(to_cols)})")
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
