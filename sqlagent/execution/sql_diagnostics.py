# Copyright (c) 2026 Brad Long
# Author: Brad Long

import re
from contextlib import closing

from sqlglot import exp

from sqlagent.controls.sql_policy import parse_single_sql
from sqlagent.adaptive.semantic_model import default_semantic_model
from sqlagent.controls.security_utils import (
    contains_case_insensitive,
    full_table_name,
    get_denied_columns,
)
from sqlagent.execution.engines import active_engine
from sqlagent.execution.sql_execution import get_connection


# ---------------------------------------------------------------------------
# Semantic column aliases
# ---------------------------------------------------------------------------
# The column vocabulary is the semantic model's column labels, aliases and
# column terms (config/databases/<database>/semantic/), the same words the
# catalog uses to pick tables and shows the LLM. Here it is read the other way
# round: the model wrote an alias ("phone") or label as if it were a column, so
# map it back to the physical column (employees.home_phone). This NEVER
# bypasses authorisation: a denied column is reported as such.


# ---------------------------------------------------------------------------
# Schema diagnostics
# ---------------------------------------------------------------------------

def get_physical_columns(full_table):
    """Return physical columns for internal diagnostics only."""
    schema_name, table_name = full_table.split(".", 1)

    # closing(): a DB-API "with connection" block only ends the
    # transaction, it does not close the connection.
    with closing(get_connection()) as conn:
        return active_engine().physical_columns(conn, schema_name, table_name)


def get_column_alias(full_table, column_name, semantic=None):
    """
    The physical column that column_name is another name for on this
    table (a column label, alias or column term in the semantic model),
    or None. A bare table name is in the default schema.
    """
    semantic = semantic if semantic is not None else default_semantic_model()
    return semantic.physical_column_for(full_table_name(full_table), column_name)


def extract_missing_column(error_text):
    """
    Return the bare column name from the database's "no such column"
    error, or None. The wording is the engine's (see its
    missing_column()); any table qualifier is dropped because the alias
    lookup that follows works on plain column names.
    """
    return active_engine().missing_column(error_text)


def diagnose_sql_error(sql, error, security, semantic=None):
    """
    Diagnose "no such column" errors. semantic is
    the catalog's semantic model (the default model if omitted).

    Physical schema details remain internal and are not sent to Ollama.
    """
    error_text = str(error)

    column_name = extract_missing_column(error_text)

    if not column_name:
        return None

    try:
        tree = parse_single_sql(sql)
    except ValueError:
        return None

    referenced_tables = []

    for table in tree.find_all(exp.Table):
        full_table = full_table_name(table.name, table.db)

        if not any(
            existing.lower() == full_table.lower() for existing in referenced_tables
        ):
            referenced_tables.append(full_table)

    alias_matches = []

    for full_table in referenced_tables:
        physical_alias = get_column_alias(full_table, column_name, semantic)

        if not physical_alias:
            continue

        try:
            physical_columns = get_physical_columns(full_table)
        except Exception:
            continue

        actual_column = next(
            (
                column
                for column in physical_columns
                if column.lower() == physical_alias.lower()
            ),
            None,
        )

        if actual_column is None:
            continue

        denied = get_denied_columns(security, full_table)
        authorised = not contains_case_insensitive(denied, actual_column)

        alias_matches.append({
            "table": full_table,
            "column": actual_column,
            "alias": column_name,
            "authorised": authorised,
        })

    if alias_matches:
        error_type = (
            "invalid_column_alias_authorised"
            if any(match["authorised"] for match in alias_matches)
            else "invalid_column_alias_denied"
        )
    else:
        error_type = "invalid_column"

    return {
        "error_type": error_type,
        "column": column_name,
        "tables": referenced_tables,
        "matches": alias_matches,
    }

# ---------------------------------------------------------------------------
# JSON / JSONB type errors
# ---------------------------------------------------------------------------
# A column of type json/jsonb used as plain text or a number ("name =
# 'Australia'", "quantity * standard_price") fails with e.g. "invalid input
# syntax for type json" or "operator does not exist: numeric * jsonb". The
# raw error doesn't say WHICH column is JSON, and a small model asked to
# correct it tends to strip a correct ->>'en_US' and keep the real
# mistake. This names the JSON columns the failed SQL uses, each with its
# note from the semantic model (how to read it), so the retry is told
# exactly what to change.
#
# Only columns in the role's catalog are named: the catalog never holds an
# unauthorised table or a denied column, and the schema these columns
# come from has already been shown to the model.

_JSON_TYPES = ("json", "jsonb")
_JSON_ERROR = re.compile(r"\bjsonb?\b", re.IGNORECASE)


def is_json_type_error(error_text):
    """True when the database error is about a json/jsonb value."""
    return bool(_JSON_ERROR.search(str(error_text or "")))


def json_columns_in_sql(sql, catalog):
    """
    [(table, column, note)] for the json/jsonb columns the SQL refers to,
    in order of first use. table is the bare table name, note the column's
    semantic label/description ("" when it has none). Unparseable SQL, or
    a column that can't be tied to one catalog table, is skipped.
    """
    try:
        tree = parse_single_sql(sql)
    except ValueError:
        return []

    # alias (or bare name) -> catalog table
    by_alias = {}
    for table in tree.find_all(exp.Table):
        full = catalog.resolve_table_name(full_table_name(table.name, table.db))
        if full and full in catalog.tables:
            by_alias[(table.alias_or_name or table.name).lower()] = catalog.tables[full]
            by_alias.setdefault(table.name.lower(), catalog.tables[full])

    def column_of(table, name):
        return next((c for c in table["columns"]
                     if c["name"].lower() == name.lower()), None)

    found, seen = [], set()
    for column in tree.find_all(exp.Column):
        if column.table:
            candidates = [by_alias.get(column.table.lower())]
        else:
            # Unqualified: only when exactly one referenced table has it.
            owners = {id(t): t for t in by_alias.values() if column_of(t, column.name)}
            candidates = list(owners.values()) if len(owners) == 1 else []

        for table in candidates:
            if not table:
                continue
            info = column_of(table, column.name)
            if not info or str(info.get("type", "")).lower() not in _JSON_TYPES:
                continue
            key = (table["name"].lower(), info["name"].lower())
            if key in seen:
                continue
            seen.add(key)
            note = info.get("description") or ""
            found.append((table["name"], info["name"], note))

    return found


def json_correction_hint(sql, error_text, catalog):
    """
    The JSON COLUMNS block for correct_sql(), or "" when the error isn't
    about json or the SQL names no json column.
    """
    if not is_json_type_error(error_text):
        return ""

    columns = json_columns_in_sql(sql, catalog)
    if not columns:
        return ""

    lines = ["JSON COLUMNS IN THE FAILED SQL"]
    for table, column, note in columns:
        if note.upper().startswith("JSON"):
            line = f"- {table}.{column}: {note}"
        else:
            line = f"- {table}.{column} is JSONB" + (f": {note}" if note else "")
        lines.append(line)
    lines += [
        "A JSONB column cannot be compared with text or used in arithmetic",
        "as it is. Read a value out of it with ->> and cast it when a number",
        "is needed, e.g. (col->>'1')::numeric. Keep every ->> that is",
        "already applied to a JSONB column; do not remove it.",
    ]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Missing columns
# ---------------------------------------------------------------------------
# The model often writes a column from memory of another Odoo version or
# ERP (hr_version.contract_end_date for contract_date_end, project_task.hours
# for allocated_hours) and, told only "column does not exist", sends the
# same SQL back. This names the table the column was looked for in, the
# closest real columns, the table's own note from the semantic model, and
# any other table in the query that does have that column - so the retry
# has something to go on, or is told plainly that nothing similar exists.
#
# Only the role's catalog is used: it never holds an unauthorised table or
# a denied column, so nothing here can name data the role can't see.

MISSING_COLUMN_MIN_SCORE = 70     # weakest suggestion shown
MISSING_COLUMN_SUGGESTIONS = 3
MISSING_COLUMN_NOTE_CHARS = 400   # table note, trimmed to this
MISSING_COLUMN_DETAILED = 6       # columns explained in full; the rest are listed

_QUALIFIED_MISSING = re.compile(
    r'column\s+"?([A-Za-z_][\w$]*)"?\s*\.\s*"?([A-Za-z_][\w$]*)"?\s+does not exist',
    re.IGNORECASE)


def _words(name):
    return name.replace("_", " ").lower()


def column_similarity(missing, candidate):
    """
    0-100: how likely `candidate` is the column meant by `missing`.
    Whole-name similarity, word order (contract_end_date ~
    contract_date_end) and word subsets (hours ~ allocated_hours, scaled
    down a little). A bare "id" never counts: nearly every *_id contains
    it.
    """
    from rapidfuzz import fuzz
    if candidate.lower() == "id":
        return 0
    a, b = missing.lower(), candidate.lower()
    return max(fuzz.ratio(a, b),
               fuzz.token_sort_ratio(_words(a), _words(b)),
               0.9 * fuzz.token_set_ratio(_words(a), _words(b)))


def _similar_columns(missing, table):
    """[(score, column name)] best first, from names, labels and aliases."""
    try:
        import rapidfuzz  # noqa: F401  (pinned; without it, names only)
        fuzzy = True
    except ImportError:
        fuzzy = False

    scored = {}
    for column in table["columns"]:
        name = column["name"]
        words = [column.get("label") or ""] + list(column.get("aliases") or ())
        if any(w and _words(w) == _words(missing) for w in words):
            scored[name] = 100           # the model used the column's label
            continue
        if fuzzy:
            score = column_similarity(missing, name)
            if score >= MISSING_COLUMN_MIN_SCORE:
                scored[name] = score
    return sorted(((round(s), n) for n, s in scored.items()),
                  key=lambda item: (-item[0], item[1]))[:MISSING_COLUMN_SUGGESTIONS]


def missing_column_hint(sql, error_text, catalog, unknown=None):
    """
    The COLUMN NOT FOUND block for correct_sql(), or "" when the error
    isn't a missing column or its table can't be found in the catalog.
    unknown: [(column, qualifier, table)] from find_unknown_columns() -
    every column the pre-execution check found missing, all covered in
    one block; otherwise the one the database error names.
    """
    if unknown:
        wanted = [(column, qualifier) for column, qualifier, _ in unknown]
    else:
        column_name = extract_missing_column(str(error_text or ""))
        if not column_name:
            return ""
        match = _QUALIFIED_MISSING.search(str(error_text).splitlines()[0])
        qualifier = match.group(1) if match and \
            match.group(2).lower() == column_name.lower() else None
        wanted = [(column_name, qualifier)]
    try:
        tree = parse_single_sql(sql)
    except ValueError:
        return ""

    # reference (alias or bare name) -> catalog table
    by_reference = {}
    for table in tree.find_all(exp.Table):
        full = catalog.resolve_table_name(full_table_name(table.name, table.db))
        if full and full in catalog.tables:
            by_reference[(table.alias_or_name or table.name).lower()] = catalog.tables[full]
            by_reference.setdefault(table.name.lower(), catalog.tables[full])
    if not by_reference:
        return ""

    lines = ["COLUMN NOT FOUND"]
    noted = set()            # each table's note once
    for column_name, qualifier in wanted[:MISSING_COLUMN_DETAILED]:
        lines += _missing_column_lines(tree, by_reference, column_name,
                                       qualifier, noted)
    if len(lines) == 1:
        return ""
    rest = wanted[MISSING_COLUMN_DETAILED:]
    if rest:
        lines.append("- Also not found: " + ", ".join(
            f"{qualifier}.{column}" if qualifier else column
            for column, qualifier in rest))
    lines += [
        "Use only columns that the schema lists for each table. If none of",
        "the closest columns means what the question asks, the data may not",
        "be recorded: return DATA_NOT_AVAILABLE rather than invent a column.",
    ]
    return "\n".join(lines) + "\n"


def _missing_column_lines(tree, by_reference, column_name, qualifier, noted):
    """The hint lines for one missing column. noted: names of tables whose
    note is already in the hint (updated)."""
    # Which table it was looked for in: its qualifier (column
    # sp.purchase_order_id), else how the SQL uses it, else every table.
    qualifiers = []
    if qualifier:
        qualifiers.append(qualifier.lower())
    else:
        qualifiers += [c.table.lower() for c in tree.find_all(exp.Column)
                       if c.name.lower() == column_name.lower() and c.table]

    targets = []
    for reference in dict.fromkeys(qualifiers):
        table = by_reference.get(reference)
        if table and all(table is not t for _, t in targets):
            targets.append((reference, table))
    if not targets:
        seen = []
        for reference, table in by_reference.items():
            if all(table is not t for t in seen):
                seen.append(table)
                targets.append((reference, table))

    def has_column(table, name):
        return any(c["name"].lower() == name.lower() for c in table["columns"])

    lines = []
    for reference, table in targets:
        name = table["name"]
        shown = f"{reference}.{column_name}" if reference != name.lower() else column_name
        lines.append(f"- {shown}: {name} has no column {column_name}.")
        similar = _similar_columns(column_name, table)
        if similar:
            lines.append(f"  Closest columns in {name}: "
                         + ", ".join(column for _, column in similar))
        else:
            lines.append(f"  {name} has no similar column.")
        note = " ".join((table.get("description") or "").split())
        if note and name not in noted:
            noted.add(name)
            if len(note) > MISSING_COLUMN_NOTE_CHARS:
                note = note[:MISSING_COLUMN_NOTE_CHARS - 3] + "..."
            lines.append(f"  About {name}: {note}")

    # Another table in the query that does have it (standard_price is on
    # product_product, not product_template).
    elsewhere = []
    for reference, table in by_reference.items():
        if all(table is not t for _, t in targets) and has_column(table, column_name):
            label = f"{table['name']} ({reference})" if reference != table["name"].lower() \
                else table["name"]
            if label not in elsewhere:
                elsewhere.append(label)
    if elsewhere:
        lines.append(f"- {column_name} is a column of: {', '.join(elsewhere)}")
    return lines


# ---------------------------------------------------------------------------
# Unknown columns, before the query runs
# ---------------------------------------------------------------------------
# The catalog holds every column of each discovered table except the role's
# denied ones, and by the time this runs prepare_sql() has stripped or
# blocked every denied column. So a column the SQL names that isn't in its
# catalog table doesn't exist (or the catalog is out of date - restart after
# a schema change). Catching it here saves a database round trip and sends
# the model straight to correction with missing_column_hint().
#
# It only ever errs towards running the query: anything it can't be sure
# of is left for the database to judge.
#   - a qualified column (t.col) is checked only when t is a catalog table;
#     an alias used for several tables in different subqueries passes if
#     any of them has the column
#   - an unqualified column is checked only when every row source in the
#     query is a catalog table (no derived tables, CTEs, functions or
#     undiscovered tables), and passes if any of them has it or it is an
#     output alias somewhere in the query (ORDER BY total)


class PlaceholderError(Exception):
    """The SQL has a parameter placeholder (%s, $1, ?, :name) where a
    value belongs. Nothing fills it in, so the query runs against the
    marker itself and matches nothing; the correction is told to write a
    complete query (placeholder_hint)."""

    def __init__(self, placeholders):
        self.placeholders = list(placeholders)
        super().__init__(
            "the query has a parameter placeholder ("
            + ", ".join(self.placeholders)
            + ") where a value belongs, but no value is supplied")


def find_placeholders(sql):
    """The parameter placeholders in the SQL (%s, $1, ?, :name), as
    written, in order; [] when there are none or the SQL can't be parsed.
    Text inside string literals ('%s%') isn't a placeholder."""
    try:
        tree = parse_single_sql(sql)
    except ValueError:
        return []
    found = []
    for node in tree.find_all(exp.Placeholder, exp.Parameter):
        text = node.sql(dialect=active_engine().dialect)
        if text not in found:
            found.append(text)
    return found


def placeholder_hint(placeholders):
    """The NO PARAMETERS block for correct_sql()."""
    return (
        "NO PARAMETERS\n"
        f"- The SQL has a placeholder ({', '.join(placeholders)}) where a value\n"
        "  belongs, but nothing fills it in: the query must be complete on\n"
        "  its own.\n"
        "- If the question names the value, write it in as a literal. If it\n"
        "  doesn't (\"a particular manager\", \"a given customer\"), don't\n"
        "  filter on it: list every match with that value as a column, e.g.\n"
        "  each employee with their manager's name.\n"
    )


def has_derived_table(sql):
    """True when the SQL has a subquery in FROM or JOIN, or a WITH clause:
    the policy can't tie their columns to a real table, so it rejects
    them."""
    try:
        tree = parse_single_sql(sql)
    except ValueError:
        return False
    if tree.find(exp.CTE):
        return True
    return any(isinstance(node.parent, (exp.From, exp.Join))
               for node in tree.find_all(exp.Subquery))


class UnknownColumnError(Exception):
    """Columns the SQL names that aren't in the role's catalog (a list of
    (column, qualifier, table) from find_unknown_columns). str() is the
    engine's own "no such column" message for the first, so the
    correction step reads it like a database error; missing_column_hint()
    covers them all."""

    def __init__(self, unknown):
        self.unknown = list(unknown)
        column, qualifier, _ = self.unknown[0]
        super().__init__(active_engine().missing_column_message(column, qualifier))


def find_unknown_columns(sql, catalog):
    """
    [(column, qualifier, table name)] for every column the SQL names that
    its catalog table doesn't have, in order, each once. qualifier is the
    alias as written (None if unqualified); table is the catalog table's
    name, or None for an unqualified column. [] when all are known or the
    SQL can't be parsed. The database reports one missing column at a
    time; this finds them all, so one correction can fix them all.
    """
    try:
        tree = parse_single_sql(sql)
    except ValueError:
        return []

    tables_for = {}           # reference -> [catalog table]
    other_sources = set()     # references whose columns we can't know
    for table in tree.find_all(exp.Table):
        reference = (table.alias_or_name or table.name).lower()
        full = catalog.resolve_table_name(full_table_name(table.name, table.db))
        if full and full in catalog.tables and isinstance(table.this, exp.Identifier):
            entry = catalog.tables[full]
            for key in {reference, table.name.lower()}:
                bucket = tables_for.setdefault(key, [])
                if all(entry is not t for t in bucket):
                    bucket.append(entry)
        else:
            other_sources.add(reference)
    for node in tree.find_all(exp.Subquery, exp.CTE, exp.Unnest, exp.Lateral):
        if node.alias:
            other_sources.add(node.alias.lower())
    has_other = bool(other_sources) or any(
        isinstance(source, (exp.Subquery, exp.Unnest, exp.Lateral))
        for source in _row_sources(tree))

    output_names = {a.alias.lower() for a in tree.find_all(exp.Alias) if a.alias}
    for table_alias in tree.find_all(exp.TableAlias):
        output_names.update(c.name.lower() for c in table_alias.columns)

    def has(table, name):
        return any(c["name"].lower() == name for c in table["columns"])

    every_table = [t for bucket in tables_for.values() for t in bucket]

    unknown, seen = [], set()
    for column in tree.find_all(exp.Column):
        if isinstance(column.this, exp.Star) or not column.name:
            continue
        name = column.name.lower()
        if column.table:
            qualifier = column.table.lower()
            if qualifier in other_sources or qualifier not in tables_for:
                continue
            candidates = tables_for[qualifier]
            if any(has(t, name) for t in candidates):
                continue
            found = (column.name, column.table, candidates[0]["name"])
        else:
            if has_other or name in output_names or not every_table:
                continue
            if any(has(t, name) for t in every_table):
                continue
            found = (column.name, None, None)
        key = (found[0].lower(), (found[1] or "").lower())
        if key not in seen:
            seen.add(key)
            unknown.append(found)
    return unknown


def _row_sources(tree):
    """Every FROM / JOIN source in the query, at any depth."""
    for select in tree.find_all(exp.Select):
        from_clause = select.args.get("from_") or select.args.get("from")
        if from_clause:
            yield from_clause.this
        for join in select.args.get("joins") or []:
            yield join.this
