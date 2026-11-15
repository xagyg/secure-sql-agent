# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Changes for PostgreSQL / API use:
#   - the artificial-limit stripping regex now matches Postgres's
#     "LIMIT n" instead of SQL Server's "TOP n"
#   - every exit point now returns a dict ({"answer", "blocked", "sql"})
#     in addition to the existing print() calls, so a caller other than
#     the REPL (e.g. an HTTP API) can get the result back directly,
#     instead of scraping stdout or reading conversation_history after
#     the fact. The REPL's own printed output is unchanged.
#   - results now also carry a "reason" ("policy" | "error" | None) so a
#     caller can tell a guardrail stopping a request apart from a
#     technical failure. Only "policy" results have blocked=True.
#   - policy results also carry "rule" / "rule_label" (see BLOCK_RULES in
#     messages.py): a stable code plus a short, generic label that
#     is safe to show in the UI. Detailed reasons stay in the console.


import re

from sqlagent.controls.messages import (
    WITHHELD_LABEL,
    WITHHELD_NOTE,
    WITHHELD_RULE,
    block_rule,
    clarify_message,
    no_query_message,
    off_topic_message,
    overview_message,
    rule_label,
    rule_message,
)
from sqlagent.controls.question_policy import (
    follow_up_asks_restricted,
    is_overview_question,
    mentions_denied_column,
)
from sqlagent.controls.result_policy import apply_result_policy
from sqlagent.controls.sql_policy import MAX_ROWS, prepare_sql
from sqlagent.adaptive.history import format_results_table, summarise_result
from sqlagent.adaptive.llm import (
    CORRECTION_SQL_CHARS,
    HISTORY_SAMPLE_ROWS,
    HISTORY_SUMMARY_CHARS,
    HISTORY_VALUE_CHARS,
    MAX_HISTORY_TURNS,
    classify_model_output,
    looks_like_write_request,
    correct_sql,
    explain_results,
    generate_sql,
)
from sqlagent.adaptive.domains import parse_context_tags
from sqlagent.controls.row_scope import RowScopeError, apply_row_scope
from sqlagent.execution.engines import active_dialect, active_engine
from sqlagent.execution.sql_diagnostics import (
    diagnose_sql_error,
    PlaceholderError,
    UnknownColumnError,
    find_placeholders,
    has_derived_table,
    placeholder_hint,
    similar_tables,
    find_unknown_columns,
    json_correction_hint,
    missing_column_hint,
)
from sqlagent.execution.sql_execution import execute_sql_with_sources
from sqlagent.settings import get_settings
from sqlagent.adaptive.text_match import tokenize


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

def _validation_reason_kind(reason):
    """
    Classify a validate_agent_sql() failure.

    A query the parser couldn't read is a technical failure, not a
    guardrail firing, so it is reported as "error". Everything else
    (restricted table/column, non read-only, multiple statements) is
    a policy decision.
    """
    if "could not be parsed" in reason.lower():
        return "error"
    return "policy"


def _result(answer, sql=None, *, blocked=False, reason=None, rule=None,
            label=None, outcome=None, row_count=None):
    """
    The dict run_agent() returns (see its docstring). rule_label is taken
    from BLOCK_RULES unless label is given.
    """
    if label is None and rule is not None:
        label = rule_label(rule)
    return {
        "answer": answer,
        "blocked": blocked,
        "reason": reason,
        "rule": rule,
        "rule_label": label,
        "sql": sql,
        "outcome": outcome,
        "row_count": row_count,
    }


def _policy_block(rule, sql=None):
    """A guardrail stopped the request: log and return the rule's
    generic message."""
    message = rule_message(rule)
    print(f"\n[answer] {message}")
    return _result(message, sql, blocked=True, reason="policy", rule=rule)


def _not_available(question, security, sql=None, corrected=False):
    """
    The model said the data isn't in the schema (DATA_NOT_AVAILABLE),
    first time or (corrected) in a rewrite: "restricted" when the
    question names a column this role is denied, otherwise "not
    available".
    """
    if mentions_denied_column(question, security):
        print("\n[security] Question refers to a restricted column.")
        return _policy_block("restricted_data", sql)
    if corrected:
        print("\n[agent] Correction: the requested data isn't in the "
              "authorised schema.")
    else:
        print("\n[security] Requested data isn't in the authorised schema.")
    return _policy_block("not_available", sql)


def _error(message, sql=None):
    """A technical failure (not a guardrail)."""
    return _result(message, sql, reason="error")


def _validation_failure(reason, sql):
    """Build the result dict for a validate_agent_sql() failure."""
    print(f"\n[security] {reason}")

    rule = block_rule(reason)

    if _validation_reason_kind(reason) == "policy":
        return _policy_block(rule, sql)

    message = rule_message(rule)
    print(f"\n[answer] {message}")
    return _error(message, sql)


def _prepare_sql(sql, security, catalog, table_retry=False):
    """
    Make generated SQL safe to run (see sql_policy.prepare_sql) and log
    each change. Used for the first query and for a corrected one, so
    both get exactly the same checks.

    Returns (sql, withheld, failure): failure is a result dict when
    validation stopped the query, else None. Errors from the rewrite
    step are raised for the caller to report. With table_retry (the
    first attempt only), a query stopped ONLY because it reads a table
    outside the role's schema gives failure = {"retry_table": name,
    "reason": ...} instead, for _retry_unavailable_table(), and one the
    parser couldn't read gives {"retry_parse": True, "reason": ...}, for
    _retry_unparseable().
    """
    prepared = prepare_sql(sql, security, catalog)

    if prepared.withheld:
        print(f"\n[security] Restricted column(s) withheld: "
              f"{', '.join(prepared.withheld)}")
        print("\n[sql after withholding]")
        print(prepared.stripped_sql)

    if prepared.rewritten:
        print("\n[sql after rewrite]")
        print(prepared.sql)

    failure = None
    if prepared.failure_reason:
        table = _unauthorised_table(prepared.failure_reason) if table_retry else None
        if table:
            print(f"\n[security] {prepared.failure_reason}")
            failure = {"retry_table": table, "reason": prepared.failure_reason}
        elif table_retry and _validation_reason_kind(prepared.failure_reason) == "error":
            print(f"\n[security] {prepared.failure_reason}")
            failure = {"retry_parse": True, "reason": prepared.failure_reason}
        elif table_retry and has_derived_table(sql):
            # A subquery in FROM / JOIN (or a WITH): its columns can't be
            # tied to a real table, so the policy rejects the query. Not
            # a security issue - one rewrite without them.
            print(f"\n[sql] {prepared.failure_reason} (a subquery in FROM "
                  "or JOIN, which can't be checked)")
            failure = {"retry_parse": True, "reason": prepared.failure_reason,
                       "hint": _DERIVED_TABLE_HINT,
                       "action": "rewrite it without subqueries in FROM"}
        else:
            failure = _validation_failure(prepared.failure_reason, prepared.sql)

    return prepared.sql, prepared.withheld, failure


# ---------------------------------------------------------------------------
# A table outside the role's schema: one retry
# ---------------------------------------------------------------------------
# The model sometimes writes a table it remembers rather than one it was
# shown (timesheet_line, account_payment_rel). That used to end the request
# as "restricted". Now it gets one rewrite using only the schema it was
# given, or DATA_NOT_AVAILABLE. Nothing leaks: the hint names only the
# table the model wrote itself, and says the same whether that table is
# hidden from the role or doesn't exist. The hint tells the model not to
# answer from a table that means something else, so a question for
# restricted data ("show me the payslips") ends as DATA_NOT_AVAILABLE, not
# as an answer from a different table. Every rewrite gets this one try;
# there is no word-matching on the question to decide.

_UNAUTHORISED_TABLE = re.compile(r"^Table '([^']+)' is not authorised\.$")


def _unauthorised_table(reason):
    """The table a "Table 'x' is not authorised." reason names, or None
    (any other validation failure is never retried)."""
    match = _UNAUTHORISED_TABLE.match(reason.strip())
    return match.group(1) if match else None


def _retry_unavailable_table(question, schema, sql, failure, security, catalog):
    """
    One rewrite of a query stopped for reading a table outside the role's
    schema. Returns (sql, withheld, failure) from _prepare_sql() on the
    rewrite, or a finished result dict (blocked / not available / error).
    """
    table = failure["retry_table"]
    reason = failure["reason"]
    bare = table.split(".")[-1]

    # Closest tables only for a name the model invented ("order details"
    # for order_details). A real table this role can't see means
    # something of its own: the closest name (salesorderheader for
    # purchaseorderheader) would be a different thing. Only tables the
    # role can see are suggested, so the hint never names a hidden one.
    closest = []
    if bare.strip('"[]`').lower() not in catalog.database_table_names:
        visible = [t for t in catalog.tables
                   if not security.tables or t in security.tables]
        closest = similar_tables(bare, visible)
    if closest:
        print(f"\n[sql] Closest table(s) to {bare}: {', '.join(closest)}")

    hint = (
        "TABLE NOT AVAILABLE\n"
        f"- {bare} is not in the schema you were given.\n"
        + (f"- Closest tables in the schema: {', '.join(closest)}\n"
           if closest else "") +
        "Use only the tables listed in DATABASE SCHEMA. If the question needs\n"
        "data that isn't in them, return exactly DATA_NOT_AVAILABLE - do not\n"
        "answer it from a table that means something else.\n"
    )
    print(f"\n[agent] Asking Ollama to rewrite it without {bare}...")
    try:
        corrected = correct_sql(question, schema, sql,
                                f"Table {bare} is not available.", hint)
    except Exception as ex:
        print(f"\n[CORRECTION ERROR] {ex}")
        return _error("I couldn't correct that query.", sql)

    print("\n[corrected sql]")
    print(corrected)

    if classify_model_output(corrected) == "not_available":
        return _not_available(question, security, sql, corrected=True)

    if _normalise_sql(corrected) == _normalise_sql(sql):
        print("\n[agent] Correction produced the same SQL. Stopping.")
        return _policy_block(block_rule(reason), sql)

    try:
        return _prepare_sql(corrected, security, catalog)
    except Exception as ex:
        print(f"\n[error] {ex}")
        message = "I couldn't safely prepare the query for execution."
        print(f"\n[answer] {message}")
        return _error(message, corrected)


# ---------------------------------------------------------------------------
# SQL the parser couldn't read: one retry
# ---------------------------------------------------------------------------
# Usually a pattern copied wrongly - e.g. the financial-year lookup written
# as a second FROM after the WHERE. Nothing was run and nothing is unsafe
# about asking again: the rewrite goes through every check in
# _prepare_sql() like any other query, and a second parse failure ends it.

_DERIVED_TABLE_HINT = (
    "SUBQUERY IN FROM NOT ALLOWED\n"
    "- Subqueries in FROM or JOIN, and WITH clauses, are rejected: their\n"
    "  columns can't be checked against real tables.\n"
    "- Read the base tables directly. To compare periods, use conditional\n"
    "  aggregation, e.g. SUM(CASE WHEN so.date_order >= ... THEN\n"
    "  so.amount_total ELSE 0 END) AS this_year, and compare the two sums\n"
    "  in HAVING. A single lookup can be a subquery in WHERE or SELECT.\n"
)


def _retry_unparseable(question, schema, sql, failure, security, catalog):
    """
    One rewrite of a query the parser couldn't read, or (failure["hint"])
    one with a subquery in FROM. Returns (sql, withheld, failure) from
    _prepare_sql() on the rewrite, or a finished result dict (not
    available / error).
    """
    hint = failure.get("hint") or (
        "SQL COULD NOT BE PARSED\n"
        "- The query is not valid SQL. Write ONE SELECT statement with a\n"
        "  single FROM clause. Put any lookup it needs from another table\n"
        "  in a subquery in the WHERE clause, e.g. col > (SELECT ... FROM\n"
        "  other_table t WHERE t.id = x.other_id) - never a second FROM\n"
        "  after the WHERE. WITH (CTEs) and subqueries in FROM are not\n"
        "  allowed.\n"
    )
    print(f"\n[agent] Asking Ollama to {failure.get('action', 'rewrite it as valid SQL')}...")
    try:
        corrected = correct_sql(question, schema, _sql_for_correction(sql, sql),
                                _sanitize_sql_error_for_llm(failure["reason"]), hint)
    except Exception as ex:
        print(f"\n[CORRECTION ERROR] {ex}")
        return _error("I couldn't correct that query.", sql)

    print("\n[corrected sql]")
    print(corrected)

    if classify_model_output(corrected) == "not_available":
        return _not_available(question, security, sql, corrected=True)

    if _normalise_sql(corrected) == _normalise_sql(sql):
        print("\n[agent] Correction produced the same SQL. Stopping.")
        return _validation_failure(failure["reason"], sql)

    try:
        return _prepare_sql(corrected, security, catalog)
    except Exception as ex:
        print(f"\n[error] {ex}")
        message = "I couldn't safely prepare the query for execution."
        print(f"\n[answer] {message}")
        return _error(message, corrected)


def _check_before_running(sql, catalog):
    """
    The pre-run check: SQL that is valid - it parses and the database
    would accept it - but can't give a correct answer. Each finding
    raises an error the correction step has a hint for, so the query is
    corrected without a database round trip:

      - an unfilled parameter placeholder (%s, $1, ?, :name): it would
        run against the marker itself (PlaceholderError)
      - a column that isn't in the role's catalog (UnknownColumnError;
        only with query.check_columns, see find_unknown_columns)
    """
    placeholders = find_placeholders(sql)
    if placeholders:
        print(f"\n[sql] Pre-run check: unfilled placeholder "
              f"{', '.join(placeholders)}")
        raise PlaceholderError(placeholders)
    if not get_settings().query.check_columns:
        return
    unknown = find_unknown_columns(sql, catalog)
    if unknown:
        names = ", ".join(
            f"{qualifier}.{column}" if qualifier else column
            for column, qualifier, _ in unknown)
        print(f"\n[sql] Pre-run check: not in the schema - {names}")
        raise UnknownColumnError(unknown)


# The answer to a query that ran and matched nothing.
NO_ROWS_ANSWER = ("No matching records were found. If you expected some, "
                  "try rephrasing the question or checking the spelling "
                  "of any names.")


def _results_without_explanation(results, withheld):
    """The answer when the LLM explanation is skipped: the row count,
    anything withheld, and the first rows as a table."""
    count = len(results)
    lines = [f"{count} row(s)"
             + (f" (the row limit of {MAX_ROWS}; there may be more)"
                if count >= MAX_ROWS else "") + "."]
    if withheld:
        lines.append(f"Withheld by policy: {', '.join(sorted(set(withheld)))}.")
    lines += ["", format_results_table(results)]
    return "\n".join(lines)


def _sql_for_correction(sql, generated_sql):
    """
    The SQL to show the model when asking it to fix a failed query: the
    prepared SQL that ran, unless that is over llm.correction_sql_chars
    (SELECT * expanded to hundreds of columns), when the model's own SQL
    is shorter and enough to fix. A 300-column SELECT list once pushed
    the correction past the read timeout.
    """
    if len(sql) > CORRECTION_SQL_CHARS and generated_sql \
            and len(generated_sql) < len(sql):
        print(f"\n[agent] The prepared SQL is long ({len(sql)} characters) - "
              "showing the model its own SQL for the correction")
        return generated_sql
    return sql


def _normalise_sql(sql):
    """For comparing two queries: case, whitespace and a trailing ";"
    ignored."""
    return " ".join(sql.strip().rstrip(";").split()).lower()


def _sanitize_sql_error_for_llm(error_text):
    """
    Remove schema detail (PostgreSQL's DETAIL/HINT sections, say) before
    sending a database error to Ollama; see the engine's sanitize_error().

    The full database error remains available locally for diagnostics, but
    hints/details must not disclose physical schema information to the
    correction model.
    """
    return active_engine().sanitize_error(error_text)


def _available_areas(catalog):
    """
    The Domain of Discourse labels this role can see (domains with at
    least one authorised table). Labels are generic ("Sales"), never
    table names, so they are safe to show the user.
    """
    resolver = getattr(catalog, "domain_resolver", None)
    if resolver is None:
        return []
    return [
        domain["label"]
        for key, domain in resolver.domains.items()
        if resolver.domain_tables.get(key)
    ]


def run_agent(question, catalog, history, security, explain=True):
    """
    Complete agent cycle:

        User
          ↓
        Who / What / Where -> Domain of Discourse
          ↓
        Partial schema (domain anchors + relationship hops)
          ↓
        Conversation History
          ↓
        Ollama
          ↓
        SQL
          ↓
        Structural Safety
          ↓
        Authorisation
          ↓
        SELECT * Rewrite
          ↓
        Query Limit
          ↓
        Re-validation
          ↓
        Database (PostgreSQL)
          ↓
        Results
          ↓
        Ollama
          ↓
        Explanation
          ↓
        Conversation History

    Returns a dict:
        {
            "answer":  str,
            "blocked": bool,               # True only when policy stopped it
            "reason":  "policy" | "error" | None,
            "rule":    str | None,         # rule code, policy blocks only
            "rule_label": str | None,      # short UI label, policy blocks only
            "sql":     str | None,
            "domain":  str | None,         # Domain of Discourse label
            "outcome": str | None,         # answered without SQL: "unclear",
                                           # "off_topic", "overview",
                                           # "no_question"
            "row_count": int | None,       # rows returned, when a query ran
        }

    reason:
        "policy" - a guardrail stopped the request (blocked=True), or
                   the query ran with restricted columns left out
                   (blocked=False, rule="fields_withheld")
        "error"  - a technical failure, e.g. the query couldn't be
                   prepared or corrected (blocked=False)
        None     - the query ran normally
    """
    # ---------------------------------------------------------
    # Who / What / Where -> Domain of Discourse (see domains.py)
    # ---------------------------------------------------------
    # [where=...] / [who=...] tags are removed here, so neither the
    # LLM nor the conversation history ever sees them.
    context = parse_context_tags(question)
    question = context.question

    if context.where or context.who:
        print(f"\n[context] where={context.where!r} who={context.who!r}")

    if not question:
        result = _result("Please add a question to go with the context tag.",
                         outcome="no_question")
        result["domain"] = None
        return result

    # ---------------------------------------------------------
    # A question about the database itself ("What does Northwind
    # have?"). Answered from the areas this role can see; no model
    # call, no SQL.
    # ---------------------------------------------------------
    if is_overview_question(question):
        print("\n[agent] Question about the database itself; "
              "listing the available areas.")
        message = overview_message(_available_areas(catalog))
        print(f"\n[answer] {message}")
        result = _result(message, outcome="overview")
        result["domain"] = None
        return result

    # ---------------------------------------------------------
    # Something this database doesn't record (semantic model
    # not_recorded, e.g. Odoo timesheets): "not available", decided
    # here rather than by the model, which kept answering from columns
    # that only looked similar.
    # ---------------------------------------------------------
    missing = catalog.semantic.not_recorded_match(tokenize(question))
    if missing:
        name, phrase, description = missing
        print(f"\n[semantic] Not recorded in this database: {name} "
              f"(the question says \"{phrase}\")"
              + (f" - {description}" if description else ""))
        result = _policy_block("not_available")
        result["domain"] = None
        return result

    resolver = catalog.domain_resolver
    previous_domain = history[-1].get("domain") if history else None

    # The last turn that returned rows. A query that found nothing (e.g.
    # the model guessed the wrong table) mustn't redirect the
    # conversation, so follow-ups anchor on this turn's tables. Turns
    # recorded before row_count was stored count as having rows.
    anchor_turn = next(
        (turn for turn in reversed(history) if turn.get("row_count", 1) > 0),
        None,
    )

    decision = resolver.resolve(
        question,
        roles=security.roles if security else (),
        where=context.where,
        who=context.who,
        previous_domain=previous_domain,
    )
    print(f"\n[domain] {decision.summary()}")

    print("\n[agent] Generating SQL...")

    # A follow-up - only weak evidence ("What is Thomas's full name?") or
    # none at all ("What information do you have about Jose?") - starts
    # from the tables the previous query used, not from every table whose
    # column words happen to match or the domain's fallback list (which
    # e.g. adds employees and makes "Jose" ambiguous). Only tables in the
    # role's catalog are used.
    anchors = None
    if decision.mode == "follow_up" and anchor_turn:
        anchors = catalog.tables_in_sql(anchor_turn.get("sql"))
        if anchors:
            names = ", ".join(sorted(anchors))
            print(f"\n[schema] Follow-up - starting from the previous "
                  f"query's tables: {names}")

    # ---------------------------------------------------------
    # The follow-up asks for something restricted on the table the
    # conversation is about ("What is Thomas's address?" after a
    # customers query). Answer now, before the model can substitute an
    # unrestricted look-alike from a neighbouring table (orders.
    # ship_address) and report "not found" instead.
    # ---------------------------------------------------------
    if anchors and follow_up_asks_restricted(question, security, catalog, anchors):
        print("\n[security] Follow-up asks for a column restricted on "
              "the conversation's table.")
        result = _policy_block("restricted_data")
        result["domain"] = decision.label
        return result

    schema = catalog.discover_schema(
        question, scope=resolver.scope(decision), anchors=anchors or None)

    print(f"\n[schema] Retrieved context: {len(schema.splitlines())} lines, "
          f"{catalog.context_summary(schema)}")

    result = _run_pipeline(
        question, catalog, history, security, schema,
        decision.domains[0] if decision.domains else None,
        explain=explain,
    )
    # The domain label is generic ("Purchasing & Inventory"), so it is
    # safe to show in the UI. Table names are never returned.
    result["domain"] = decision.label
    return result


def _execute(sql, security):
    """
    Apply the user's row scope, run the query and apply the result
    policy. Returns (rows, removed), where removed lists result columns
    taken out by policy.

    Row scope is applied here, just before execution, so every query -
    first try or corrected - gets it, and the rest of the pipeline (the
    correction and explanation steps, the conversation history) keeps
    the SQL as the model wrote it: the user's entitlements never reach a
    prompt. RowScopeError propagates; the caller blocks the query.
    """
    scoped_sql = apply_row_scope(sql, security.row_filters, active_dialect())
    if scoped_sql != sql:
        print("\n[security] Row scope applied:")
        print(scoped_sql)
    results, sources = execute_sql_with_sources(scoped_sql)
    results, removed = apply_result_policy(results, security, sources)

    if removed:
        print(f"\n[security] Result column(s) withheld: {', '.join(removed)}")

    return results, removed


def _all_withheld(results):
    """True when the query returned rows but the result policy removed
    every column, so there is nothing left to explain."""
    return bool(results) and all(not row for row in results)


def _run_pipeline(question, catalog, history, security, schema, domain_key,
                  explain=True):
    """
    Generate, control, execute and explain - unchanged by domains. Each
    step returns a finished result dict when it ends the request.
    """
    sql = generate_sql(question, schema, history, allowed_tables=catalog.tables)
    generated_sql = sql   # as the model wrote it, before any rewriting

    print("\n[sql]")
    print(sql)

    finished = _answer_without_sql(question, sql, security, catalog)
    if finished:
        return finished

    prepared = _prepare_with_retries(question, schema, sql, security, catalog)
    if isinstance(prepared, dict):
        return prepared
    sql, withheld = prepared

    ran = _execute_with_correction(question, schema, sql, generated_sql,
                                   withheld, security, catalog)
    if isinstance(ran, dict):
        return ran
    sql, results, withheld = ran

    return _answer_from_results(question, sql, results, withheld, history,
                                domain_key, explain)


# ---------------------------------------------------------------------------
# Step 1: did the model return a query at all?
# ---------------------------------------------------------------------------
def _answer_without_sql(question, sql, security, catalog):
    """The result for a reply that isn't SQL (a marker or prose), or None
    when it is SQL and the pipeline goes on."""
    output_kind = classify_model_output(sql)

    if output_kind == "write_request" and not looks_like_write_request(question):
        # The model used the write marker for a read-only question it
        # couldn't answer: either it asks for something restricted
        # ("what is joe's phone number?") or it was too vague ("what
        # does Northwind have?"). The marker says nothing about which,
        # so it is NOT reported as "not available / may be restricted":
        # that blamed security for a vague question.
        print("\n[agent] Write marker without write intent; "
              "treating as an unclear question.")
        output_kind = "unclear"

    if output_kind == "unclear":
        if mentions_denied_column(question, security):
            print("\n[security] Question refers to a restricted column.")
            return _policy_block("restricted_data")
        print("\n[agent] Question too vague to answer with one query.")
        message = clarify_message(_available_areas(catalog))
        print(f"\n[answer] {message}")
        return _result(message, outcome="unclear")

    if output_kind == "not_available":
        return _not_available(question, security)

    if output_kind == "write_request":
        # The model recognised a request to modify data and declined to
        # write SQL. Report it as the same read-only policy block the
        # validator would give a DELETE/UPDATE, rather than as a
        # parse failure ("couldn't be validated").
        print("\n[security] Request to modify data; read-only access.")
        return _policy_block("read_only")

    if output_kind == "off_topic":
        print("\n[agent] Not a data question.")
        message = off_topic_message()
        print(f"\n[answer] {message}")
        return _result(message, outcome="off_topic")

    if output_kind == "no_sql":
        print("\n[agent] Model did not return a SQL statement.")
        message = no_query_message()
        print(f"\n[answer] {message}")
        return _error(message)

    return None


# ---------------------------------------------------------------------------
# Step 2: strip, validate, rewrite, re-validate (see _prepare_sql), with
# one rewrite for an unavailable table and one for SQL that won't parse
# ---------------------------------------------------------------------------
def _prepare_with_retries(question, schema, sql, security, catalog):
    """(sql, withheld) ready to run, or a finished result dict."""
    generated_sql = sql
    try:
        sql, withheld, failure = _prepare_sql(sql, security, catalog,
                                              table_retry=True)
    except Exception as ex:
        print(f"\n[error] {ex}")
        message = "I couldn't safely prepare the query for execution."
        print(f"\n[answer] {message}")
        return _error(message, sql)

    if failure and "retry_table" in failure:
        retried = _retry_unavailable_table(
            question, schema, generated_sql, failure, security, catalog)
        if isinstance(retried, dict):
            return retried
        sql, withheld, failure = retried

    if failure and "retry_parse" in failure:
        retried = _retry_unparseable(
            question, schema, generated_sql, failure, security, catalog)
        if isinstance(retried, dict):
            return retried
        sql, withheld, failure = retried

    if failure:
        return failure
    return sql, withheld


# ---------------------------------------------------------------------------
# Step 3: execute, with one correction when the query can't run
# ---------------------------------------------------------------------------
def _execute_with_correction(question, schema, sql, generated_sql, withheld,
                             security, catalog):
    """(sql that ran, rows, withheld) or a finished result dict."""
    print("\n[agent] Executing SQL...")

    try:
        _check_before_running(sql, catalog)
        results, removed = _execute(sql, security)
        return sql, results, withheld + removed
    except RowScopeError as ex:
        print(f"\n[security] Row scope could not be applied: {ex}")
        return _policy_block("policy", sql)
    except Exception as ex:
        failed = ex

    if isinstance(failed, (UnknownColumnError, PlaceholderError)):
        print("[agent] Not run: correcting it first.")
    else:
        print(f"\n[SQL ERROR] {failed}")

    correction_hint = _correction_hint(sql, failed, security, catalog)
    if isinstance(correction_hint, dict):
        return correction_hint

    print("\n[agent] Asking Ollama to correct SQL...")

    try:
        corrected_sql = correct_sql(
            question, schema,
            _sql_for_correction(sql, generated_sql),
            _sanitize_sql_error_for_llm(str(failed)), correction_hint
        )

        print("\n[corrected sql]")
        print(corrected_sql)

        # The hint said nothing similar exists and the model agreed:
        # the data isn't in the schema. Same answer as when the first
        # attempt says so (a restricted column is still reported as
        # restricted).
        if classify_model_output(corrected_sql) == "not_available":
            return _not_available(question, security, sql, corrected=True)

        # Compare with what the model first wrote, not the prepared
        # SQL: that has LIMIT 1000 (and maybe rewrites) added, so the
        # two never matched and the failing query was run again.
        if _normalise_sql(corrected_sql) in {
            _normalise_sql(generated_sql), _normalise_sql(sql)
        }:
            print("\n[agent] Correction produced the same SQL. Stopping.")
            return _error("I wasn't able to correct that query.", sql)

        # Re-run ALL the checks on the corrected SQL
        corrected_sql, corrected_withheld, failure = _prepare_sql(
            corrected_sql, security, catalog)
        withheld = withheld + corrected_withheld

        if failure:
            return failure

        print("\n[agent] Executing corrected SQL...")

        _check_before_running(corrected_sql, catalog)
        results, removed = _execute(corrected_sql, security)
        return corrected_sql, results, withheld + removed

    except RowScopeError as ex:
        print(f"\n[security] Row scope could not be applied: {ex}")
        return _policy_block("policy", sql)
    except Exception as correction_error:
        print(f"\n[CORRECTION ERROR] {correction_error}")
        return _error("I couldn't correct that query.", sql)


def _correction_hint(sql, ex, security, catalog):
    """
    The hint for correct_sql() about why `sql` failed with `ex` ("" when
    there is none), or a finished result dict when the failure itself
    answers the request (a business word for a restricted column).
    """
    if isinstance(ex, PlaceholderError):
        return placeholder_hint(ex.placeholders)

    correction_hint = ""
    diagnosis = diagnose_sql_error(sql, ex, security, catalog.semantic)
    if diagnosis:
        print(f"\n[sql] Error type: {diagnosis['error_type']}")
        print(f"[sql] Invalid column: {diagnosis['column']}")

        if diagnosis.get("tables"):
            print("[sql] Referenced tables:")
            for table in diagnosis["tables"]:
                print(f"  {table}")

        if diagnosis["error_type"] == "invalid_column_alias_denied":
            match = diagnosis["matches"][0]
            print(
                f"\n[security] Column "
                f"'{diagnosis['column']}' "
                f"maps to restricted column "
                f"'{match['table']}.{match['column']}'."
            )
            return _policy_block("restricted_data", sql)

        if diagnosis["error_type"] == "invalid_column_alias_authorised":
            match = next(
                item for item in diagnosis["matches"] if item["authorised"]
            )
            correction_hint = (
                "KNOWN COLUMN MAPPING\n"
                f"- {diagnosis['column']} -> "
                f"{match['table']}.{match['column']}\n"
                "Use the physical column in the corrected SQL.\n"
            )

    # A column that doesn't exist: name the table, its closest real
    # columns and its note, so the retry doesn't send the same SQL
    # back (see sql_diagnostics.missing_column_hint).
    if not correction_hint:
        correction_hint = missing_column_hint(
            sql, ex, catalog,
            unknown=ex.unknown if isinstance(ex, UnknownColumnError) else None)
        if correction_hint:
            print("\n[sql] Missing column hint for the correction:")
            print(correction_hint.rstrip())

    # A json/jsonb column used as text or a number: name the columns
    # and how to read them, so the retry fixes the right one instead
    # of stripping a correct ->> (see sql_diagnostics.py).
    if not correction_hint:
        correction_hint = json_correction_hint(sql, ex, catalog)
        if correction_hint:
            print("\n[sql] JSON column hint for the correction:")
            print(correction_hint.rstrip())

    return correction_hint


# ---------------------------------------------------------------------------
# Step 4: the answer, and the turn recorded in the conversation history
# ---------------------------------------------------------------------------
def _answer_from_results(question, sql, results, withheld, history,
                         domain_key, explain):
    """Explain (or list) the rows, record the turn, and build the result."""
    print(f"[agent] {len(results)} row(s) returned.")

    # ---------------------------------------------------------
    # Every returned column was withheld. Don't ask the model to
    # explain empty rows: it reads them as "no match" and says the
    # record doesn't exist, which is wrong. The message neither
    # confirms nor denies that the record exists.
    # ---------------------------------------------------------
    if _all_withheld(results):
        print("\n[security] Every result column was withheld.")
        return _policy_block("not_found_or_restricted", sql)

    print("\n[agent] Asking Ollama to interpret the results...")

    # Remove the artificial row cap (MAX_ROWS) from the SQL supplied to
    # the explanation model so that it doesn't incorrectly attribute the
    # result to the user's question. How the cap is written ("LIMIT n" on
    # Postgres) is the engine's.
    explanation_sql = active_engine().strip_row_limit(sql, MAX_ROWS)

    if explain and not results:
        # No rows: a fixed answer, not an LLM call. Asked to explain an
        # empty result, the model padded it with troubleshooting advice
        # ("check the country code") that didn't apply.
        explanation = NO_ROWS_ANSWER
        print("\n[answer]")
    elif explain:
        explanation = explain_results(
            question, explanation_sql, results, withheld=sorted(set(withheld)),
            row_cap=MAX_ROWS,
        )
        print("\n[answer]")
    else:
        # explain=False (main.py --no-explain): the rows themselves, built
        # by code. Everything that protects the result - withheld columns,
        # the result policy - already ran in _execute().
        explanation = _results_without_explanation(results, withheld)
        print("\n[answer] (explanation skipped)")
    print(explanation)

    history.append({
        "question": question,
        "sql": explanation_sql,
        "answer": explanation,
        # What the next SQL prompt sees instead of the prose answer.
        # Built from the rows after the result policy, so withheld
        # columns never reach it.
        "result_summary": summarise_result(
            results,
            sample_rows=HISTORY_SAMPLE_ROWS,
            max_value_chars=HISTORY_VALUE_CHARS,
            max_chars=HISTORY_SUMMARY_CHARS,
            row_cap=MAX_ROWS,
            withheld=sorted(set(withheld)),
        ),
        "domain": domain_key,
        "row_count": len(results),
    })

    if len(history) > MAX_HISTORY_TURNS:
        del history[:-MAX_HISTORY_TURNS]

    if withheld:
        # The query ran, but without the restricted columns. Report it
        # with a "fields withheld" tag so the guardrail is visible.
        # blocked stays False: the question WAS answered.
        return _result(
            f"{explanation}\n\n_{WITHHELD_NOTE}_", explanation_sql,
            reason="policy", rule=WITHHELD_RULE, label=WITHHELD_LABEL,
            row_count=len(results),
        )

    return _result(explanation, explanation_sql, row_count=len(results))
