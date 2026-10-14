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
    NO_QUERY_MESSAGE,
    OFF_TOPIC_MESSAGE,
    WITHHELD_LABEL,
    WITHHELD_NOTE,
    WITHHELD_RULE,
    block_rule,
    clarify_message,
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
from sqlagent.adaptive.llm import (
    MAX_HISTORY_TURNS,
    classify_model_output,
    looks_like_write_request,
    correct_sql,
    explain_results,
    generate_sql,
)
from sqlagent.adaptive.domains import parse_context_tags
from sqlagent.execution.sql_diagnostics import diagnose_sql_error
from sqlagent.execution.sql_execution import execute_sql_with_sources


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
            label=None):
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
    }


def _policy_block(rule, sql=None):
    """A guardrail stopped the request: log and return the rule's
    generic message."""
    message = rule_message(rule)
    print(f"\n[answer] {message}")
    return _result(message, sql, blocked=True, reason="policy", rule=rule)


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


def _prepare_sql(sql, security, catalog):
    """
    Make generated SQL safe to run (see sql_policy.prepare_sql) and log
    each change. Used for the first query and for a corrected one, so
    both get exactly the same checks.

    Returns (sql, withheld, failure): failure is a result dict when
    validation stopped the query, else None. Errors from the rewrite
    step are raised for the caller to report.
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
        failure = _validation_failure(prepared.failure_reason, prepared.sql)

    return prepared.sql, prepared.withheld, failure


def _normalise_sql(sql):
    """For comparing two queries: case, whitespace and a trailing ";"
    ignored."""
    return " ".join(sql.strip().rstrip(";").split()).lower()


def _sanitize_sql_error_for_llm(error_text):
    """
    Remove PostgreSQL DETAIL/HINT sections before sending an error to Ollama.

    The full database error remains available locally for diagnostics, but
    PostgreSQL hints/details must not disclose physical schema information
    to the correction model.
    """
    return re.sub(
        r"(?ms)^\s*(?:DETAIL|HINT):.*?(?=^\s*(?:DETAIL|HINT):|\Z)",
        "",
        error_text,
    ).strip()


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


def run_agent(question, catalog, history, security):
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
        PostgreSQL
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
        result = _result("Please add a question to go with the context tag.")
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
        result = _result(message)
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

    print(f"\n[schema] Retrieved context: {len(schema.splitlines())} lines")

    result = _run_pipeline(
        question, catalog, history, security, schema,
        decision.domains[0] if decision.domains else None,
    )
    # The domain label is generic ("Purchasing & Inventory"), so it is
    # safe to show in the UI. Table names are never returned.
    result["domain"] = decision.label
    return result


def _execute(sql, security):
    """Run the query and apply the result policy. Returns (rows,
    removed), where removed lists result columns taken out by policy."""
    results, sources = execute_sql_with_sources(sql)
    results, removed = apply_result_policy(results, security, sources)

    if removed:
        print(f"\n[security] Result column(s) withheld: {', '.join(removed)}")

    return results, removed


def _all_withheld(results):
    """True when the query returned rows but the result policy removed
    every column, so there is nothing left to explain."""
    return bool(results) and all(not row for row in results)


def _run_pipeline(question, catalog, history, security, schema, domain_key):
    """Generate, control, execute and explain - unchanged by domains."""
    sql = generate_sql(question, schema, history)
    generated_sql = sql   # as the model wrote it, before any rewriting

    print("\n[sql]")
    print(sql)

    # ---------------------------------------------------------
    # Did the model return a query at all?
    # ---------------------------------------------------------
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
        return _result(message)

    if output_kind == "not_available":
        if mentions_denied_column(question, security):
            print("\n[security] Question refers to a restricted column.")
            rule = "restricted_data"
        else:
            print("\n[security] Requested data isn't in the authorised schema.")
            rule = "not_available"
        return _policy_block(rule)

    if output_kind == "write_request":
        # The model recognised a request to modify data and declined to
        # write SQL. Report it as the same read-only policy block the
        # validator would give a DELETE/UPDATE, rather than as a
        # parse failure ("couldn't be validated").
        print("\n[security] Request to modify data; read-only access.")
        return _policy_block("read_only")

    if output_kind == "off_topic":
        print("\n[agent] Not a data question.")
        print(f"\n[answer] {OFF_TOPIC_MESSAGE}")
        return _result(OFF_TOPIC_MESSAGE)

    if output_kind == "no_sql":
        print("\n[agent] Model did not return a SQL statement.")
        print(f"\n[answer] {NO_QUERY_MESSAGE}")
        return _error(NO_QUERY_MESSAGE)

    # ---------------------------------------------------------
    # Strip, validate, rewrite, re-validate (see _prepare_sql)
    # ---------------------------------------------------------
    try:
        sql, withheld, failure = _prepare_sql(sql, security, catalog)
    except Exception as ex:
        print(f"\n[error] {ex}")
        message = "I couldn't safely prepare the query for execution."
        print(f"\n[answer] {message}")
        return _error(message, sql)

    if failure:
        return failure

    # ---------------------------------------------------------
    # Execute
    # ---------------------------------------------------------
    print("\n[agent] Executing SQL...")

    try:
        results, removed = _execute(sql, security)
        withheld = withheld + removed
    except Exception as ex:
        print(f"\n[SQL ERROR] {ex}")

        diagnosis = diagnose_sql_error(sql, ex, security, catalog.semantic)
        correction_hint = ""

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

        print("\n[agent] Asking Ollama to correct SQL...")

        try:
            llm_error = _sanitize_sql_error_for_llm(str(ex))

            corrected_sql = correct_sql(
                question, schema, sql, llm_error, correction_hint
            )

            print("\n[corrected sql]")
            print(corrected_sql)

            # Compare with what the model first wrote, not the prepared
            # SQL: that has LIMIT 1000 (and maybe rewrites) added, so the
            # two never matched and the failing query was run again.
            if _normalise_sql(corrected_sql) in {
                _normalise_sql(generated_sql), _normalise_sql(sql)
            }:
                print("\n[agent] Correction produced the same SQL. Stopping.")
                return _error("I wasn't able to correct that query.", sql)

            # -------------------------------------------------
            # Re-run ALL the checks on the corrected SQL
            # -------------------------------------------------
            corrected_sql, corrected_withheld, failure = _prepare_sql(
                corrected_sql, security, catalog)
            withheld = withheld + corrected_withheld

            if failure:
                return failure

            print("\n[agent] Executing corrected SQL...")

            results, removed = _execute(corrected_sql, security)
            withheld = withheld + removed
            sql = corrected_sql

        except Exception as correction_error:
            print(f"\n[CORRECTION ERROR] {correction_error}")
            return _error("I couldn't correct that query.", sql)

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

    # Remove the artificial LIMIT MAX_ROWS from the SQL supplied to the
    # explanation model so that it doesn't incorrectly attribute the
    # result to the user's question. (Postgres renders the row cap as
    # "LIMIT n", unlike SQL Server's "TOP n".)
    explanation_sql = re.sub(
        rf"\bLIMIT\s+{MAX_ROWS}\b\s*",
        "",
        sql,
        flags=re.IGNORECASE,
    )

    explanation = explain_results(
        question, explanation_sql, results, withheld=sorted(set(withheld))
    )

    print("\n[answer]")
    print(explanation)

    history.append({
        "question": question,
        "sql": explanation_sql,
        "answer": explanation,
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
        )

    return _result(explanation, explanation_sql)
