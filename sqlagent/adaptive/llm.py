# Copyright (c) 2026 Brad Long
# Author: Brad Long

import re
import json
import base64
from functools import lru_cache

import httpx
from ollama import Client

from sqlagent.adaptive.history import format_history
from sqlagent.databases import active_database
from sqlagent.controls.security_utils import full_table_name
from sqlagent.execution.engines import active_dialect, active_engine
from sqlagent.settings import get_settings


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# config/settings/llm.yaml (OLLAMA_* environment variables override it).
# The username and password come from the environment variables it
# names, never from the file.
_LLM = get_settings().llm
OLLAMA_HOST = _LLM.host
OLLAMA_MODEL = _LLM.model
OLLAMA_USERNAME = _LLM.username()
OLLAMA_PASSWORD = _LLM.password()
MAX_HISTORY_TURNS = _LLM.history_turns
HISTORY_SAMPLE_ROWS = _LLM.history_sample_rows
HISTORY_VALUE_CHARS = _LLM.history_value_chars
HISTORY_SQL_TURNS = _LLM.history_sql_turns
HISTORY_SUMMARY_CHARS = _LLM.history_summary_chars
CORRECTION_SQL_CHARS = _LLM.correction_sql_chars
EXPLAIN_ROWS = _LLM.explain_rows
EXPLAIN_VALUE_CHARS = _LLM.explain_value_chars
EXPLAIN_RESULT_CHARS = _LLM.explain_result_chars

# Timeouts for calls to Ollama, in seconds. The ollama client's default is
# no timeout at all, so a call sent on a connection that was silently
# dropped (e.g. by the ngrok tunnel after a long idle period) waited
# forever: the REPL froze, and under the API each hung call held a worker
# thread for good until the thread pool ran out.
OLLAMA_CONNECT_TIMEOUT = _LLM.connect_timeout
OLLAMA_READ_TIMEOUT = _LLM.read_timeout

# Returned by the model (instead of SQL) when the user asks to modify data.
# It can only ever lead to a request being BLOCKED, never to more access,
# so trusting the model here doesn't weaken any guardrail: if the model
# ignores the instruction and writes a DELETE anyway, the AST validator
# still rejects it as not read-only.
WRITE_REQUEST_SENTINEL = "READ_ONLY_VIOLATION"

# Returned when the message isn't a question about the data at all
# (greetings, insults, general chat). Without this second option the model
# used READ_ONLY_VIOLATION as a catch-all "no SQL" answer, so e.g.
# "you are stupid" was reported as a read-only block.
NOT_A_DATA_QUESTION_SENTINEL = "NOT_A_DATA_QUESTION"

# Returned when it IS a data question but the schema above can't answer it,
# e.g. the column is restricted for this role (and therefore hidden from
# the schema the model sees) or doesn't exist. The model can't tell those
# two apart, so the user-facing message doesn't claim either one.
DATA_NOT_AVAILABLE_SENTINEL = "DATA_NOT_AVAILABLE"

# Returned when it is a data question but too vague to turn into one
# query ("what does Northwind have?", "show me stuff"). Without it the
# model guessed a filter, or used READ_ONLY_VIOLATION, and the user was
# told the data might be restricted for their role.
UNCLEAR_QUESTION_SENTINEL = "UNCLEAR_QUESTION"

headers = dict(_LLM.headers)

if OLLAMA_USERNAME and OLLAMA_PASSWORD:
    credentials = f"{OLLAMA_USERNAME}:{OLLAMA_PASSWORD}"
    encoded = base64.b64encode(credentials.encode()).decode()
    headers["Authorization"] = f"Basic {encoded}"

ollama_client = Client(
    host=OLLAMA_HOST,
    headers=headers,
    # read: how long to wait for the model to answer; connect: how long
    # to wait for the server (or tunnel) to accept the connection.
    timeout=httpx.Timeout(OLLAMA_READ_TIMEOUT, connect=OLLAMA_CONNECT_TIMEOUT),
    # Open a fresh connection for every call instead of reusing an idle
    # one, so there is never a stale connection to send on. The extra
    # handshake is negligible next to the model's own time.
    limits=httpx.Limits(max_keepalive_connections=0),
)

# Failures where the request never reached the model, so trying once more
# is safe and usually works. A read timeout is NOT retried: the model got
# the request and is just slow, and asking again would double the wait.
_RETRYABLE_ERRORS = (
    ConnectionError,             # ollama's wrapper for httpx.ConnectError
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.RemoteProtocolError,   # e.g. server closed the connection
    httpx.ReadError,
    httpx.WriteError,
)


# ---------------------------------------------------------------------------
# Ollama
# ---------------------------------------------------------------------------

def _ollama_options():
    """llm.temperature / seed / num_ctx as Ollama request options; unset
    ones are left out so the model's defaults apply."""
    options = {"temperature": _LLM.temperature, "seed": _LLM.seed,
               "num_ctx": _LLM.num_ctx}
    return {name: value for name, value in options.items() if value is not None}


OLLAMA_OPTIONS = _ollama_options()

# A prompt using this share of num_ctx gets a warning: Ollama cuts a
# prompt that doesn't fit, without an error.
CONTEXT_WARNING_SHARE = 0.9

# Characters per token, to estimate a prompt's size before it is sent.
# Measured on qwen3-coder with the Odoo prompts: about 4 (17,100 characters
# were counted as 12,900 tokens).
CHARS_PER_TOKEN = 4.0

# When a prompt doesn't fit, llama.cpp keeps only about half the context
# (the start and the most recent part), so a cut prompt is counted at
# num_ctx / 2 plus a token or two: 4,098 at 8K, 8,194 at 16K.
CUT_COUNT_TOLERANCE = 16

# Without num_ctx (Ollama's own context setting is used), a cut is seen
# when Ollama counts well under what was sent: below this share of the
# estimate. Uncut prompts count at about the estimate or above (2,589 for
# ~2,564 sent); a cut one at about half the context (2,050 for ~4,915 at
# 4K). Prompts estimated under CUT_MIN_ESTIMATE tokens aren't judged.
CUT_SHARE = 0.6
CUT_MIN_ESTIMATE = 1000


def estimated_tokens(messages):
    """The approximate token count of the messages, from their length."""
    chars = sum(len(str(m.get("content", ""))) for m in messages)
    return round(chars / CHARS_PER_TOKEN)


def prompt_was_cut(prompt, num_ctx, estimate):
    """True when Ollama's count shows it dropped part of the prompt: the
    count sits at half the context while more than that was sent, or the
    prompt sent was larger than the whole context. Without num_ctx: the
    count is well under what was sent (CUT_SHARE)."""
    if not prompt:
        return False
    if not num_ctx:
        return bool(estimate) and estimate >= CUT_MIN_ESTIMATE \
            and prompt < CUT_SHARE * estimate
    at_half = abs(prompt - num_ctx // 2) <= CUT_COUNT_TOLERANCE
    if at_half and (not estimate or estimate > num_ctx // 2):
        return True
    return bool(estimate) and estimate > num_ctx


def token_report(response, num_ctx=None, estimate=None):
    """
    One line of token counts and times from an Ollama reply, e.g.
    "6,850 prompt tokens (9.8s), 120 out (3.1s)", plus a warning when the
    prompt was cut (Ollama counted far fewer tokens than were sent) or
    used most of num_ctx. None when the reply has no counts. estimate is
    estimated_tokens() of what was sent.
    """
    prompt = getattr(response, "prompt_eval_count", None)
    output = getattr(response, "eval_count", None)
    if prompt is None and output is None:
        return None

    def seconds(name):
        value = getattr(response, name, None)
        return f" ({value / 1e9:.1f}s)" if value else ""

    text = (f"{prompt or 0:,} prompt tokens{seconds('prompt_eval_duration')}, "
            f"{output or 0:,} out{seconds('eval_duration')}")
    if estimate:
        text += f"; ~{estimate:,} sent"
    if prompt_was_cut(prompt, num_ctx, estimate):
        if num_ctx:
            text += (f" - WARNING: the prompt was cut to fit the context "
                     f"(num_ctx {num_ctx:,}); the model didn't see all of it")
        else:
            # A cut prompt is counted at about half the context.
            text += (f" - WARNING: the prompt was cut to fit Ollama's context "
                     f"(about {prompt * 2:,} tokens, from the Ollama app's "
                     "setting); the model didn't see all of it. Set num_ctx "
                     "in llm.yaml, or raise the app's context length")
    elif num_ctx and prompt and prompt >= CONTEXT_WARNING_SHARE * num_ctx:
        text += (f" - WARNING: {prompt / num_ctx:.0%} of num_ctx {num_ctx:,}; "
                 "the prompt may have been cut")
    return text


def prompt_breakdown(prompt, **parts):
    """
    "[llm] SQL prompt ~12,800 tokens: schema ~9,100, examples ~1,200,
    history ~400, rules ~2,100" - where a prompt's size goes, estimated
    from each part's length. rules is everything else in the prompt.
    """
    sizes = {name: round(len(text or "") / CHARS_PER_TOKEN)
             for name, text in parts.items()}
    total = round(len(prompt) / CHARS_PER_TOKEN)
    rest = max(total - sum(sizes.values()), 0)
    shown = ", ".join(f"{name} ~{size:,}" for name, size in sizes.items())
    return f"[llm] SQL prompt ~{total:,} tokens: {shown}, rules ~{rest:,}"


def ask_ollama(messages):
    try:
        response = ollama_client.chat(model=OLLAMA_MODEL, messages=messages,
                                      options=OLLAMA_OPTIONS or None)
    except _RETRYABLE_ERRORS as ex:
        print(f"\n[llm] Ollama connection failed ({type(ex).__name__}); retrying once...")
        response = ollama_client.chat(model=OLLAMA_MODEL, messages=messages,
                                      options=OLLAMA_OPTIONS or None)
    if _LLM.log_tokens:
        report = token_report(response, _LLM.num_ctx, estimated_tokens(messages))
        if report:
            print(f"[llm] {report}")
    return response.message.content


def _format_examples(examples):
    """
    The database's own SQL examples (sql_examples in
    config/databases/<database>/identity.yaml) in the prompt's
    "message -> reply" layout:

      "how many customers are there?"    -> SELECT COUNT(*) FROM customers
      "a question too long for the column"
                                         -> SELECT ...
        (an optional note)

    Each line ends with a newline, so no examples means no lines.
    """
    lines = []
    for example in examples:
        message = f'"{example.question}"'
        if example.note is None and len(message) <= 34:
            lines.append(f"  {message:<35}-> {example.sql}")
        else:
            lines.append(f"  {message}")
            if example.note:
                lines.append(f"    ({example.note})")
            lines.append(f"{'':<37}-> {example.sql}")
    return "".join(line + "\n" for line in lines)


@lru_cache(maxsize=256)
def _example_tables(sql, dialect):
    """The tables an example's SQL reads, as lowercase full names, or None
    if it can't be parsed."""
    import sqlglot
    from sqlglot import exp
    try:
        tree = sqlglot.parse_one(sql, read=dialect)
    except Exception:
        return None
    return frozenset(
        full_table_name(f"{t.db}.{t.name}" if t.db else t.name).lower()
        for t in tree.find_all(exp.Table)
    )


def examples_for_role(examples, allowed_tables):
    """
    The SQL examples whose tables are all ones the role may see. The
    examples go into every SQL prompt, so without this a sales user's
    prompt carried the HR and accounting examples - tables the role can't
    see, which the model then tried to use. allowed_tables is the role's
    catalog (full names); None keeps every example. An example that can't
    be parsed is left out.
    """
    if allowed_tables is None:
        return list(examples)
    allowed = {name.lower() for name in allowed_tables}
    dialect = active_dialect()
    kept = []
    for example in examples:
        tables = _example_tables(example.sql, dialect)
        if tables is not None and tables <= allowed:
            kept.append(example)
    return kept


def generate_sql(question, schema, history, allowed_tables=None):
    """
    allowed_tables: the tables the role may see (the catalog's full
    names), used to choose which SQL examples go in the prompt
    (examples_for_role). None sends them all.
    """
    history_text = format_history(history, MAX_HISTORY_TURNS, HISTORY_SQL_TURNS)

    db = active_database()
    db_names = " (or ".join(f'"{n}"' for n in db.names[:2]) + (")" if len(db.names) > 1 else "")
    db_values = " or ".join(f"'{n}'" for n in db.names)
    db_name = db.names[0] if db.names else "the database"

    engine = active_engine().label
    engine_rules = active_engine().prompt_rules
    examples = examples_for_role(db.sql_examples, allowed_tables)
    if len(examples) < len(db.sql_examples):
        print(f"[llm] SQL examples: {len(examples)} of {len(db.sql_examples)} "
              "(the rest use tables this role can't see)")
    sql_examples = _format_examples(examples)

    system_prompt = f"""
You are a {engine} assistant working with the {db.connection.database} database.
Your job is to generate ONE {engine} SELECT statement that answers
the user's current question.

DATABASE SCHEMA
{schema}

CONVERSATION CONTEXT
{history_text if history_text else "(no previous conversation)"}

IMPORTANT:
* Conversation context is background information only.
* Do not copy JSON, previous query results, or previous answers into SQL.
* Generate SQL for the CURRENT user question.
* Use previous questions and results to resolve references such as:
  "them", "those customers", "the previous result", "now show me..."
* A follow-up usually refers to the MOST RECENT turn. Use earlier turns
  only when the current question clearly points back to them.
* If the current question does not refer to the conversation at all,
  ignore the conversation context and answer it on its own.
* {engine} syntax.
* If the current message explicitly asks to add, change, delete or
  otherwise modify data or the database (e.g. "delete all customers",
  "update the price", "drop the orders table"), do NOT write a query
  and do NOT substitute a SELECT. Return exactly this and nothing else:
  {WRITE_REQUEST_SENTINEL}
* If the current message is not a question about the data at all
  (e.g. a greeting, thanks, an insult, a comment about you, or general
  chat), do NOT write a query. Return exactly this and nothing else:
  {NOT_A_DATA_QUESTION_SENTINEL}
* If the current message IS a question about the data, but the
  DATABASE SCHEMA above has no table that could hold the answer, do
  NOT guess and do NOT use a different table. Return exactly this and
  nothing else:
  {DATA_NOT_AVAILABLE_SENTINEL}
  Use it ONLY when no listed table could hold the answer. A table
  marked "... more columns, not listed" has other columns too: a
  column you need may be one of them.
* If the current message is about the data but too vague to answer
  with one query (it names no record, measure or kind of thing, e.g.
  "what does {db_name} have?", "show me stuff", "what's going on?"),
  do NOT guess a table or a filter. Return exactly this and nothing
  else:
  {UNCLEAR_QUESTION_SENTINEL}
* {db_names} is the name of the company and the
  database. It is never a value to filter on: never write
  WHERE ... = {db_values}.
* If the message asks what is known about a person, company or other
  record ("what information do you have about X?", "tell me about X",
  "any further details on X?"), select ALL columns of the matching row
  with SELECT * from the table that holds it (use the conversation to
  tell which table that is). Restricted columns are removed
  automatically, so never refuse these.
* Only use {WRITE_REQUEST_SENTINEL} for requests to modify data. Never
  use it for questions that only read data, even when they can't be
  answered: use {DATA_NOT_AVAILABLE_SENTINEL} or
  {UNCLEAR_QUESTION_SENTINEL} for those.
* Reply with ONE of: a SELECT statement, or a single marker. Never both.

EXAMPLES (message -> correct reply)
  "delete all customers"             -> {WRITE_REQUEST_SENTINEL}
  "update the price of Chai to 20"   -> {WRITE_REQUEST_SENTINEL}
  "add a new supplier"               -> {WRITE_REQUEST_SENTINEL}
  "you are stupid"                   -> {NOT_A_DATA_QUESTION_SENTINEL}
  "stupid"                           -> {NOT_A_DATA_QUESTION_SENTINEL}
  "do you not understand?"           -> {NOT_A_DATA_QUESTION_SENTINEL}
  "hello"                            -> {NOT_A_DATA_QUESTION_SENTINEL}
  "thanks!"                          -> {NOT_A_DATA_QUESTION_SENTINEL}
  "what's the weather today?"        -> {NOT_A_DATA_QUESTION_SENTINEL}
  "what does North wind have"        -> {UNCLEAR_QUESTION_SENTINEL}
  "show me some data"                -> {UNCLEAR_QUESTION_SENTINEL}
{sql_examples}Insults, complaints and comments about you are NEVER data questions:
always reply {NOT_A_DATA_QUESTION_SENTINEL} for them.
* No WITH clauses (CTEs) and no subqueries in FROM or JOIN: they are
  rejected. Use joins, subqueries in WHERE or SELECT, or conditional
  aggregation (SUM(CASE WHEN ... THEN ... END)) instead.
{engine_rules}
* Reply with the SQL only.
* Show names, not internal IDs. For every column you SELECT that holds
  another record's id (partner_id, user_id, product_id, employee_id,
  company_id, ...), join that record's table and select its name
  instead, where the table is in the schema. Identify a row by its own
  name or number (an order's S00023 or P00015), not by its id.
  e.g. purchase orders awaiting approval:
       SELECT po.name, p.name AS vendor, po.date_order, po.amount_total
       not SELECT po.id, po.partner_id, ... - unless the user asks
       for ids.
"""

    if _LLM.log_tokens:
        print(prompt_breakdown(system_prompt, schema=schema,
                               examples=sql_examples, history=history_text))

    return clean_sql(ask_ollama([
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": question},
    ]))


def correct_sql(question, schema, sql, error, correction_hint=""):
    engine = active_engine().label

    prompt = f"""
You are correcting a {engine} query.

DATABASE SCHEMA
{schema}

USER QUESTION
{question}

FAILED SQL
{sql}

SQL ERROR
{error}

{correction_hint}

TASK
Correct the SQL query using the actual database schema.

IMPORTANT:
* Return ONE corrected SELECT statement, and only the SQL.
* Follow any hint above the TASK; never send back what it says is
  wrong.
* Use only columns that exist in the schema.
* No WITH clauses (CTEs) and no subqueries in FROM or JOIN.
* If no column in the schema holds what the question asks for, return
  exactly {DATA_NOT_AVAILABLE_SENTINEL} instead of SQL.
"""

    return clean_sql(ask_ollama([
        {
            "role": "system",
            "content": f"You are a {engine} query correction assistant.",
        },
        {"role": "user", "content": prompt},
    ]))


# Statement keywords that mean the model produced something other than a
# query. These are passed through UNCHANGED so validate_agent_sql() can
# reject them with a proper "read-only" policy block, instead of being
# silently discarded or turned into an HTTP 500.
_STATEMENT_START = re.compile(
    r"\s*(select|with|insert|update|delete|drop|alter|create|truncate|"
    r"grant|revoke|merge|copy|call|do|set|vacuum|explain)\b",
    flags=re.IGNORECASE,
)

# Where a query begins if the model wrapped it in prose. "WITH" is only
# treated as a CTE when it looks like one ("WITH name AS ("), so ordinary
# words such as "with joins:" in an explanation don't match.
_QUERY_START = re.compile(
    r"\bSELECT\b|\bWITH\s+(?:RECURSIVE\s+)?\w+\s+AS\s*\(",
    flags=re.IGNORECASE,
)


def clean_sql(text):
    """
    Extract the SQL statement from the model response.

    The model may wrap the SQL in markdown or a sentence of explanation.
    This function only tidies that up; it never decides what is allowed.
    Structural validation and authorisation happen later, and always see
    what the model actually produced:

      * A response that already starts with a statement keyword
        (SELECT, WITH, DELETE, ...) is returned as-is. Previously
        everything before the first SELECT was cut off, which silently
        turned "DELETE ... WHERE id IN (SELECT ...)" into a broken
        fragment and broke every query beginning with WITH.
      * Prose followed by SQL is trimmed to where the SQL starts.
      * Anything else is returned unchanged rather than raising, so the
        validator produces the user-facing result instead of an HTTP 500.
    """
    text = text.strip()

    text = re.sub(r"```(?:sql)?\s*", "", text, flags=re.IGNORECASE)
    text = text.replace("```", "").strip()

    if _STATEMENT_START.match(text):
        return text

    match = _QUERY_START.search(text)

    if match:
        return text[match.start():].strip()

    return text


def classify_model_output(text):
    """
    Say what kind of response the model gave, before validation.

      "sql"          - starts with a statement keyword; send it to the
                       validator as usual (a DELETE is still blocked there).
      "write_request"- the model flagged the question as a request to
                       modify data (WRITE_REQUEST_SENTINEL).
      "off_topic"    - the model flagged the message as not a data
                       question (NOT_A_DATA_QUESTION_SENTINEL).
      "not_available"- a data question the schema can't answer
                       (DATA_NOT_AVAILABLE_SENTINEL).
      "unclear"      - a data question too vague for one query
                       (UNCLEAR_QUESTION_SENTINEL).
      "no_sql"       - anything else, e.g. the model answered or declined
                       in prose. Previously this fell through to the parser
                       and surfaced as "couldn't be validated".

    A marker counts when it is the whole reply, or a line of its own
    (ignoring quotes, backticks and punctuation). A marker line wins over
    any SQL in the same reply: the model hedged, e.g.

        SELECT phone FROM suppliers WHERE contact_name = 'Maria Anders'
        READ_ONLY_VIOLATION

    and its SQL is not trusted to answer the question. The agent then
    picks the user-facing message itself (a read-only marker without
    write intent becomes "restricted" when the question names a
    restricted column, otherwise "unclear"). Previously the SQL
    won, failed to parse, and the user got "couldn't produce a valid
    query". Two DIFFERENT markers in one reply give "no_sql" rather than
    a guess. A marker mentioned mid-sentence doesn't count.
    """
    found = set()
    for line in text.splitlines():
        token = line.strip().strip("`'\".;:!* \t").upper()
        if token in _MARKER_KINDS:
            found.add(_MARKER_KINDS[token])

    if len(found) == 1:
        return found.pop()
    if len(found) > 1:
        return "no_sql"

    if _STATEMENT_START.match(text):
        return "sql"
    return "no_sql"


_MARKER_KINDS = {
    WRITE_REQUEST_SENTINEL: "write_request",
    NOT_A_DATA_QUESTION_SENTINEL: "off_topic",
    DATA_NOT_AVAILABLE_SENTINEL: "not_available",
    UNCLEAR_QUESTION_SENTINEL: "unclear",
}


# Backstop for the write marker. The model (qwen3-coder) has used
# READ_ONLY_VIOLATION as a catch-all for "I can't write SQL for this", so
# the agent only reports a read-only block when the question itself
# contains a write-style verb. This is used ONLY to choose which message
# to show; it never allows anything. Every query that does get generated
# is still checked by the AST validator.
_WRITE_INTENT = re.compile(
    r"\b(delete|remove|drop|truncate|erase|wipe|purge|clear|update|change|"
    r"modify|edit|alter|rename|insert|add|create|set|replace|grant|revoke|"
    r"overwrite|reset|write)\b",
    flags=re.IGNORECASE,
)


def looks_like_write_request(question):
    return bool(_WRITE_INTENT.search(question))


def _results_for_prompt(results, max_rows, max_value_chars, max_chars):
    """
    (text, rows shown): the rows to show the model, one compact JSON
    object per line with long values cut, adding rows until max_rows or
    max_chars is reached (always at least one). Indented JSON of a large
    result could fill the model's context, which then drops the start of
    the prompt - the question and the row count.
    """
    def short(value):
        if isinstance(value, str) and len(value) > max_value_chars:
            return value[:max_value_chars - 3] + "..."
        return value

    lines, used = [], 0
    for row in results[:max_rows]:
        line = json.dumps({key: short(value) for key, value in row.items()},
                          default=str, ensure_ascii=False)
        if lines and used + len(line) + 1 > max_chars:
            break
        lines.append(line)
        used += len(line) + 1
    return "\n".join(lines), len(lines)


def explain_results(question, sql, results, withheld=(), row_cap=None):
    """
    Send SQL results back to Ollama and ask for a natural-language answer.

    The row count and the columns actually present are computed here and
    stated in the prompt, rather than left for the model to infer: it
    previously miscounted (reading a supplier_id of 27 as "27 suppliers")
    and described columns from the SQL that weren't in the results.
    withheld lists result columns removed by the security policy. At most
    llm.explain_rows rows (and explain_result_chars characters of them)
    are shown; the full count is stated twice, before and after them.
    row_cap is the query's row limit: a result that reached it is
    reported as "at least" that many.
    """
    row_count = len(results)
    rows_text, shown = _results_for_prompt(
        results, EXPLAIN_ROWS, EXPLAIN_VALUE_CHARS, EXPLAIN_RESULT_CHARS)
    capped = bool(row_cap) and row_count >= row_cap

    if capped:
        count_text = (f"{row_count} (the row limit: there may be more; say "
                      f"\"at least {row_count}\")")
    else:
        count_text = str(row_count)
    if shown < row_count:
        results_label = f"RESULTS (the first {shown} of {row_count} rows, one per line)"
        # Only when rows were actually left out: stated unconditionally,
        # the model called complete results "examples" too.
        shown_rule = (
            f"* Only {shown} of the {row_count} rows are shown. Give the total\n"
            "  from ROW COUNT and describe the shown rows as examples; don't\n"
            "  present them as the full list.\n")
    else:
        results_label = "RESULTS (one row per line)"
        shown_rule = (
            "* Every row is shown: this is the complete result. Don't call\n"
            "  the rows examples or suggest there may be more.\n")

    columns = []
    for row in results:
        for column in row:
            if column not in columns:
                columns.append(column)

    if withheld:
        withheld_text = (
            "These columns were withheld by the security policy and are NOT "
            "in the results: " + ", ".join(withheld) + ".\n"
            "Do not describe their values and do not say they are missing "
            "from the database."
        )
    else:
        withheld_text = "None."

    prompt = f"""
Answer the user's database question using the SQL query and results below.

USER QUESTION
{question}

SQL QUERY
{sql}

ROW COUNT
{count_text}

COLUMNS IN THE RESULTS
{", ".join(columns) if columns else "(no rows)"}

WITHHELD COLUMNS
{withheld_text}

{results_label}
{rows_text or "(no rows)"}

ROW COUNT (again): {count_text}

Rules:
* ROW COUNT is the exact number of rows. Use it for any count; never
  count rows yourself and never treat an ID value as a count.
{shown_rule}* Only mention fields listed in COLUMNS IN THE RESULTS. The SQL may
  name other columns; ignore them.
* Do not mention access or permissions.
* Explain the result clearly and concisely.
* Do not invent information that isn't present in the results.
"""

    return ask_ollama(
        [
            {
                "role": "system",
                "content": "You are a database analyst explaining SQL query results.",
            },
            {"role": "user", "content": prompt},
        ]
    )