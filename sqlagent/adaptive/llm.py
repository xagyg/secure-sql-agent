# Copyright (c) 2026 Brad Long
# Author: Brad Long

import os
import re
import json
import base64

import httpx
from ollama import Client


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# These are set in the startup script
OLLAMA_HOST = os.getenv("OLLAMA_HOST")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL")
OLLAMA_USERNAME = os.getenv("OLLAMA_USERNAME")
OLLAMA_PASSWORD = os.getenv("OLLAMA_PASSWORD")
MAX_HISTORY_TURNS = 5

# Timeouts for calls to Ollama, in seconds. The ollama client's default is
# no timeout at all, so a call sent on a connection that was silently
# dropped (e.g. by the ngrok tunnel after a long idle period) waited
# forever: the REPL froze, and under the API each hung call held a worker
# thread for good until the thread pool ran out.
OLLAMA_CONNECT_TIMEOUT = float(os.getenv("OLLAMA_CONNECT_TIMEOUT", "10"))
OLLAMA_READ_TIMEOUT = float(os.getenv("OLLAMA_READ_TIMEOUT", "120"))

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

headers = {"ngrok-skip-browser-warning": "true"}

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

def ask_ollama(messages):
    try:
        response = ollama_client.chat(model=OLLAMA_MODEL, messages=messages)
    except _RETRYABLE_ERRORS as ex:
        print(f"\n[llm] Ollama connection failed ({type(ex).__name__}); retrying once...")
        response = ollama_client.chat(model=OLLAMA_MODEL, messages=messages)
    return response.message.content


def generate_sql(question, schema, history):
    history_text = ""

    if history:
        history_text = "\n\n".join(
            f"""
Previous user question:
{turn["question"]}

Previous SQL:
{turn["sql"]}

Previous answer:
{turn["answer"]}
"""
            for turn in history[-MAX_HISTORY_TURNS:]
        )

    system_prompt = f"""
You are a PostgreSQL assistant working with the northwind database.
Your job is to generate ONE PostgreSQL SELECT statement that answers
the user's current question.

DATABASE SCHEMA
{schema}

CONVERSATION CONTEXT
{history_text if history_text else "(no previous conversation)"}

IMPORTANT:
* Conversation context is background information only.
* Do not copy JSON, previous query results, or previous answers into SQL.
* Generate SQL for the CURRENT user question.
* Use previous questions and answers to resolve references such as:
  "them", "those customers", "the previous result", "now show me..."
* PostgreSQL syntax.
* Only SELECT queries.
* Do not modify data.
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
  DATABASE SCHEMA above has no table or column that can answer it
  (e.g. it asks for a phone number and no phone column is listed),
  do NOT guess and do NOT use a different column. Return exactly this
  and nothing else:
  {DATA_NOT_AVAILABLE_SENTINEL}
  Use it ONLY when no listed table could hold the answer.
* If the current message is about the data but too vague to answer
  with one query (it names no record, measure or kind of thing, e.g.
  "what does Northwind have?", "show me stuff", "what's going on?"),
  do NOT guess a table or a filter. Return exactly this and nothing
  else:
  {UNCLEAR_QUESTION_SENTINEL}
* "Northwind" (or "North Wind") is the name of the company and the
  database. It is never a value to filter on: never write
  WHERE ... = 'Northwind' or 'North Wind'.
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
  "what is Nancy's home phone?"      -> {DATA_NOT_AVAILABLE_SENTINEL}
    (only when no phone column is listed in the schema above)
  "what does North wind have"        -> {UNCLEAR_QUESTION_SENTINEL}
  "show me some data"                -> {UNCLEAR_QUESTION_SENTINEL}
  "what products does Northwind sell?"
                                     -> SELECT product_name FROM products
  "how many customers are there?"    -> SELECT COUNT(*) FROM customers
  "what information do you have about Jose?"
    (after an answer naming Jose Pavarotti, a customer contact)
                                     -> SELECT * FROM customers WHERE contact_name = 'Jose Pavarotti'
Insults, complaints and comments about you are NEVER data questions:
always reply {NOT_A_DATA_QUESTION_SENTINEL} for them.
* Do not use WITH clauses (CTEs); use joins or subqueries instead.
* Table and column names are lowercase/snake_case unless the schema
  above shows otherwise — do not invent camelCase names.
* Only use double quotes around an identifier if the schema above
  shows it needs them (e.g. a mixed-case or reserved-word name).
* Return ONLY the SQL statement.
* Do not return markdown.
* Do not return JSON.
* Do not explain the SQL.
* When the user asks for a person, customer, employee, product, etc.,
  return identifying information such as the person's name, not just
  an internal ID, where the relevant table is available.
* Join to the relevant entity table when necessary to provide the
  requested identifying information.
"""

    return clean_sql(ask_ollama([
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": question},
    ]))


def correct_sql(question, schema, sql, error, correction_hint=""):
    prompt = f"""
You are correcting a PostgreSQL query.

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
* Return ONE corrected SELECT statement.
* Use only columns that exist in the schema.
* Do not use WITH clauses (CTEs); use joins or subqueries instead.
* If a KNOWN COLUMN MAPPING is supplied, use its physical column.
* Do not use a mapped column if it is not authorised.
* Do not modify data.
* Return ONLY SQL.
* Do not use markdown.
* Do not explain the correction.
"""

    return clean_sql(ask_ollama([
        {
            "role": "system",
            "content": "You are a PostgreSQL query correction assistant.",
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


def explain_results(question, sql, results, withheld=()):
    """
    Send SQL results back to Ollama and ask for a natural-language answer.

    The row count and the columns actually present are computed here and
    stated in the prompt, rather than left for the model to infer: it
    previously miscounted (reading a supplier_id of 27 as "27 suppliers")
    and described columns from the SQL that weren't in the results.
    withheld lists result columns removed by the security policy.
    """
    row_count = len(results)

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
{row_count}

COLUMNS IN THE RESULTS
{", ".join(columns) if columns else "(no rows)"}

WITHHELD COLUMNS
{withheld_text}

RESULTS
{json.dumps(results, default=str, indent=2)}

Rules:
* ROW COUNT is the exact number of rows. Use it for any count; never
  count rows yourself and never treat an ID value as a count.
* Only mention fields listed in COLUMNS IN THE RESULTS. The SQL may
  name other columns; ignore them.
* If ROW COUNT is 0, say no matching records were found and suggest
  checking the spelling of any names or rephrasing the question. Do not
  say the record does not exist, and do not mention access or
  permissions.
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