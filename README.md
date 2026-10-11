# Secure SQL Agent

A research prototype of a conversational AI that answers natural-language questions about a database, without giving the language model unchecked access to the data.

A local LLM (served by Ollama) turns each question into SQL. That SQL is then checked structurally, authorised against the user's identity-based access rules, rewritten and limited before it reaches the database, and filtered again before the results go back to the model to be explained. The model never decides what is allowed; deterministic code does.

The demo runs against a PostgreSQL copy of the **Northwind** sample database.

> Copyright (c) 2026 Brad Long

---

## How it works

```text
Question
  → Domain routing        Who / What / Where pick a Domain of Discourse (see below)
  → Schema discovery      only tables/columns the user is authorised to see are given to the model
  → Ollama (generate SQL)
  → Structural safety     single statement, read-only SELECT, no nested writes (AST-based, via sqlglot)
  → Authorisation         every table and column checked against the SecurityContext
  → Rewrite               SELECT * expanded to authorised columns; restricted columns stripped
  → Query limit           LIMIT added if missing (max 1,000 rows)
  → Re-validation
  → PostgreSQL            read-only role, read-only transaction, statement timeout
  → Result policy         restricted columns removed again, row and byte caps
  → Ollama (explain results)
  → Answer
```

If the query fails, the agent diagnoses the database error (with schema-revealing `DETAIL`/`HINT` text removed) and asks the model for one corrected attempt, which goes through the same checks.

Blocked requests return a short, generic message and rule label (for example `read-only`, `restricted data`, `not available`) that never names a table or column. The detailed reason stays in the server console and audit log.

### Domains of Discourse

The whole authorised schema is the agent's *Universe of Discourse*. `config/semantic/northwind/domains.yaml` defines named subsets of it, *Domains of Discourse* (Sales, Purchasing & Inventory, Shipping & Logistics, Human Resources, Financials), each with the words, roles and locations that point towards it.

For every question the agent scores each domain on three signals and combines them:

| Signal | Source | How it scores |
| ------ | ------ | ------------- |
| **What** | The question | Domain named in the question (`in purchasing`), plus how well the domain's best three tables match the question's words (top table counts in full, 2nd half, 3rd a quarter) |
| **Where** | `[where=...]` at the end of the question | The most specific location phrase matched (`purchase order entry` beats `order entry`). Function codes such as `PUR0410` map to location names via `function_aliases` |
| **Who** | The user's roles (or `[who=...]` in the demo) | The strongest role affinity for the domain. Friendly role names via `role_aliases` |

What and Where are normalised to 0–1 across domains and weighted 0.45 / 0.35 / 0.20 (What / Where / Who). An absent signal's weight is shared among the others. The domain used on the previous turn gets a 0.10 bonus so follow-ups stay put.

* **Clear winner** (≥ 0.25 and ≥ 0.15 ahead): search that domain.
* **Too close to call**: search the top two domains together.
* **No signal**: search the whole schema, exactly as before.

Inside the chosen domain, anchor tables are found by the usual table search, then the relationship walk follows the **full** foreign-key graph to the domain's hop limit, so it can cross into neighbouring domains. A table outside the domain that the question names in full is always kept. Vague questions ("show me Nancy's details") use the domain's own fallback tables.

Examples:

```text
what was the last order?                                  → Sales + Financials (blended)
what was the last order? [where=financials data entry]    → Financials
what was the last order? [where=shipping desk]            → Shipping & Logistics
show me the latest one [where=PUR0410]                    → Purchasing & Inventory
what was the last order? [who=accountant]                 → Financials
```

Routing changes where the search *starts*, never what the user may *see*: domains are mapped onto the security-filtered catalog, so an unauthorised table is never in a domain, and every control below still runs on the generated SQL. The tags are stripped before the question reaches the LLM or the conversation history. `[who=...]` affects routing only and is controlled by `ALLOW_WHO_TAG`; turn it off outside the demo.

The chosen domain is printed as a `[domain]` line in the console with each signal's score, and shown as a tag next to the answer in the browser. Run the routing tests (no database or model needed) with:

```bash
python -m unittest tests.test_domains -v
```

Or run every test in the project (also no database or model needed):

```bash
python -m unittest discover tests -v
```

---

## Defence in depth

| Layer                | Where                                    | What it does                                                                                                                                                    |
| -------------------- | ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Security policy      | `config/security/northwind.yaml`, `controls/security_policy.py` | Deny by default; roles resolved to a concrete table list at startup; the server won't start if the file is missing or invalid                     |
| Schema scoping       | `adaptive/schema_catalog.py`             | The model only sees authorised tables and non-denied columns; semantic labels, relationships and terms are applied only to what the role can see                |
| Structural safety    | `controls/sql_policy.py`                 | Parses SQL into an AST; allows exactly one `SELECT`/`UNION`; rejects nested `INSERT`/`UPDATE`/`DELETE`/DDL, `SELECT INTO` and `FOR UPDATE` anywhere in the tree |
| Authorisation        | `controls/sql_policy.py`, `controls/security_utils.py` | Table and column checks against the caller's `SecurityContext`                                                                                                  |
| Rewriting and limits | `controls/sql_policy.py`                 | Expands `SELECT *`, strips denied columns, enforces a row limit                                                                                                 |
| Final execution gate | `execution/sql_execution.py`             | Re-runs the structural check immediately before execution                                                                                                       |
| Database             | PostgreSQL                               | Least-privilege `SELECT`-only role, `readonly` transaction, `statement_timeout` (10s default)                                                                   |
| Result policy        | `controls/result_policy.py`              | Strips denied columns from results; caps at 1,000 rows / 5 MB                                                                                                   |
| Public API           | `api.py`                                 | Rate limits, concurrency gate, timeouts, input-length cap, audit log                                                                                            |

---

## Project layout

The code is grouped by IBAAM layer. Entry points stay at the root.

```
api.py, main.py            entry points (public demo API, local REPL)
config/                    one security file and one semantic folder per database
  security/
    northwind.yaml         who may see what (roles, allowed tables, denied columns)
  semantic/
    northwind/
      model.yaml           what the data means (sources, labels, aliases, relationships, terms)
      domains.yaml         Domains of Discourse, role aliases, function codes
sqlagent/
  agent.py                 run_agent(): orchestrates the question -> answer pipeline
  adaptive/                Adaptive layer: the LLM, what it sees and where it starts
  controls/                Control layer: the Agent Behavioural Controls (ABCs)
  execution/               Execution layer: controlled PostgreSQL execution
tests/                     unit tests (no database or model needed)
```

| File                                    | Purpose                                                                                 |
| --------------------------------------- | --------------------------------------------------------------------------------------- |
| `sqlagent/agent.py`                     | `run_agent()`: the full question → answer pipeline                                      |
| `sqlagent/adaptive/llm.py`              | Ollama client, prompts for SQL generation, correction and explanation                   |
| `sqlagent/adaptive/schema_catalog.py`   | Reads the schema at startup and picks the relevant tables for each question             |
| `sqlagent/adaptive/semantic_model.py`   | Loads and validates the semantic model in `config/semantic/<database>/`                 |
| `sqlagent/adaptive/domains.py`          | Domains of Discourse and Who / What / Where routing                                     |
| `sqlagent/adaptive/text_match.py`       | Shared tokenizing and phrase matching for schema search, routing and policy checks      |
| `sqlagent/controls/sql_policy.py`       | Structural safety, authorisation, `SELECT *` rewriting, column stripping, row limit     |
| `sqlagent/controls/result_policy.py`    | Removes restricted columns from results (by source table); caps result size            |
| `sqlagent/controls/question_policy.py`  | Restricted columns named in the question; the follow-up "restricted" pre-check          |
| `sqlagent/controls/messages.py`         | Block rules and generic user-facing messages                                            |
| `sqlagent/controls/security_context.py` | `SecurityContext`: user, roles, authorised tables, denied columns                       |
| `sqlagent/controls/security_policy.py`  | Loads `config/security/<database>.yaml` and builds each user's `SecurityContext` (fails closed)     |
| `sqlagent/controls/security_utils.py`   | Case-insensitive authorisation and table-naming helpers                                 |
| `sqlagent/execution/sql_execution.py`   | PostgreSQL connection and the final execution gate                                      |
| `sqlagent/execution/sql_diagnostics.py` | Diagnoses SQL errors to guide the correction attempt                                    |
| `sqlagent/config_files.py`              | Shared YAML loading (rejects duplicate keys)                                            |
| `config/security/northwind.yaml`        | Security policy: roles, allowed tables, denied columns, group-to-role mapping           |
| `config/semantic/northwind/*.yaml`      | Semantic model: discovery, labels, aliases, relationships, terms, domains               |
| `tests/`                                | Unit tests; `tests/fixtures.py` holds a static Northwind schema                         |
| `api.py`                                | FastAPI wrapper for the public demo                                                     |
| `main.py`                               | Interactive command-line REPL for local use                                             |
| `run.ps1`                               | Starts the API or local REPL on Windows (assumes Ollama is already running)             |
| `run_with_ollama.ps1`                   | Restarts Ollama with the recommended server settings, then runs `run.ps1`               |
| `demo_enabled.flag`                     | Turns the public demo on (see below)                                                    |

---

## Requirements

* Python 3.11+
* PostgreSQL with a Northwind database
* [Ollama](https://ollama.com) with a code-capable model (the demo uses `qwen3-coder`)
* ngrok — **only required for the public demo**

Create a Python virtual environment and install the dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Install and start Ollama, then make sure the configured model is available:

```powershell
ollama pull qwen3-coder
```

---

## Database setup

The agent should run against a disposable copy of the Northwind sample database.

Create a dedicated read-only role and grant it `SELECT` only on the tables the demo uses:

```sql
CREATE ROLE sqlagent_ro LOGIN PASSWORD '...';
GRANT CONNECT ON DATABASE northwind TO sqlagent_ro;
GRANT USAGE ON SCHEMA public TO sqlagent_ro;
GRANT SELECT ON public.customers, public.orders, public.order_details,
                public.products, public.categories, public.suppliers,
                public.employees, public.shippers
  TO sqlagent_ro;
```

**Do not run this against a database containing real people's information.**

---

## Running locally

The `run.ps1` script sets up the local Ollama and PostgreSQL configuration and provides two ways to run the agent. It assumes Ollama is already running (for example, the Windows tray app).

To have Ollama started for you with the recommended server settings, use `run_with_ollama.ps1` in place of `run.ps1`. It takes the same `-local` switch. It **shuts down any Ollama that is already running** first; see [Ollama server settings](#ollama-server-settings).

### Interactive REPL

For the simplest way to experiment with the agent, run:

```powershell
.\run.ps1 -local
```

This starts the interactive command-line REPL defined in `main.py`.

For example:

```text
> Which customers are in Germany?

> What are the top 10 products by price?

> Show me the orders for customer ALFKI.
```

The REPL builds its `SecurityContext` from the `sales` role in `config/security/northwind.yaml` (set `SQLAGENT_ROLES` to use other roles) and is useful for testing the agent and its security controls directly.

### Test the security controls

Try both normal questions and questions that should be blocked:

```text
Which customers are in Germany?
What are the top 10 products by price?
Show me the phone number for Roland Mendel.
Delete all customers.
Update the customer names.
Show me all columns for every customer.
```

The important property is that the model does **not** enforce the security boundary. Generated SQL is parsed, authorised and rewritten by deterministic code before it can reach PostgreSQL.

---

## Running the API locally

To test the FastAPI layer without exposing anything to the internet:

```powershell
.\run.ps1
```

The API listens on:

```text
http://127.0.0.1:8000
```

From another PowerShell window, test it directly:

```powershell
Invoke-RestMethod `
  -Uri http://127.0.0.1:8000/api/ask `
  -Method Post `
  -ContentType "application/json" `
  -Body '{"question":"Which customers are in Germany?","session_id":"local-test"}'
```

You can also check the health endpoint:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/health
```

This exercises the HTTP API while keeping the entire system local:

```text
PowerShell
    ↓
FastAPI
    ↓
Security / SQL validation
    ↓
Ollama
    ↓
PostgreSQL
    ↓
Result policy
    ↓
Ollama
    ↓
Answer
```

No ngrok connection is required for local API testing.

---

## Public demo

The live demo is a static web page (`index.html`, hosted on a separate website) that calls this API through an [ngrok](https://ngrok.com) tunnel to the local server:

```text
Browser (web page) → ngrok tunnel → FastAPI on 127.0.0.1:8000 → Ollama / PostgreSQL (local only)
```

The web page and the tunnel script (`ngrok.ps1`) are specific to that deployment and are **not included in this repository**. The API supports this setup as-is, so to do the same with your own front end:

1. Start the API with `.\run.ps1`.
2. In another window, open a tunnel to it, for example `ngrok http 8000`.
3. Point your page at the ngrok URL and set `DEMO_ALLOWED_ORIGIN` in `run.ps1` to your page's origin. It is currently set to the original demo's site.

`run.ps1` sets `DEMO_TRUSTED_PROXY_HOPS=1` because ngrok is the one proxy in front of the API; change it if you use a different setup. CORS is limited to the origins in `DEMO_ALLOWED_ORIGIN`.

### Endpoints

| Method | Path          | Purpose                                               |
| ------ | ------------- | ----------------------------------------------------- |
| `POST` | `/api/ask`    | `{ "question": "...", "session_id": "..." }` → answer |
| `GET`  | `/api/status` | Whether the demo is currently enabled                 |
| `GET`  | `/api/health` | Liveness and number of tables loaded                  |

### Turning the demo on and off

`/api/ask` only answers while `demo_enabled.flag` exists next to `api.py`.

Delete the file to switch the demo off without stopping the server; the page then shows an "unavailable" message.

Every anonymous visitor gets the same fixed, narrow context: the `demo` role in `config/security/northwind.yaml`, eight Northwind tables, with customer phone, fax and address, and employee home phone, denied.

---

## Configuration

`run.ps1` supplies the local configuration for Ollama and PostgreSQL. Secrets are not stored in the script.

### Database and model

| Variable                             | Example                               |
| ------------------------------------ | ------------------------------------- |
| `PG_HOST`, `PG_PORT`, `PG_DATABASE`  | `localhost`, `5432`, `northwind`      |
| `PG_USER`, `PG_PASSWORD`             | `sqlagent_ro`, *(secret)*             |
| `PG_STATEMENT_TIMEOUT_SECONDS`       | `10`                                  |
| `OLLAMA_HOST`                        | `http://localhost:11434`              |
| `OLLAMA_MODEL`                       | `qwen3-coder`                         |
| `OLLAMA_USERNAME`, `OLLAMA_PASSWORD` | Only if Ollama sits behind basic auth |
| `OLLAMA_CONNECT_TIMEOUT`             | `10` (seconds to connect to Ollama)   |
| `OLLAMA_READ_TIMEOUT`                | `120` (seconds to wait for an answer) |

### Ollama server settings

These are read by the Ollama server when it starts, not by this app, so setting them in `run.ps1` would have no effect. There are two ways to apply them.

**Option 1: set them once for your user.** Set them as Windows user environment variables, then quit and restart Ollama (from the system tray) for them to take effect:

```powershell
setx OLLAMA_KEEP_ALIVE -1
setx OLLAMA_NUM_PARALLEL 1
```

| Variable              | Value | Effect                                                                                                   |
| --------------------- | ----- | -------------------------------------------------------------------------------------------------------- |
| `OLLAMA_KEEP_ALIVE`   | `-1`  | Keeps the model loaded in memory permanently, so no visitor waits for it to load (the default unloads it after 5 minutes idle) |
| `OLLAMA_NUM_PARALLEL` | `1`   | Ollama answers one request per model at a time; others queue inside Ollama                              |

**Option 2: use `run_with_ollama.ps1`.** It stops any running Ollama, including the tray app, then starts `ollama serve` with these values (plus `OLLAMA_MAX_LOADED_MODELS=1`) for that server only, waits for it to answer, and runs `run.ps1`. Your user environment variables are not changed. Override the values with parameters:

```powershell
.\run_with_ollama.ps1                                  # API, NUM_PARALLEL=1, KEEP_ALIVE=-1
.\run_with_ollama.ps1 -local                           # REPL
.\run_with_ollama.ps1 -NumParallel 2 -KeepAlive 1h     # other settings
```

The server it starts keeps running after the script exits, and logs to `logs\ollama-serve*.log`. To go back to the tray app, stop it (`Get-Process ollama | Stop-Process`) and start Ollama as usual.

Keep `DEMO_MAX_CONCURRENCY` (below) equal to `OLLAMA_NUM_PARALLEL`. Both default to 1, which keeps the queue in the API: a second visitor waits up to `DEMO_QUEUE_WAIT` seconds for a free slot, then gets a prompt "busy" reply. If the API allowed more runs than Ollama answers at once, the extra runs would be admitted but then wait inside Ollama, and because each run makes two or more model calls, that wait would count against `DEMO_AGENT_TIMEOUT` and could end in a timeout. To let visitors wait longer for a turn, raise `DEMO_QUEUE_WAIT`. If you raise `OLLAMA_NUM_PARALLEL`, raise `DEMO_MAX_CONCURRENCY` to match, bearing in mind that each extra slot uses more GPU memory.

### Demo API

| Variable                                | Default                   | Purpose                                                                                              |
| --------------------------------------- | ------------------------- | ---------------------------------------------------------------------------------------------------- |
| `DEMO_ALLOWED_ORIGIN`                   | *(unset = same-origin)*   | Comma-separated CORS origins                                                                         |
| `DEMO_TRUSTED_PROXY_HOPS`               | `1`                       | Proxies in front of the API; client IP is read this many entries from the right of `X-Forwarded-For` |
| `DEMO_MAX_QUESTION_CHARS`               | `300`                     | Question length limit                                                                                |
| `DEMO_IP_RPM` / `DEMO_IP_RPD`           | `10` / `150`              | Per-IP requests per minute / day                                                                     |
| `DEMO_SESSION_RPM` / `DEMO_SESSION_RPD` | `4` / `40`                | Per-session requests per minute / day                                                                |
| `DEMO_MAX_CONCURRENCY`                  | `1`                       | Agent runs (Ollama calls) in flight at once                                                          |
| `DEMO_QUEUE_WAIT`                       | `5`                       | Seconds to wait for a free slot before replying "busy"                                               |
| `DEMO_AGENT_TIMEOUT`                    | `25` (`120` in `run.ps1`) | Seconds before a request times out                                                                   |
| `DEMO_MAX_SLOT_HOLD`                    | `90` (`150` in `run.ps1`) | Hard cap on how long a stuck run holds a slot                                                        |
| `DEMO_MAX_SESSIONS`                     | `2000`                    | Conversation histories kept in memory                                                                |
| `DEMO_AUDIT_LOG`                        | `audit.log`               | Audit log path                                                                                       |

Run with `--workers 1`. The rate limiter and session store are in memory and are not shared across worker processes.

### Security policy (`config/security/<database>.yaml`)

Who may see what, one file per database (`config/security/northwind.yaml` for the demo). Owned by security / IT and reviewed separately from the semantic model, which can never widen access.

```yaml
version: 1
default: deny                      # required; nothing is visible unless a role allows it

roles:
  demo:
    allow: [public.customers, public.orders, public.employees]
    deny_columns:
      public.customers: [phone, fax, address]
      public.employees: [home_phone]

  hr_analyst:
    allow: ["semantic.employees_v", "erp.emp_*"]
    deny:  ["erp.emp_salary_hist"]        # deny beats a wildcard allow
    deny_columns:
      "erp.emp_*": [tax_file_no]

group_roles:                       # identity-provider group -> roles
  Northwind-Sales: [sales]
```

* **Patterns** are fnmatch patterns on `schema.table` (`*`, `?`); a name without a schema is in `public`.
* **Resolved once.** At startup (or sign-in) each role's patterns are expanded against the tables that exist and the result is printed (`[security] user demo (roles: demo): 8 table(s)` followed by each table and its denied columns). Query-time checks only ever see that concrete list. Prefer explicit names: with `erp.*`, a table added later becomes visible at the next restart without anyone deciding it should be.
* **Several roles.** A table is visible if any role allows it; a column on it is hidden only if every role that allows the table hides it.
* **Fails closed.** A missing file, invalid YAML, a duplicate or unknown key, `default` other than `deny`, a `deny_columns` table the role isn't granted (usually a typo), or an undefined role stops startup. A denied column that doesn't exist on its table is logged as a warning.
* **Users come from identity, not the file.** `group_roles` maps identity-provider groups to roles (`SecurityPolicy.roles_for_groups`). The demo API always uses the `demo` role; the REPL uses `SQLAGENT_ROLES`.

### Semantic model (`config/semantic/<database>/`)

What the data means, one folder per database (`config/semantic/northwind/`: `model.yaml` and `domains.yaml`). Every `.yaml` file directly in the folder is merged, so a large ERP can have one file per domain; sub-folders and other databases' folders are never read. Nothing here grants access: it is applied to the catalog after security filtering, and anything that names a table or column the role can't see is skipped.

```yaml
sources:                           # which tables and views to discover
  include: ["erp.*", "semantic.*"]   # "*.*" = every schema
  exclude: ["erp.audit_*"]
  use_database_foreign_keys: false   # most ERPs have none: declare them below

tables:
  erp.cust_mst:
    label: customers               # the business name, shown next to the real one
    aliases: [client, buyer]       # other words people use
    columns:
      cm_cr_lim: {label: credit_limit, aliases: [credit]}

relationships:                     # joins the database doesn't declare
  - from: erp.so_line(company_id, order_no)
    to:   erp.so_hdr(company_id, order_no)
    cardinality: many_to_one

terms:                             # words that pick rows
  terminated:
    table: semantic.employees_v
    column: is_terminated          # best: the rule lives in a view
  shipped_late:
    table: public.orders
    predicate: shipped_date > required_date
```

| Concept | Picks | Example |
| ------- | ----- | ------- |
| Table label / aliases | Which table | `cust_mst` is *customers*, also *client* |
| Column label / aliases | Which column | `hire_date` is also *start date* |
| Term | Which rows | *terminated* → `is_terminated`; *shipped late* → `shipped_date > required_date` |

* **Labels** are shown to the model next to the physical name (`TABLE erp.cust_mst  -- customers`); the model still has to write the real name, which the SQL policy checks.
* **Relationships** from the database and from the file are merged. Composite keys are supported, and declared ones show their cardinality to the model. A relationship is used only when both tables and all its columns are visible to the role.
* **Terms** are shown to the model in a `TERMS` section and point routing at their table. A predicate may use only the table's own columns (no subqueries) and is guidance for the model, not injected into the SQL, so "employees who are *not* terminated" still works. For a rule that must always be right, put it in a view (`WITH (security_invoker = true)`) and use a column term.
* **Loading.** A structural error (unknown key, wrong type, a name defined twice) stops startup. A name that isn't in the database is skipped with a log line. No folder at all means an empty model: everything is discovered and there is no vocabulary.

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `SQLAGENT_SECURITY_FILE` | `config/security/northwind.yaml` | Security policy |
| `SQLAGENT_SEMANTIC_PATH` | `config/semantic/northwind` | Semantic model (a folder or one file) |
| `SQLAGENT_USER` | `brad` | REPL only: the local user's name |
| `SQLAGENT_ROLES` | `sales` | REPL only: comma-separated roles from the security file |

---

## Logging

* **Console:** the agent prints each step (`[agent]`, `[schema]`, `[sql]`, `[security]`, `[answer]`), including the generated SQL and any detailed block reasons.
* **`audit.log`:** one line per event (`request_received`, `request_completed`, `rate_limited`, `busy`, `timeout`, `error`) with a request ID, hashed client IP, session ID, the question and the executed SQL. SQL is logged but never returned to the browser.

---

## Security notes and limitations

This is a research demonstration, not a production system.

* The public API has no user authentication. Visitors are anonymous and all share the demo `SecurityContext`. Session IDs are generated in the browser and only separate conversation history and rate-limit buckets; they don't prove identity.
* CORS only controls which web pages can call the API from a browser. It doesn't stop direct calls with `curl` or scripts. Rate limits and the concurrency gate are the real controls.
* Only the API is exposed through the tunnel. Ollama and PostgreSQL listen on localhost only.
* The in-memory rate limiter treats each IPv6 address separately, so a client with a large IPv6 range could spread requests across addresses.
* The table and column names in `config/security/northwind.yaml` and `config/semantic/northwind/` assume snake_case Northwind naming. Check them against your schema (`\dt public.*`) before running. Startup logs every name it can't find.
* The local REPL and API use the same underlying agent and security controls; the API adds the HTTP-specific rate limiting, concurrency, timeout and audit controls.

---

## Citing

If you use this work, please cite the paper. If you used or built on the code itself, you can cite the software as well (or instead).

**The paper** (also available from GitHub's *Cite this repository* button in the sidebar):

```bibtex
@misc{long2026securesqlagent,
  author       = {Long, Brad},
  title        = {Secure {SQL} Agent: Invariant-Bounded Conversational Access to Enterprise Data},
  year         = {2026},
  howpublished = {\url{https://github.com/xagyg/secure-sql-agent/blob/main/docs/secure-sql-agent-paper.pdf}}
}
```

**The software:**

```bibtex
@software{long2026securesqlagent_software,
  author = {Long, Brad},
  title  = {Secure {SQL} Agent},
  year   = {2026},
  url    = {https://github.com/xagyg/secure-sql-agent}
}
```

`@software` needs biblatex; with classic BibTeX, change it to `@misc` and replace `url = {...}` with `howpublished = {\url{...}}`.
