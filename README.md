# Secure SQL Agent

A research prototype of a conversational AI that answers natural-language questions about a database, without giving the language model unchecked access to the data.

A local LLM (served by Ollama) turns each question into SQL. That SQL is then checked structurally, authorised against the user's identity-based access rules, rewritten and limited before it reaches the database, and filtered again before the results go back to the model to be explained. The model never decides what is allowed; deterministic code does.

The demo runs against a PostgreSQL copy of the **Northwind** sample database.

> Copyright (c) 2026 Brad Long

---

## How it works

```text
Question
  → Domain routing        picks where in the schema to start looking (Who / What / Where)
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

Blocked requests return a short, generic message and rule label (for example `read-only`, `restricted data`, `not available`) that never names a table or column. The detailed reason stays in the server console and audit log.

---

## Defence in depth

Each layer, and the file that implements it:

| Layer                | Where                                    | What it does                                                                                                                                                    |
| -------------------- | ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Security policy      | `config/northwind/security.yaml`, `controls/security_policy.py` | Deny by default; roles resolved to a concrete table list at startup; the server won't start if the file is missing or invalid                     |
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
config/                    one folder per database
  databases.yaml           which databases exist, how to connect, which roles to use
  northwind/
    security.yaml          who may see what (roles, allowed tables, denied columns)
    semantic/
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
| `sqlagent/adaptive/semantic_model.py`   | Loads and validates the semantic model in `config/<database>/semantic/`                 |
| `sqlagent/adaptive/domains.py`          | Domains of Discourse and Who / What / Where routing                                     |
| `sqlagent/adaptive/text_match.py`       | Shared tokenizing and phrase matching for schema search, routing and policy checks      |
| `sqlagent/controls/sql_policy.py`       | Structural safety, authorisation, `SELECT *` rewriting, column stripping, row limit     |
| `sqlagent/controls/result_policy.py`    | Removes restricted columns from results (by source table); caps result size            |
| `sqlagent/controls/question_policy.py`  | Restricted columns named in the question; the follow-up "restricted" pre-check          |
| `sqlagent/controls/messages.py`         | Block rules and generic user-facing messages                                            |
| `sqlagent/controls/security_context.py` | `SecurityContext`: user, roles, authorised tables, denied columns                       |
| `sqlagent/controls/security_policy.py`  | Loads `config/<database>/security.yaml` and builds each user's `SecurityContext` (fails closed)     |
| `sqlagent/controls/security_utils.py`   | Case-insensitive authorisation and table-naming helpers                                 |
| `sqlagent/execution/sql_execution.py`   | Database connection and the final execution gate                                        |
| `sqlagent/execution/engines/`           | Everything specific to a database product: driver, catalog queries, read-only and timeout guards, column tracing, error handling (`postgres.py`, `sqlserver.py`) |
| `sqlagent/execution/sql_diagnostics.py` | Diagnoses SQL errors to guide the correction attempt                                    |
| `sqlagent/config_files.py`              | Shared YAML loading (rejects duplicate keys)                                            |
| `sqlagent/settings.py`                  | Loads and validates `config/settings/*.yaml`, with environment overrides (fails closed) |
| `sqlagent/databases.py`                 | Loads `config/settings/databases.yaml` and picks the active database (fails closed)     |
| `config/settings/databases.yaml`        | Database profiles: engine, connection, roles, and where each database's files are       |
| `config/<database>/identity.yaml`       | How the agent talks about a database: name, example questions, worked SQL examples      |
| `config/settings/*.yaml`                | Runtime settings: LLM, API limits, query limits, retrieval, REPL                        |
| `config/northwind_mssql/`               | Security policy, semantic model and identity for Northwind on SQL Server                |
| `tools/check_engine.py`                 | Checks a configured database end to end without the LLM (PASS/FAIL per check)           |
| `tools/probe_sqlserver.py`              | Read-only probe of a SQL Server: driver, login rights, catalog, column tracing, errors  |
| `config/northwind/security.yaml`        | Security policy: roles, allowed tables, denied columns, group-to-role mapping           |
| `config/northwind/semantic/*.yaml`      | Semantic model: discovery, labels, aliases, relationships, terms, domains               |
| `tests/`                                | Unit tests; `tests/fixtures.py` holds a static Northwind schema                         |
| `api.py`                                | FastAPI wrapper for the public demo                                                     |
| `main.py`                               | Interactive command-line REPL for local use                                             |
| `run.ps1`                               | Starts the API or local REPL on Windows (assumes Ollama is already running)             |
| `run_with_ollama.ps1`                   | Restarts Ollama with the recommended server settings, then runs `run.ps1`               |
| `demo_enabled.flag`                     | Turns the public demo on (see below)                                                    |

---

## Requirements

* Python 3.11+
* PostgreSQL or Microsoft SQL Server with a Northwind database (SQL Server
  also needs Microsoft's *ODBC Driver 18 for SQL Server*)
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

### SQL Server

The original SQL Server Northwind (`dbo` schema, PascalCase names, `[Order Details]`) is configured as `northwind_mssql`, with its own `config/northwind_mssql/` security policy, semantic model and identity.

SQL Server has no read-only session, so **the login's permissions are the database's own boundary**. Use a dedicated SQL login whose database user is in `db_datareader` only: no `db_datawriter`, no `EXECUTE`, no DDL, and never `db_owner` or `sysadmin`. A Windows login (`Trusted_Connection`) would run every generated query with your own rights. The server must allow SQL logins: in SSMS, server Properties → Security → *SQL Server and Windows Authentication mode*, then restart the service.

```sql
CREATE LOGIN sqlagent_ro WITH PASSWORD = '...';
USE Northwind;
CREATE USER sqlagent_ro FOR LOGIN sqlagent_ro;
ALTER ROLE db_datareader ADD MEMBER sqlagent_ro;
```

Then check the whole path without the LLM, and run the agent:

```powershell
$env:SQLSERVER_PASSWORD = "..."        # or setx it; run.ps1 asks if it's missing
.\.venv\Scripts\python tools\check_engine.py --db northwind_mssql
.\run.ps1 -local -db northwind_mssql
```

How it differs from PostgreSQL:

* **Timeout:** the ODBC query timeout (`query.yaml` `statement_timeout_seconds`) cancels a slow query; the connection stays usable.
* **Column tracing** for the result policy uses `sp_describe_first_result_set` (browse mode 2): aliases, joins and derived tables are traced to their table; a view is its own source, as on PostgreSQL.
* **Extra structural blocks** (both engines): database- or server-qualified names (`OtherDb.dbo.Customers`), functions used as tables (`OPENROWSET`, `OPENQUERY`, `OPENDATASOURCE`, table-valued functions) and `NEXT VALUE FOR`. Keep *Ad Hoc Distributed Queries* and `xp_cmdshell` turned off on the server as well.
* The model is told SQL Server's syntax (`TOP`, square brackets, `GETDATE()`), and names that need brackets are shown to it bracketed (`dbo.[Order Details]`).

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

The REPL builds its `SecurityContext` from the active database's `repl_roles` (the `sales` role in `config/northwind/security.yaml` for Northwind; set `SQLAGENT_ROLES` to use other roles) and is useful for testing the agent and its security controls directly.

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

### Unit tests

Run every test in the project (no database or model needed):

```bash
python -m unittest discover tests -v
```

Or just the domain routing tests:

```bash
python -m unittest tests.test_domains -v
```

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
3. Point your page at the ngrok URL and set your page's origin once as a Windows user environment variable (then open a new PowerShell window):
   `setx DEMO_ALLOWED_ORIGIN "https://example.com,https://www.example.com"`
   If it's unset, the API allows same-origin requests only.

`api.yaml` sets `trusted_proxy_hops: 1` because ngrok is the one proxy in front of the API; change it if you use a different setup. CORS is limited to the origins in `allowed_origins` (or `DEMO_ALLOWED_ORIGIN`).

### Endpoints

| Method | Path          | Purpose                                               |
| ------ | ------------- | ----------------------------------------------------- |
| `POST` | `/api/ask`    | `{ "question": "...", "session_id": "..." }` → answer |
| `GET`  | `/api/status` | Whether the demo is currently enabled                 |
| `GET`  | `/api/health` | Liveness and number of tables loaded                  |

### Turning the demo on and off

`/api/ask` only answers while `demo_enabled.flag` exists next to `api.py`.

Delete the file to switch the demo off without stopping the server; the page then shows an "unavailable" message.

Every anonymous visitor gets the same fixed, narrow context: the `demo` role in `config/northwind/security.yaml`, eight Northwind tables, with customer phone, fax and address, and employee home phone, denied.

---

## Configuration

All runtime settings live in YAML under `config/settings/`, next to each database's own configuration:

```
config/
  settings/
    databases.yaml   which databases exist and how to reach them
    llm.yaml         Ollama host and model, timeouts, conversation history
    api.yaml         public demo API: CORS, proxy hops, rate limits, concurrency, timeouts
    query.yaml       limits on every generated query: statement timeout, max rows, max result bytes
    retrieval.yaml   which authorised tables are shown to the LLM per question
    repl.yaml        local REPL user
  northwind/         per database: security.yaml, semantic/, identity.yaml
  adventureworks/
  northwind_mssql/
```

Each file documents its own keys. They are loaded once at startup by `sqlagent/settings.py` and validated: an unknown key, a value out of range (e.g. `max_rows: 0`), weights that don't add up to 1, or a statement timeout that isn't below the API timeout stops startup. The `[settings]` startup line shows the folder in use and any environment overrides.

**Precedence:** environment variable, then the YAML file, then the built-in default. The environment variable names are unchanged (`OLLAMA_MODEL`, `DEMO_AGENT_TIMEOUT`, `PG_STATEMENT_TIMEOUT_SECONDS`, ...), and each file lists the variable beside the key it overrides. Use them for a one-off run or a deployment; keep the normal values in the YAML. An empty variable counts as unset. `SQLAGENT_SETTINGS_DIR` points at a different settings folder.

**Secrets are never stored in a settings file.** A key ending in `_env` names the environment variable that holds the secret, so the file shows where each one comes from:

```yaml
# databases.yaml
connection:
  user: sqlagent_ro
  password_env: PG_PASSWORD     # value from the environment, never here

# llm.yaml
username_env: OLLAMA_USERNAME
password_env: OLLAMA_PASSWORD
```

A literal `password`, `username`, `secret`, `token` or `api_key` key anywhere in a settings file, or an `Authorization` header in `llm.yaml`, is rejected at startup. A placeholder value such as `password: "[set by environment]"` is deliberately not used: it would be one edit away from holding the real password. Startup reports whether each password was found without printing it (`password from $PG_PASSWORD: set`).

`run.ps1` selects the database and supplies the password variable that database's `password_env` names (`PG_PASSWORD`, `SQLSERVER_PASSWORD`, ...): from the window, your Windows user variables or a hidden prompt. It no longer sets any other configuration.

### Switching databases

Everything that belongs to one database hangs off its name in `config/settings/databases.yaml`:

```yaml
default: northwind
databases:
  northwind:
    connection: {host: localhost, port: 5432, database: northwind, user: sqlagent_ro,
                 password_env: PG_PASSWORD}
    repl_roles: [sales]      # main.py
    demo_roles: [demo]       # api.py
```

`engine` names the database product: `postgresql` (the default) or `sqlserver`. It decides the SQL dialect, the driver and the catalog queries; see `sqlagent/execution/engines/`. `default_schema` sets the schema for a bare table name, otherwise the engine's (`public` for PostgreSQL, `dbo` for SQL Server). SQL Server connections also take `driver`, `encrypt` and `trust_server_certificate`, and `host` may name an instance (`SERVER\SQLEXPRESS`).

By convention the name also finds the database's own files in `config/<name>/`; set `security_file`, `semantic_path` or `identity_file` to use other locations:

| File | |
| ---- | - |
| `security.yaml` (required) | who may see what |
| `semantic/` (optional) | what the data means |
| `identity.yaml` (optional) | how the agent talks about the database |

`identity.yaml` holds the name used in the LLM prompt and in user-facing messages, the names users call the database (recognised in "what does Northwind have?", and never used as a filter value by the LLM), the example questions offered when a question is vague or off topic, and `sql_examples`: a few worked question → SQL examples for the model in that database's own names and dialect. It never affects access. Without the file, the database's key is used as its name and no examples are offered; an invalid file stops startup.

```yaml
# config/northwind/identity.yaml
version: 1
display_name: Northwind
names: [Northwind, North Wind]
about: a sample trading company's database
example_questions:
  - Which customers are in Germany?
sql_examples:
  - question: how many customers are there?
    sql: SELECT COUNT(*) FROM customers
```

Pick a database with `-db`, or set it once as a user variable:

```powershell
.\run.ps1 -local -db adventureworks
setx SQLAGENT_DATABASE adventureworks
```

Without either, the file's `default` is used. Startup prints the choice (`[database] northwind: sqlagent_ro@localhost:5432/northwind ...`) and the API records it in the `startup` audit line. An unknown name, a missing security file or an invalid `databases.yaml` stops startup. `PG_HOST`, `PG_DATABASE` and the like are ignored, so a value left over in a PowerShell window can't pair one database's security policy with another database. The unit tests always use Northwind, whatever is selected.

To add a database: load it, grant `sqlagent_ro` read access, add an entry to `databases.yaml`, then create `config/<name>/security.yaml` and (optionally) `config/<name>/semantic/` and `config/<name>/identity.yaml`. Check it with `tools/check_engine.py --db <name>`.

### Environment variables

These override the settings files, or select what the files can't:

| Variable | Overrides / purpose |
| -------- | ------------------- |
| `SQLAGENT_DATABASE` | Which database in `databases.yaml` (default: its `default`) |
| `PG_PASSWORD`, `SQLSERVER_PASSWORD` | *(secret)* the database password, whichever variable the database's `password_env` names |
| `OLLAMA_USERNAME`, `OLLAMA_PASSWORD` | *(secret)* only if Ollama sits behind basic auth |
| `OLLAMA_HOST`, `OLLAMA_MODEL`, `OLLAMA_CONNECT_TIMEOUT`, `OLLAMA_READ_TIMEOUT` | `llm.yaml` |
| `DEMO_ALLOWED_ORIGIN`, `DEMO_TRUSTED_PROXY_HOPS`, `DEMO_MAX_QUESTION_CHARS`, `DEMO_SESSION_RPM`/`RPD`, `DEMO_IP_RPM`/`RPD`, `DEMO_MAX_CONCURRENCY`, `DEMO_QUEUE_WAIT`, `DEMO_AGENT_TIMEOUT`, `DEMO_MAX_SLOT_HOLD`, `DEMO_MAX_SESSIONS`, `DEMO_AUDIT_LOG` | `api.yaml` |
| `PG_STATEMENT_TIMEOUT_SECONDS` | `query.yaml` |
| `SQLAGENT_USER` | `repl.yaml` |
| `SQLAGENT_ROLES` | REPL only: comma-separated roles (default: the profile's `repl_roles`) |
| `SQLAGENT_SECURITY_FILE`, `SQLAGENT_SEMANTIC_PATH` | The profile's security file / semantic folder |
| `SQLAGENT_SETTINGS_DIR` | The settings folder (default `config/settings/`) |

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

Keep `max_concurrency` in `api.yaml` equal to `OLLAMA_NUM_PARALLEL`. Both default to 1, which keeps the queue in the API: a second visitor waits up to `queue_wait` seconds for a free slot, then gets a prompt "busy" reply. If the API allowed more runs than Ollama answers at once, the extra runs would be admitted but then wait inside Ollama, and because each run makes two or more model calls, that wait would count against `agent_timeout` and could end in a timeout. To let visitors wait longer for a turn, raise `queue_wait`. If you raise `OLLAMA_NUM_PARALLEL`, raise `max_concurrency` to match, bearing in mind that each extra slot uses more GPU memory.


### Demo API

The API's limits are in `config/settings/api.yaml`: CORS origins, trusted proxy hops, question length, per-IP and per-session rate limits, concurrency, queue wait, agent timeout, slot hold, sessions kept in memory and the audit log path. Wildcard CORS origins are rejected.

Run with `--workers 1`. The rate limiter and session store are in memory and are not shared across worker processes.

### Security policy (`config/<database>/security.yaml`)

Who may see what, one file per database (`config/northwind/security.yaml` for the demo). Owned by security / IT and reviewed separately from the semantic model, which can never widen access.

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
* **Fails closed.** A missing file, invalid YAML, a duplicate or unknown key, `default` other than `deny`, a `deny_columns` table the role isn't granted (usually a typo), or an undefined role stops startup, and so does a role that ends up with no tables at all (usually missing database grants, e.g. after loading a new database). A denied column that doesn't exist on its table is logged as a warning.
* **Users come from identity, not the file.** `group_roles` maps identity-provider groups to roles (`SecurityPolicy.roles_for_groups`). The demo API always uses the `demo` role; the REPL uses `SQLAGENT_ROLES`.

### Semantic model (`config/<database>/semantic/`)

What the data means, one folder per database (`config/northwind/semantic/`: `model.yaml` and `domains.yaml`). Every `.yaml` file directly in the folder is merged, so a large ERP can have one file per domain; sub-folders are never read. Nothing here grants access: it is applied to the catalog after security filtering, and anything that names a table or column the role can't see is skipped.

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

### Domains of Discourse (`config/<database>/semantic/domains.yaml`)

Named subsets of the schema (Sales, Purchasing & Inventory, Shipping & Logistics, Human Resources, Financials for Northwind). For each question the agent picks the best-matching domain from three signals and starts its table search there:

* **What:** the words in the question.
* **Where:** the user's working context, such as the screen or function they asked from. In a real deployment the calling application supplies this.
* **Who:** the user's roles, which come from their identity.

The demo has no host application or sign-in, so it simulates the last two with tags at the end of a question:

```text
what was the last order? [where=shipping desk]   → Shipping & Logistics
show me the latest one [where=PUR0410]           → Purchasing & Inventory (function code)
what was the last order? [who=accountant]        → Financials
```

Tags are stripped before the question reaches the LLM. `[who=...]` only affects routing, never access, and is controlled by `domains.allow_who_tag` in `config/settings/retrieval.yaml`; turn it off outside the demo. The routing weights and thresholds are in the same file.

Routing changes where the search *starts*, never what the user may *see*: domains are mapped onto the security-filtered catalog and every layer in [Defence in depth](#defence-in-depth) still runs. The chosen domain is printed as a `[domain]` line in the console.

The environment variables that select the database, security file and semantic folder are listed under [Environment variables](#environment-variables).

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
* The table and column names in `config/northwind/` assume the snake_case PostgreSQL port of Northwind, and `config/northwind_mssql/` the original SQL Server Northwind. Check them against your schema before running (`tools/check_engine.py`). Startup logs every name it can't find.
* On SQL Server, read-only access rests on the login's permissions (see [SQL Server](#sql-server)); PostgreSQL also enforces a read-only transaction.
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
