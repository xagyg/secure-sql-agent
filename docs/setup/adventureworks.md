# Setting up AdventureWorks (PostgreSQL)

AdventureWorks is Microsoft's sample database for a fictional bicycle
manufacturer: 68 tables of sales, purchasing, production, HR and people
data across several schemas. It is closer to a real ERP than Northwind,
so it is a better test of schema size, routing and role design.

The agent is configured for it as `adventureworks` in
`config/settings/databases.yaml`, with its files in
`config/databases/adventureworks/`.

Back to the [main README](../../README.md#database-setup).

## 1. Load the database

Use [ggodreau/adventureworks](https://github.com/ggodreau/adventureworks),
a PostgreSQL port of AdventureWorks 2014 that ships with the data already
converted to CSV, so there is nothing to download or convert first.

It needs `psql` on the machine that runs the script, and the server needs
the PostgreSQL contrib extensions (`uuid-ossp` and `tablefunc`), which
`install.sql` uses. They come with the standard Windows installer; on Linux
install the `postgresql-contrib` package.

1. Clone the repository and open a window in its folder.
2. Create the database:

   ```powershell
   psql -U postgres -c "CREATE DATABASE adventureworks;"
   ```

3. Load it:

   ```powershell
   psql -U postgres -d adventureworks -f install.sql
   ```

Name the database `adventureworks`, in lower case: that's the name
`databases.yaml` connects to. To load into a remote server, add
`-h <host>`; the CSVs are sent from your machine.

## 2. Schemas

| Schema                         | Contents                                                   |
| ------------------------------ | ---------------------------------------------------------- |
| `humanresources`               | Employees, departments, shifts, pay history                |
| `person`                       | People, addresses, contact details                         |
| `production`                   | Products, inventory, bills of materials, work orders       |
| `purchasing`                   | Vendors, purchase orders                                   |
| `sales`                        | Customers, orders, territories, special offers             |
| `hr`, `pe`, `pr`, `pu`, `sa`   | Short-name views: a `SELECT *` copy of every base table    |
| `public`                       | PostgreSQL's default schema; unused                        |

The agent uses only the five business schemas. The short-name view
schemas repeat every table under another name, so the semantic model
leaves them out of discovery (`sources:` in
`config/databases/adventureworks/semantic/model.yaml`), and the login
below isn't granted them.

To list the schemas in your copy:

```sql
SELECT schema_name FROM information_schema.schemata ORDER BY schema_name;
```

or `\dn` in `psql`.

## 3. Read-only login

Use the same `sqlagent_ro` login as for Northwind (`CREATE ROLE sqlagent_ro
LOGIN PASSWORD '...';` if it doesn't exist yet). Grant it the five
business schemas, then take back the objects that hold secrets or
personal data, which no role in `security.yaml` is meant to see:

```sql
GRANT CONNECT ON DATABASE adventureworks TO sqlagent_ro;

GRANT USAGE ON SCHEMA humanresources, person, production, purchasing, sales
  TO sqlagent_ro;

GRANT SELECT ON ALL TABLES IN SCHEMA
    humanresources, person, production, purchasing, sales
  TO sqlagent_ro;
```

`ALL TABLES` includes the views in those schemas. The security policy
and the semantic model's `exclude:` list keep the remaining sensitive
views away from the model.
Revoke them here as well if you want the database login to enforce that
too.

The login's grants are the outer boundary: the security policy can only
narrow them, never widen them.

**Do not run this against a database containing real people's
information.**

## 4. Check and run

Check the connection, catalog and read-only guards without the LLM:

```powershell
.\.venv\Scripts\python tools\check_engine.py --db adventureworks
```

Then run the REPL against it:

```powershell
.\run.ps1 -local -db adventureworks
```

Or select it for every run with `setx SQLAGENT_DATABASE adventureworks`
(then open a new PowerShell window).

## 5. Roles and local identities

`config/databases/adventureworks/security.yaml` defines a role per
department (`sales`, `purchasing`, `production`, `hr`, `finance`), plus
`demo` for the public API and `explorer` for broad testing. Every table
is granted by explicit name rather than by wildcard, except in
`explorer`. There is no row-level security for AdventureWorks yet.

`config/idp/adventureworks.yaml` holds local identities to sign in as
(see [Local identities](../row-level-security.md#8-local-identities-demo-environment)):

| Identity      | Groups                                   | Who                                            |
| ------------- | ---------------------------------------- | ---------------------------------------------- |
| `ken`         | every department                         | Ken Sanchez, CEO                               |
| `brian`       | `AW-Sales`                               | Brian Welcker, VP Sales                        |
| `stephen`     | `AW-Sales`                               | Stephen Jiang, North American Sales Manager    |
| `michael`     | `AW-Sales`                               | Michael Blythe, Sales Representative           |
| `laura`       | `AW-Finance`, `AW-Purchasing`            | Laura Norman, CFO                              |
| `sheela`      | `AW-Purchasing`                          | Sheela Word, Purchasing Manager                |
| `james`       | `AW-Production`                          | James Hamilton, VP Production                  |
| `hr_analyst`  | `AW-HR`                                  | An HR analyst                                  |
| `explorer`    | `AW-Explorer`                            | Every table; secrets and national IDs hidden   |
| `contractor`  | `Contoso-Staff`                          | In no AdventureWorks group: sees nothing       |

```powershell
.\run.ps1 -local -db adventureworks -identity laura
```

A file of test questions is in `tests/questions/aworks-full.txt`:

```powershell
.\run.ps1 -questions tests\questions\aworks-full.txt -db adventureworks
```
