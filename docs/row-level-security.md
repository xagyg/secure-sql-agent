# Row-level security (`scopes` and `group_grants`)

Secure SQL Agent separates **what a user can access** from **which rows
they can see**.

-   **Roles** determine which tables and columns a user can access (see
    [Security policy](../README.md#security-policy-configdatabasesdatabasesecurityyaml)
    in the main README).
-   **Scopes** determine which rows within those tables are visible.
-   **Grants** associate a role with a scope.
-   **Identity-provider groups** assign grants to users.

This means a single role, such as `sales_manager`, can serve users with
very different levels of access without creating multiple copies of the
role.

For example:

| User type        | Role            | Scope              | Access                  |
| ---------------- | --------------- | ------------------ | ----------------------- |
| VP Sales         | `sales_manager` | `unrestricted`     | All sales rows          |
| Regional manager | `sales_manager` | `region: [1]`      | Rows for their region   |
| Team leader      | `sales_manager` | `salesperson: team`| Their own team's rows   |
| Sales rep        | `sales_manager` | `salesperson: self`| Their own rows          |

The role remains the same; only the scope changes.

The complete Northwind policy is in
[`config/databases/northwind/security.yaml`](../config/databases/northwind/security.yaml).

## 1. Defining roles, scopes and grants

The following example illustrates how these concepts fit together:

```yaml
roles:
  sales_manager:
    extends: sales
    scope: required

scopes:
  salesperson:
    user_attribute: employee_id
    hierarchy:
      table: employees
      key: employee_id
      parent: reports_to
    tables:
      orders:        {column: employee_id}
      order_details: {via: orders}
      customers:     {via: orders}
      products:      unscoped

  region:
    # defined the same way: see config/databases/northwind/security.yaml

group_grants:
  Sales-National:
    - {role: sales_manager, scope: unrestricted}

  Sales-Eastern:
    - {role: sales_manager, scope: {region: [1]}}

  Sales-Team:
    - {role: sales_manager, scope: {salesperson: team}}

  Sales-Rep:
    - {role: sales_manager, scope: {salesperson: self}}
```

Here, `extends: sales` reuses the existing sales role, including its
table permissions and hidden columns.

The `scope: required` declaration means that every grant for this role
must explicitly specify a scope. There is no implicit unrestricted
access. `scope` is not inherited: a role that extends one with
`scope: required` must declare it too.

## 2. How scopes apply to tables

Every table accessible through a scoped role must have a rule describing
how its rows are restricted.

There are three possible rules:

| Rule       | Meaning                                       | Example                                  |
| ---------- | --------------------------------------------- | ---------------------------------------- |
| `column`   | The table contains the column used to filter rows. | Orders filtered by `employee_id`.   |
| `via`      | Rows are visible when a related row is visible. | An order line follows its order's scope. |
| `unscoped` | All rows are visible.                         | Reference data such as products.         |

For example:

-   `orders` is filtered directly using `employee_id`.
-   `order_details` inherits the scope of its related order.
-   `customers` are visible when they have at least one order in scope.
-   `products` are reference data and are not filtered.

`via` rules can be chained: a table can be scoped via a table that is
itself scoped via another.

### Fail-closed behaviour

By default, every table must have an explicit scope rule.

If a table is missing a rule, sign-in fails for anyone granted that
scope. This prevents a newly added table from accidentally becoming
accessible without row-level filtering.

Alternatively, a scope can declare:

```yaml
default: unscoped
```

This reverses the default: only explicitly listed tables are filtered;
all other tables are unrestricted. The shipped Northwind policy uses this.

Sign-in logs identify the tables covered by this default, for example:

```text
[security] scope salesperson: unscoped by default for role sales_manager: public.categories, ...
```

When using this approach, any table requiring filtering must be
explicitly listed before it is added to the role.

## 3. How `via` relationships work

A `via` rule allows a table to inherit the row restrictions of another
table.

By default, Secure SQL Agent discovers the database foreign key
connecting the two tables. It can follow the relationship in either
direction.

For example, an order detail is in scope when its associated order is in
scope.

Startup logs show the joins discovered:

```text
[security] scope region: public.orders via public.employees on employee_id = employee_id (foreign key)
```

If there is no foreign key, or multiple possible foreign keys, startup
stops and requires an explicit join.

This is important when a table has multiple relationships to another
table, such as an order containing both `customer_id` and
`billing_customer_id`. Specify the relationship explicitly, as this
table's column mapped to the related table's column:

```yaml
orders:
  via: customers
  join:
    billing_customer_id: customer_id
```

The configuration key is `join`, not `on`: YAML reads an unquoted `on` as
`true`. An explicit `join` always takes precedence over automatic
foreign-key discovery. Secure SQL Agent never guesses which relationship
to use.

## 4. Supported scope values

Scope values can be fixed lists, unrestricted access or dynamically
resolved from the signed-in user's identity.

| Value          | Meaning                                                    |
| -------------- | ---------------------------------------------------------- |
| `[1, 2, 3]`    | A fixed list of permitted values.                          |
| `unrestricted` | All rows are visible.                                      |
| `self`         | Only the signed-in user.                                   |
| `team`         | The user and everyone below them in the hierarchy.         |
| `reports`      | Everyone below the user, excluding the user themselves.    |

Relative scopes are resolved at sign-in using the user's identity
attributes (the scope's `user_attribute`). `team` and `reports` need the
scope's `hierarchy`.

For example, a team leader's `team` scope is calculated from their
`employee_id` and the configured reporting hierarchy. Changes to the
organisational structure therefore flow through without requiring
changes to the security policy.

## 5. Multiple grants and effective access

A user can receive multiple grants, and each grant is evaluated
independently.

The resulting behaviour is:

-   A row is visible if it is permitted by **any** of the user's grants.
-   Unrestricted access must be explicitly granted.
-   A scope that resolves to no values provides no rows.
-   If grants expose different rows of a table, a column is visible only
    when every applicable grant permits that column.

This allows users to combine entitlements from different groups without
creating additional roles.

## 6. SQL enforcement

Row-level security is enforced in the SQL execution pipeline
(`sqlagent/controls/row_scope.py`), not through instructions to the
language model.

Immediately before execution, every reference to a scoped table is
rewritten as a filtered subquery:

```sql
(SELECT *
 FROM orders AS _t
 WHERE <row-level filter>) AS <alias>
```

This ensures that only permitted rows are available to the query.

The rewriting applies consistently to:

-   Ordinary joins and outer joins.
-   Subqueries and scalar subqueries.
-   Common table expressions (CTEs).
-   Self-joins.
-   Every branch of a `UNION`.

After rewriting, the final SQL is parsed again and checked. Every scoped
table must be contained within its exact required filter. If the
validation fails, execution is blocked.

Importantly, the SQL correction and explanation stages, along with
conversation history, retain the SQL as originally written by the model.
Entitlements and resolved scope values are never exposed in model
prompts.

## 7. Startup diagnostics

Secure SQL Agent logs the resolved security configuration at startup
and sign-in.

This includes:

-   Each user's grants.
-   Each grant's resolved scope.
-   The tables covered by each scope.
-   The resulting row filters.
-   The joins used to propagate scope through related tables.

This makes it possible to inspect and troubleshoot the effective
security configuration without relying on assumptions about how the
policy is interpreted.

## 8. Local identities (demo environment)

In a production deployment, the identity provider supplies each user's
groups and attributes.

The demo environment does not implement sign-in. Instead, `config/idp/`
contains one identity file per organisation, representing the
information that would normally come from an identity provider.

For example:

```powershell
.\run.ps1 -local -identity steven
```

The database selects its identity file through the `idp:` setting in
`config/settings/databases.yaml`. By default, the database name is used.

This allows `northwind` and `northwind_mssql` to share:

```text
config/idp/northwind.yaml
```

A legacy `identities.yaml` file alongside a security policy prevents
startup, ensuring that an outdated identity configuration cannot
accidentally be edited or used.

The API never reads these local identity files.

### Northwind demo identities

| Identity             | Group(s)                       | Description                                              |
| -------------------- | ------------------------------ | -------------------------------------------------------- |
| `andrew`             | `Sales-National`               | VP Sales: unrestricted access to all rows.               |
| `steven`             | `Sales-Team`                   | Access to his reporting team.                            |
| `nancy`              | `Sales-Rep`                    | Access to her own orders.                                |
| `eastern`            | `Sales-Eastern`                | Access to the Eastern region.                            |
| `steven_and_eastern` | `Sales-Team`, `Sales-Eastern`  | Receives two independent grants.                         |
| `no_employee`        | `Sales-Team`                   | Has no employee record and therefore sees no team rows.  |
| `explorer`           | `Northwind-Explorer`           | Every table, personal details hidden; no row scope.      |

## 9. Testing and verification

The row-level security check tool verifies effective access on a real
database, without the LLM. From the project root:

```powershell
.\.venv\Scripts\python tools\check_row_scope.py --db northwind
.\.venv\Scripts\python tools\check_row_scope.py --db northwind --identity steven
```

For each identity (or the one given), the tool:

-   Displays the user's grants and resolved scopes.
-   Reports how many rows are visible in each table.
-   Checks that different SQL query structures produce consistent
    results.

The unit tests (`tests/test_row_scope.py`) cover subqueries, CTEs,
`UNION`, scalar subqueries and self-joins.

The SQL rewriting implementation has also been verified against
hand-written ground-truth views in PostgreSQL:

-   6 identities.
-   23 query shapes.
-   Identical results across all comparisons.
-   Deliberate removal of a row filter successfully detected.

---

# Large scopes and hierarchy optimisation

## The problem with large scopes

Relative scopes such as `team` are normally resolved into explicit lists
of permitted values.

For example, a manager responsible for four employees might produce:

```sql
employee_id IN (5, 6, 7, 9)
```

This is straightforward and works well for relatively small teams.

However, for senior managers with thousands of employees, embedding
large lists directly into SQL becomes problematic:

-   SQL query planning becomes more expensive.
-   SQL Server's plan cache can fill with one-off query plans.
-   Very large lists can exceed SQL Server's query-processing limits,
    resulting in error 8623.

To prevent this, Secure SQL Agent provides the `max_scope_values`
setting in `config/settings/query.yaml`. The default is:

```yaml
max_scope_values: 1000
```

This limits the number of values that a single scope dimension can
resolve to for an individual user.

If the limit is exceeded, access resolution fails. The error identifies
the affected user, role and scope.

**There is no fallback to an oversized list or to unrestricted access.**

## Using a closure table for large hierarchies

For large organisational hierarchies, a better approach is to let the
database resolve the hierarchy rather than embedding thousands of
employee IDs in the SQL.

A **closure table** stores the relationship between every manager and
every person below them, regardless of hierarchy depth.

It also includes each person as their own manager. This is important
because it allows a grant of `self` to represent the entire team,
including the manager.

For example:

| manager_id | employee_id |
| ---------- | ----------- |
| 5          | 5           |
| 5          | 6           |
| 5          | 7           |
| 5          | 9           |
| 6          | 6           |
| 6          | 7           |
| 6          | 9           |
| 7          | 7           |
| 9          | 9           |

The table is maintained by an HR feed or a scheduled database job.

The security policy can then use the closure table as follows, with the
manager's grant using `self`:

```yaml
salesperson:
  user_attribute: employee_id
  tables:
    hr.employee_hierarchy:
      column: manager_id

    hr.employees:
      via: hr.employee_hierarchy
      join:
        employee_id: employee_id

    sales.orders:
      via: hr.employees
```

The important difference is that the user's scope now resolves to a
single manager ID rather than a potentially enormous list of employee
IDs.

For employee 5, the resulting filter on `sales.orders` is conceptually
equivalent to:

```sql
EXISTS (
    SELECT 1
    FROM hr.employees AS _s1
    WHERE _s1.employee_id = _t.employee_id
      AND EXISTS (
          SELECT 1
          FROM hr.employee_hierarchy AS _s2
          WHERE _s2.employee_id = _s1.employee_id
            AND _s2.manager_id IN (5)
      )
)
```

The database determines which employees belong to manager 5's hierarchy.

### Why is an explicit join required?

The closure table has two foreign keys to `employees`: `manager_id` and
`employee_id`.

Because there are multiple possible relationships, the policy must
specify the intended join. Without it, startup fails rather than
guessing.

## Runnable closure-table example

A complete Northwind example is in
[`docs/examples/closure-table/`](examples/closure-table/README.md).

It includes:

-   SQL to create and refresh the closure table.
-   PostgreSQL and SQL Server implementations.
-   Complete security policies for both databases.
-   Example configurations and test instructions.

On a copy of Northwind, the closure-table implementation produced the
same results as the original `team` scope for every identity across all
23 query shapes.

## Extending the pattern beyond organisational hierarchies

The same approach works for other types of entitlements.

For example, a business might maintain a table:

```sql
user_regions(user_id, region_id)
```

This table could be populated by an access-management process and used,
with a grant of `self` via that table, to determine which regions a user
can access.

Rather than embedding region lists in YAML, Secure SQL Agent can resolve
the user's permitted regions through the database.

This has an important operational advantage: **access changes become
data changes rather than security-policy changes.**

The closure-table and entitlement-table approaches allow row-level
security to scale with the size and complexity of an organisation
without requiring increasingly large SQL statements or duplicated roles.
