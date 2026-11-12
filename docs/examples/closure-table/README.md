# Closure-table example: large teams as one value

A worked, runnable example of the approach in the main README's "Large scopes" section, on Northwind, for PostgreSQL and SQL Server. Nothing here is loaded unless you point the agent at it; the shipped configuration is unchanged.

## Why

The shipped Northwind policy grants a manager `salesperson: team`. At sign-in the agent walks `reports_to` and writes the whole team into the query: `employee_id IN (5, 6, 7, 9)` for Steven. That works for a team of four, but a senior manager in a large company can have thousands of people below them, and `max_scope_values` in `config/settings/query.yaml` stops anyone whose list is too long.

A **closure table** has one row for each manager and each person below them, at any depth. Each employee is also listed as their own manager, so a team includes its manager. The database does the lookup, so the query carries only the manager's own ID:

```sql
-- Steven's filter on orders, closure version
EXISTS (SELECT 1 FROM public.employees AS _s1
        WHERE _s1.employee_id = _t.employee_id
          AND EXISTS (SELECT 1 FROM public.employee_hierarchy AS _s2
                      WHERE _s2.employee_id = _s1.employee_id AND _s2.manager_id IN (5)))
```

It costs the same for a team of 4 or 40,000, and it's an index lookup on the closure table's primary key.

## Files

| File | |
| ---- | - |
| `employee_hierarchy.postgres.sql` | Creates `public.employee_hierarchy`, grants `sqlagent_ro` read access, and refills it from `reports_to` |
| `employee_hierarchy.sqlserver.sql` | The same for SQL Server: `dbo.EmployeeHierarchy` from `ReportsTo` |
| `security.postgres.yaml` | The shipped Northwind policy, changed to use the closure table |
| `security.sqlserver.yaml` | The same for `northwind_mssql` |

Every change from the shipped policy is marked `# CLOSURE:`. In short:

- **`sales_manager` extends `sales` and adds the closure table.** It's part of the team filter, so the role must be allowed it.
- **A new dimension, `team`, starts at the closure table's manager column** and follows employees → orders → order lines and customers.
- **`Sales-Team` is granted `team: self`**, one value, instead of `salesperson: team`.
- **`salesperson` keeps `self` for reps**, so they see only their own orders. It no longer needs a `hierarchy`.
- **Every dimension has a rule for the closure table**, as for any table the role allows.

The closure table has **two** foreign keys to employees (manager and employee). So the rules that join it to employees spell out `join:`. Without it, startup stops with "more than one foreign key joins them", instead of guessing the wrong column.

## Try it

1. **Create the table**, as the database owner, not the agent's read-only login:

   ```powershell
   # PostgreSQL
   psql -U postgres -d northwind -f docs\examples\closure-table\employee_hierarchy.postgres.sql
   # SQL Server (Windows sign-in, as an administrator)
   sqlcmd -S BRAD-Z640 -d Northwind -E -i docs\examples\closure-table\employee_hierarchy.sqlserver.sql
   ```

   The script is safe to run again. Run it whenever the reporting lines change: from the HR feed, or nightly with a scheduled task or SQL Agent job. It replaces the contents in one transaction, so the agent never sees a half-built table.

2. **Point the agent at the example policy** for this PowerShell window only:

   ```powershell
   $env:SQLAGENT_SECURITY_FILE = "docs\examples\closure-table\security.sqlserver.yaml"
   .\run.ps1 -local -db northwind_mssql -identity steven
   ```

   Startup prints Steven's grant as `sales_manager (team [5])`. In the shipped policy it is `salesperson [5, 6, 7, 9]`. He should see exactly the same orders as with the shipped policy: with the standard Northwind data, 224 of the 830, his team's. The local identities still come from `config/idp/northwind.yaml`.

3. **Check every identity:**

   ```powershell
   .\.venv\Scripts\python tools\check_row_scope.py --db northwind_mssql
   ```

4. **Go back to the shipped policy:**

   ```powershell
   Remove-Item Env:SQLAGENT_SECURITY_FILE
   ```

   The variable lasts for the PowerShell window. Clear it before switching databases: the example policy names one database's tables.

## Verified

On a PostgreSQL copy of Northwind, with the table built by `employee_hierarchy.postgres.sql`, `security.postgres.yaml` gave **the same rows as the shipped policy** for all six local identities and 23 query shapes: joins, outer joins, subqueries, CTEs, `UNION` / `INTERSECT`, scalar subqueries and a self-join. The refresh was also run against a `reports_to` cycle: PostgreSQL's `UNION` stops on the repeat, and SQL Server's `MAXRECURSION` fails the refresh and rolls it back. `tests/test_row_scope.py` (`ClosureExample`) loads both policies and checks that Steven's filter carries his own ID only.

## Variations

- **Reports only, not including the manager.** Add a `depth` column to the closure table (0 for the self row) and grant through a view that filters `depth > 0`. Or keep a second closure table without the self rows.
- **Not a hierarchy.** The same shape covers any access list kept as data: an entitlements table `user_regions(user_id, region_id)`, maintained by the access-management process, with `user_regions: {column: user_id}` and the regional tables `via` it, granted as `self`. Access changes then become data changes rather than YAML edits.
- **A path column** (SQL Server `hierarchyid`, AdventureWorks' `OrganizationNode`) can fill the closure table the same way: one row per ancestor in each employee's path.
