# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Checks row scope on a real database, WITHOUT the LLM, using the read-only
# login: for each local identity (config/idp/<idp>.yaml, the demo's
# stand-in for sign-in) it shows the grants and how many rows of
# each table that identity can see, and checks that the same table gives
# the same count however a query reaches it - a subquery, a CTE, a UNION,
# a join from another table. A difference means a query shape got round
# the filter.
#
# Usage (from the project root):
#     .\.venv\Scripts\python tools\check_row_scope.py --db northwind_mssql
#     .\.venv\Scripts\python tools\check_row_scope.py --db northwind --identity steven
#
# This checks consistency, not correctness against an independent truth:
# that needs views written by hand, which a read-only login can't create.
# The unit tests and README describe the ground-truth check.

import argparse
import contextlib
import getpass
import io
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def quietly(fn, *args, **kwargs):
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(*args, **kwargs)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True)
    parser.add_argument("--identity", help="check one identity (default: all)")
    args = parser.parse_args()
    os.environ["SQLAGENT_DATABASE"] = args.db
    os.environ.setdefault("OLLAMA_MODEL", "unused")

    from sqlagent.databases import load_database_profile
    profile = load_database_profile(args.db)
    if not os.environ.get(profile.connection.password_env):
        os.environ[profile.connection.password_env] = getpass.getpass(
            f"Password ({profile.connection.password_env}): ")

    from sqlagent.execution import sql_execution as se
    from sqlagent.execution.engines import active_engine
    from sqlagent.controls.security_policy import load_security_policy
    from sqlagent.controls.row_scope import apply_row_scope
    from sqlagent.identities import identities_file, load_identities

    engine = active_engine()
    policy = quietly(load_security_policy)
    tables = quietly(se.list_tables, se.get_connection)
    identities = load_identities(identities_file(profile))
    if args.identity:
        identities = {args.identity.lower(): identities[args.identity.lower()]}

    failures = 0

    def count(sql, row_filters):
        scoped = apply_row_scope(sql, row_filters, engine.dialect)
        rows, _ = se.execute_sql_with_sources(scoped)
        return list(rows[0].values())[0]

    visible = {}
    for name, ident in identities.items():
        ctx = quietly(policy.build_context, name, set(), tables, groups=ident.groups,
                      attributes=ident.attributes, read_hierarchy=se.read_hierarchy,
                      read_foreign_keys=se.read_foreign_keys,
                      log=False)
        print(f"\n=== {name}: {ident.description or ''}")
        print(f"  groups: {', '.join(ident.groups) or '(none)'}   attributes: {ident.attributes}")
        print(f"  grants: {'; '.join(ctx.grants) or '(none)'}")
        visible[name] = {}
        for table in sorted(ctx.tables):
            shown = engine.display_table(table)
            n = count(f"SELECT COUNT(*) AS n FROM {shown}", ctx.row_filters)
            visible[name][table] = n
            row_filter = ctx.row_filters.get(table.lower())
            marker = "filtered" if row_filter is not None else "all rows"
            print(f"  {n:>7}  {table}  ({marker})")
            if row_filter is None:
                continue
            for label, query in [
                ("subquery", f"SELECT COUNT(*) AS n FROM (SELECT * FROM {shown}) AS x"),
                ("CTE", f"WITH x AS (SELECT * FROM {shown}) SELECT COUNT(*) AS n FROM x"),
                ("UNION ALL", f"SELECT COUNT(*) AS n FROM (SELECT * FROM {shown} UNION ALL "
                              f"SELECT * FROM {shown} WHERE 1 = 0) AS x"),
                ("scalar subquery", f"SELECT (SELECT COUNT(*) FROM {shown}) AS n"),
                ("self-join", f"SELECT COUNT(*) AS n FROM {shown} AS a WHERE EXISTS "
                              f"(SELECT 1 FROM {shown} AS b WHERE 1 = 1)"),
            ]:
                try:
                    got = count(query, ctx.row_filters)
                except Exception as ex:
                    print(f"           FAIL {label}: {type(ex).__name__}: {ex}")
                    failures += 1
                    continue
                if got != n:
                    print(f"           FAIL {label}: {got} rows, expected {n}")
                    failures += 1

    # An identity with extra groups never sees fewer rows than with fewer.
    for name, ident in identities.items():
        for other, other_ident in identities.items():
            if (other != name and set(other_ident.groups) < set(ident.groups)
                    and other_ident.attributes == ident.attributes):
                for table, n in visible[other].items():
                    if visible[name].get(table, 0) < n:
                        print(f"FAIL {name} sees fewer {table} rows ({visible[name].get(table, 0)}) "
                              f"than {other} ({n}) despite holding more groups")
                        failures += 1

    print(f"\n{'All checks passed' if not failures else f'{failures} check(s) FAILED'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
