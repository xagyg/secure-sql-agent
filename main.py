# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Runs against the database chosen in config/databases.yaml
# (SQLAGENT_DATABASE, or the file's default; .\run.ps1 -local -db <name>).
# That profile gives the connection, the security file
# (config/security/<database>.yaml) and the semantic model
# (config/semantic/<database>/). The REPL's roles are the profile's
# repl_roles unless SQLAGENT_ROLES is set. Check the table and column
# names in those files against your schema first:
#     psql -c '\dt public.*'
#     psql -c '\d public.customers'

import json
import os
import sys

from sqlagent.agent import run_agent
from sqlagent.databases import DatabaseConfigError, active_database
from sqlagent.controls.security_policy import (
    SecurityPolicyError,
    load_security_policy,
)
from sqlagent.adaptive.schema_catalog import SchemaCatalog
from sqlagent.adaptive.semantic_model import SemanticModelError, load_semantic_model
from sqlagent.execution.sql_execution import get_connection, execute_sql, list_tables


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# History length is llm.MAX_HISTORY_TURNS; run_agent() trims it.
conversation_history = []

# The local user and their roles. In a real deployment both come from
# the user's sign-in (identity-provider groups -> roles, see group_roles
# in config/security/<database>.yaml); here the user is SQLAGENT_USER and
# the roles are SQLAGENT_ROLES, else the database profile's repl_roles.
LOCAL_USER = os.environ.get("SQLAGENT_USER", "brad")


def local_roles(profile):
    override = os.environ.get("SQLAGENT_ROLES", "")
    roles = {role.strip() for role in override.split(",") if role.strip()}
    return roles or set(profile.repl_roles)


# ---------------------------------------------------------------------------
# Shell
# ---------------------------------------------------------------------------

def print_banner():
    print()
    print("==============================================")
    print("        Ollama PostgreSQL Agent")
    print("==============================================")
    print()
    print("Commands:")
    print("  :schema     Show database schema")
    print("  :sql        Enter SQL directly")
    print("  :quit       Exit")
    print()
    print("Ask a natural-language database question.")
    print()


def main():
    print_banner()

    # Configuration errors stop here, before the database is touched.
    try:
        profile = active_database()
        policy = load_security_policy()
        semantic = load_semantic_model()
    except (DatabaseConfigError, SecurityPolicyError, SemanticModelError) as ex:
        print(f"Configuration error: {ex}")
        sys.exit(1)

    try:
        security = policy.build_context(
            LOCAL_USER, local_roles(profile), list_tables(get_connection))
        catalog = SchemaCatalog(get_connection, security, semantic=semantic)
        catalog.refresh()
    except SecurityPolicyError as ex:
        print(f"Configuration error: {ex}")
        sys.exit(1)
    except Exception as ex:
        print("Unable to connect to PostgreSQL.")
        print(ex)
        sys.exit(1)

    print(
        f"[agent] Schema catalog loaded "
        f"({len(catalog.tables)} tables, "
        f"{len(catalog.foreign_keys)} foreign keys)."
    )

    while True:
        try:
            question = input("\n> ").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            break

        if not question:
            continue

 #       if question.lower() in (":quit", ":exit", ":q"):
 #           break

 #       if question.lower() == ":schema":
 #           print("\nSchema Catalog")
 #           print("================")
 #           print(f"Tables: {len(catalog.tables)}")
 #           print(f"Foreign keys: {len(catalog.foreign_keys)}")
 #           continue

        # -----------------------------------------------------
        # Developer/admin SQL command
        # -----------------------------------------------------
        # This deliberately bypasses AI table/column
        # authorisation because it is an explicit developer
        # command.
        #
        # It STILL passes through execute_sql(), meaning that
        # destructive SQL and multiple statements remain blocked.

#        if question.lower() == ":sql" or question.lower().startswith(":sql "):
#            if question.lower() == ":sql":
#                sql = input("\nSQL> ").strip()
#            else:
#                sql = question[4:].strip()
#
#            try:
#                results = execute_sql(sql)
#                print(json.dumps(results, default=str, indent=2))
#            except Exception as ex:
#                print(f"\n[SQL ERROR] {ex}")
#            continue

#        if question.lower() == ":search":
#            search = input("\nSearch> ").strip()
#            context = catalog.get_context(
#                search, table_limit=10, relationship_depth=1
#            )
#            print("\n" + context)
#            continue

        try:
            run_agent(question, catalog, conversation_history, security)
        except Exception as ex:
            # e.g. Ollama unreachable or too slow (see OLLAMA_*_TIMEOUT in
            # sqlagent/adaptive/llm.py). Report it and keep the REPL going.
            print(f"\n[error] {type(ex).__name__}: {ex}")
            print("\n[answer] Something went wrong answering that question. "
                  "Please try again.")

    print("\nGoodbye.")


if __name__ == "__main__":
    main()
