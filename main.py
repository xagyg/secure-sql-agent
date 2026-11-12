# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Runs against the database chosen in config/settings/databases.yaml
# (SQLAGENT_DATABASE, or the file's default; .\run.ps1 -local -db <name>).
# That profile gives the connection, the security file
# (config/databases/<database>/security.yaml) and the semantic model
# (config/databases/<database>/semantic/). The REPL's roles are the profile's
# repl_roles unless SQLAGENT_ROLES is set. Check the table and column
# names in those files against your schema first:
#     psql -c '\dt public.*'
#     psql -c '\d public.customers'

import json
import os
import sys

# Settings are read when the modules below are imported; load them first
# so a bad settings file is reported plainly rather than as a traceback.
from sqlagent.settings import SettingsError, get_settings

try:
    get_settings()
except SettingsError as ex:
    print(f"Configuration error: {ex}")
    sys.exit(1)

from sqlagent.agent import run_agent
from sqlagent.databases import DatabaseConfigError, active_database
from sqlagent.controls.security_policy import (
    SecurityPolicyError,
    load_security_policy,
)
from sqlagent.adaptive.schema_catalog import EmptyCatalogError, SchemaCatalog
from sqlagent.adaptive.semantic_model import SemanticModelError, load_semantic_model
from sqlagent.execution.engines import active_engine
from sqlagent.execution.sql_execution import (
    execute_sql,
    get_connection,
    list_tables,
    read_hierarchy,
    read_foreign_keys,
)
from sqlagent.identities import IdentityError, load_identity


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# History length is history_turns in config/settings/llm.yaml;
# run_agent() trims it.
conversation_history = []

# The local user and their roles. In a real deployment both come from the
# user's sign-in (identity-provider groups -> roles, see group_roles in
# config/databases/<database>/security.yaml); here the user is
# config/settings/repl.yaml (SQLAGENT_USER overrides) and the roles are
# SQLAGENT_ROLES, else the database profile's repl_roles.
#
# SQLAGENT_IDENTITY (.\run.ps1 -local -identity steven) signs in as one of the
# database's local identities instead (config/idp/<idp>.yaml, DEMO ONLY):
# its groups and attributes, and so its row scope.


# Typing one of these on its own ends the REPL. The whole input must be
# the word (case and trailing punctuation ignored), so "who is on leave?"
# is still a question.
EXIT_WORDS = {"quit", "exit", "leave", "bye", ":quit", ":exit", ":q"}


def is_exit(text):
    return text.strip().rstrip(".!?").strip().lower() in EXIT_WORDS


def local_identity(profile):
    """
    (name, groups, attributes) for SQLAGENT_IDENTITY, or None.

    DEMO ONLY: a real deployment takes the user's groups and attributes
    (employee_id) from sign-in - the identity provider's token - not from
    config/idp/. This stands in for that so row scope can be tried
    from the REPL.
    """
    name = os.environ.get("SQLAGENT_IDENTITY", "").strip()
    if not name:
        return None
    _, identity = load_identity(profile, name)
    return name.lower(), identity.groups, identity.attributes


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
    print(f"        Ollama {active_engine().label} Agent")
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
    # Configuration errors stop here, before the database is touched.
    try:
        local_user = get_settings().repl.user
        profile = active_database()
        policy = load_security_policy()
        semantic = load_semantic_model()
    except (DatabaseConfigError, SecurityPolicyError, SemanticModelError) as ex:
        print(f"Configuration error: {ex}")
        sys.exit(1)

    print_banner()

    try:
        identity = local_identity(profile)
    except IdentityError as ex:
        print(f"Configuration error: {ex}")
        sys.exit(1)

    try:
        tables = list_tables(get_connection)
        if identity:
            name, groups, attributes = identity
            print(f"[security] Signed in as local identity '{name}' "
                  f"(groups: {', '.join(groups) or 'none'})")
            security = policy.build_context(
                name, set(), tables, groups=groups, attributes=attributes,
                read_hierarchy=read_hierarchy, read_foreign_keys=read_foreign_keys)
        else:
            security = policy.build_context(
                local_user, local_roles(profile), tables)
        catalog = SchemaCatalog(get_connection, security, semantic=semantic)
        catalog.refresh()
    except SecurityPolicyError as ex:
        print(f"Configuration error: {ex}")
        sys.exit(1)
    except EmptyCatalogError as ex:
        print(f"Startup stopped: {ex}")
        sys.exit(1)
    except Exception as ex:
        print(f"Unable to connect to {active_engine().label}.")
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

        if is_exit(question):
            break

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
            # e.g. Ollama unreachable or too slow (see the timeouts in
            # config/settings/llm.yaml). Report it and keep the REPL going.
            print(f"\n[error] {type(ex).__name__}: {ex}")
            print("\n[answer] Something went wrong answering that question. "
                  "Please try again.")

    print("\nGoodbye.")


if __name__ == "__main__":
    main()
