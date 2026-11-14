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
#
# Batch mode runs a file of questions instead of reading the keyboard, and
# can copy everything printed to a file to check later:
#     python main.py --questions questions.txt --out results.txt
#     .\run.ps1 -questions questions.txt          (results go to .\outputs\)
# See read_questions() for the file format.

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path

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


# ---------------------------------------------------------------------------
# Batch mode
# ---------------------------------------------------------------------------

# A line of just this (or more dashes) in a questions file starts a new
# conversation: the history is cleared, so the next question isn't read
# as a follow-up.
NEW_CONVERSATION = "---"

# "1. ", "10. " or "3) " at the start of a line: list numbering, not part
# of the question. Only with a space after it, so "1.5% growth?" is kept.
LIST_NUMBER = re.compile(r"^\d+[.)](\s+|$)")


def read_questions(path):
    """
    The questions in a batch file, in order. One question per line; blank
    lines and lines starting with # are skipped; list numbering at the
    start of a line ("1. ", "10. ", "3) ") is removed; a line of --- starts
    a new conversation (returned as NEW_CONVERSATION); an exit word (quit,
    exit, ...) ends the file early. Questions are otherwise run as one
    conversation, so a line can follow up the one before it ("only those
    in Germany").
    """
    items = []
    for line in Path(path).read_text(encoding="utf-8-sig").splitlines():
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        if set(text) == {"-"} and len(text) >= 3:
            if items and items[-1] != NEW_CONVERSATION:
                items.append(NEW_CONVERSATION)
            continue
        text = LIST_NUMBER.sub("", text).strip()
        if not text:
            continue
        if is_exit(text):
            break
        items.append(text)
    while items and items[-1] == NEW_CONVERSATION:
        items.pop()
    return items


def default_results_path(questions_path, now=None):
    """questions.txt -> outputs/questions-results-20261114-1502.txt, in an
    outputs folder next to the questions file (created when needed)."""
    path = Path(questions_path)
    stamp = (now or datetime.now()).strftime("%Y%m%d-%H%M")
    return path.parent / "outputs" / f"{path.stem}-results-{stamp}.txt"


class Tee:
    """Write to the console and a file at once (batch --out)."""

    def __init__(self, *streams):
        self.streams = streams

    def write(self, text):
        for stream in self.streams:
            stream.write(text)
        return len(text)

    def flush(self):
        for stream in self.streams:
            stream.flush()


def run_batch(items, catalog, security):
    """Run each question as the REPL would, printing a header and timing
    for each, then a summary."""
    history = []
    questions = [i for i in items if i != NEW_CONVERSATION]
    failed = 0
    started = time.monotonic()
    number = 0

    for item in items:
        if item == NEW_CONVERSATION:
            history.clear()
            print("\n[batch] --- new conversation ---")
            continue
        number += 1
        print(f"\n{'=' * 70}\n[batch] Question {number} of {len(questions)}")
        print(f"\n> {item}")
        begin = time.monotonic()
        try:
            run_agent(item, catalog, history, security)
        except Exception as ex:
            failed += 1
            print(f"\n[error] {type(ex).__name__}: {ex}")
            print("\n[answer] Something went wrong answering that question.")
        print(f"\n[batch] Took {time.monotonic() - begin:.1f}s")

    print(f"\n{'=' * 70}")
    print(f"[batch] Done: {len(questions)} question(s) in "
          f"{time.monotonic() - started:.0f}s"
          + (f", {failed} failed with an error" if failed else ""))


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Secure SQL Agent REPL. With --questions, runs a file of "
                    "questions instead of reading the keyboard.")
    parser.add_argument("--questions", metavar="FILE",
                        help="run these questions (one per line) and exit")
    parser.add_argument("--out", metavar="FILE",
                        help="with --questions: also write everything printed "
                             "to this file (default: outputs/<questions>-"
                             "results-<date>-<time>.txt, in an outputs folder "
                             "next to the questions file)")
    parser.add_argument("--no-out", action="store_true",
                        help="with --questions: print to the console only")
    return parser.parse_args(argv)


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
    args = parse_args()
    if args.questions:
        try:
            items = read_questions(args.questions)
        except OSError as ex:
            print(f"Cannot read questions file: {ex}")
            sys.exit(1)
        if not items:
            print(f"No questions in {args.questions}.")
            sys.exit(1)
        if args.no_out:
            return start(items)
        out_path = Path(args.out) if args.out else default_results_path(args.questions)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as out:
            console = sys.stdout
            sys.stdout = Tee(console, out)
            try:
                print(f"[batch] {args.questions} - {datetime.now():%Y-%m-%d %H:%M}")
                start(items)
            finally:
                sys.stdout = console
        print(f"\n[batch] Results written to {out_path}")
        return
    start(None)


def start(batch_items):
    """Load everything, then run the REPL, or the batch when given one."""
    # Configuration errors stop here, before the database is touched.
    try:
        local_user = get_settings().repl.user
        profile = active_database()
        policy = load_security_policy()
        semantic = load_semantic_model()
    except (DatabaseConfigError, SecurityPolicyError, SemanticModelError) as ex:
        print(f"Configuration error: {ex}")
        sys.exit(1)

    if batch_items is None:
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

    if batch_items is not None:
        run_batch(batch_items, catalog, security)
        return

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
