# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Security policy: who may see what, kept in YAML separately from the
# semantic model (config/security/northwind.yaml by default, or
# SQLAGENT_SECURITY_FILE). One file per database.
#
#   roles        Per role: the tables/views it may query (allow), any it
#                may not even though a wildcard matched (deny), and the
#                columns it may not see (deny_columns).
#   group_roles  Identity-provider group -> roles. Who is in which group
#                comes from the identity provider at sign-in (the IBAAM
#                side), never from this file.
#
# The policy is turned into an ordinary SecurityContext ONCE, at startup
# or sign-in (build_context). Wildcards are expanded against the tables
# that actually exist and the resolved list is printed, so what a role
# can see is visible rather than inferred from patterns. Query-time
# checks (is_authorized_table etc.) only ever see that concrete list, so
# a table created later is invisible until the next restart re-reads
# the policy.
#
# Fail closed. Unlike the semantic model, which skips what it can't use,
# any problem here stops startup:
#   - a missing file, invalid YAML, a duplicate key or an unknown key;
#   - "default" other than "deny";
#   - a deny_columns entry for a table the role isn't granted (usually a
#     typo, which would leave the column visible);
#   - a group mapped to an undefined role, or asking for an undefined role.
#
# Several roles: a table is visible if ANY of the user's roles allows it
# (and doesn't deny it); a column on it is hidden only if EVERY role that
# grants the table denies that column. Each role's denies narrow that
# role's own grants; they are not a veto over other roles. (A sales role
# hides home_phone; an HR role on the same person still shows it.)
#
# Patterns are fnmatch patterns on "schema.table", case-insensitive, e.g.
# "erp.sales_*". A name without a schema is in "public".

import fnmatch
import os
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError, model_validator

from sqlagent.config_files import (
    CONFIG_DIR,
    DEFAULT_DATABASE,
    ConfigFileError,
    format_validation_error,
    load_yaml,
)
from sqlagent.controls.security_context import SecurityContext
from sqlagent.controls.security_utils import full_table_name


DEFAULT_SECURITY_FILE = CONFIG_DIR / "security" / f"{DEFAULT_DATABASE}.yaml"


class SecurityPolicyError(ConfigFileError):
    """The security policy is missing or invalid. Startup must stop."""


# ---------------------------------------------------------------------------
# File structure
# ---------------------------------------------------------------------------

class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _is_pattern(text):
    return any(ch in text for ch in "*?[")


def _norm(text):
    return full_table_name(text.strip()).lower()


def _covers(pattern_a, pattern_b):
    """True when one table pattern can match what the other names."""
    a, b = _norm(pattern_a), _norm(pattern_b)
    return a == b or fnmatch.fnmatchcase(a, b) or fnmatch.fnmatchcase(b, a)


class RoleSpec(_Strict):
    description: str | None = None
    allow: list[str] = []
    deny: list[str] = []
    deny_columns: dict[str, list[str]] = {}

    @model_validator(mode="after")
    def _deny_columns_need_a_grant(self):
        for table in self.deny_columns:
            if not any(_covers(table, allowed) for allowed in self.allow):
                raise ValueError(
                    f"deny_columns names '{table}', which this role's allow "
                    "list doesn't grant - check for a typo")
        return self


class SecurityFile(_Strict):
    version: Literal[1] = 1
    # Required, and only "deny" is accepted: the file must say so.
    default: Literal["deny"]
    roles: dict[str, RoleSpec]
    group_roles: dict[str, list[str]] = {}

    @model_validator(mode="after")
    def _check(self):
        names = [r.lower() for r in self.roles]
        if len(names) != len(set(names)):
            raise ValueError("two roles differ only by case")
        known = set(names)
        for group, roles in self.group_roles.items():
            unknown = sorted({r.lower() for r in roles} - known)
            if unknown:
                raise ValueError(
                    f"group_roles '{group}' maps to undefined role(s): "
                    + ", ".join(unknown))
        return self


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

class SecurityPolicy:

    def __init__(self, parsed, source="(in memory)"):
        self.source = str(source)
        self.roles = {name.lower(): spec for name, spec in parsed.roles.items()}
        self.group_roles = {
            group.lower(): {r.lower() for r in roles}
            for group, roles in parsed.group_roles.items()
        }

    @classmethod
    def from_dict(cls, data, source="(in memory)"):
        try:
            parsed = SecurityFile.model_validate(data)
        except ValidationError as ex:
            raise SecurityPolicyError(format_validation_error(source, ex)) from ex
        return cls(parsed, source)

    # -- identity --------------------------------------------------------

    def roles_for_groups(self, groups):
        """
        The roles for a user's identity-provider groups. Groups with no
        mapping are ignored (most of a user's groups have nothing to do
        with this application).
        """
        roles = set()
        for group in groups:
            roles |= self.group_roles.get(group.lower(), set())
        return roles

    # -- resolution ------------------------------------------------------

    def resolve_role(self, role, available_tables):
        """
        (tables, denied_columns) for one role against the tables that
        exist: allow patterns, minus deny patterns, with that role's
        column denials for each granted table.
        """
        spec = self.roles.get(role.lower())
        if spec is None:
            raise SecurityPolicyError(
                f"{self.source}: role '{role}' is not defined")

        by_lower = {t.lower(): t for t in available_tables}
        allow = [_norm(p) for p in spec.allow]
        deny = [_norm(p) for p in spec.deny]

        for pattern in allow:
            if not _is_pattern(pattern) and pattern not in by_lower:
                print(f"[security] role {role}: allowed table '{pattern}' "
                      "not found in the database - skipped")

        tables = {
            actual for lower, actual in by_lower.items()
            if any(fnmatch.fnmatchcase(lower, p) for p in allow)
            and not any(fnmatch.fnmatchcase(lower, p) for p in deny)
        }

        denied = {}
        for table in tables:
            columns = set()
            for pattern, names in spec.deny_columns.items():
                if fnmatch.fnmatchcase(table.lower(), _norm(pattern)):
                    columns |= {n.strip().lower() for n in names if n.strip()}
            denied[table] = columns

        return tables, denied

    def build_context(self, user_id, roles, available_tables, log=True):
        """
        The SecurityContext for a user holding `roles`, resolved against
        `available_tables` (the "schema.table" names that exist; see
        sql_execution.list_tables). Raises SecurityPolicyError for an
        undefined role.
        """
        roles = {r.lower() for r in roles}
        unknown = sorted(r for r in roles if r not in self.roles)
        if unknown:
            raise SecurityPolicyError(
                f"{self.source}: undefined role(s) requested: {', '.join(unknown)}")

        tables = set()
        per_table_denies = {}   # table -> list of each granting role's denies

        for role in sorted(roles):
            role_tables, role_denied = self.resolve_role(role, available_tables)
            tables |= role_tables
            for table in role_tables:
                per_table_denies.setdefault(table, []).append(role_denied[table])

        # Hidden only if every granting role hides it.
        denied_columns = {}
        for table, denies in per_table_denies.items():
            common = set.intersection(*denies) if denies else set()
            if common:
                denied_columns[table] = common

        context = SecurityContext(
            user_id=user_id,
            roles=set(roles),
            tables=tables,
            denied_columns=denied_columns,
        )
        if log:
            log_context(context)
        return context


def log_context(context):
    """Print what a SecurityContext resolved to (startup log)."""
    roles = ", ".join(sorted(context.roles)) or "(none)"
    print(f"[security] user {context.user_id} (roles: {roles}): "
          f"{len(context.tables)} table(s)")
    for table in sorted(context.tables):
        denied = context.denied_columns.get(table)
        suffix = f"  [denied: {', '.join(sorted(denied))}]" if denied else ""
        print(f"[security]   {table}{suffix}")


def load_security_policy(path=None):
    """
    Load the security policy. path defaults to SQLAGENT_SECURITY_FILE,
    then config/security/northwind.yaml. Raises SecurityPolicyError if the file is
    missing or invalid - there is no fallback.
    """
    if path is None:
        path = os.environ.get("SQLAGENT_SECURITY_FILE") or DEFAULT_SECURITY_FILE
    path = Path(path)

    if not path.is_file():
        raise SecurityPolicyError(f"security policy not found: {path}")

    try:
        data = load_yaml(path)
    except ConfigFileError as ex:
        raise SecurityPolicyError(str(ex)) from ex

    policy = SecurityPolicy.from_dict(data, source=path)
    print(f"[security] Loaded {path}: {len(policy.roles)} role(s), "
          f"{len(policy.group_roles)} group mapping(s)")
    return policy
