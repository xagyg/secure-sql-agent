# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Security policy: who may see what, kept in YAML separately from the semantic
# model (config/databases/<database>/security.yaml for the active database in
# config/settings/databases.yaml, or SQLAGENT_SECURITY_FILE). One file per
# database.
#
#   roles        Per role: the tables/views it may query (allow), any it
#                may not even though a wildcard matched (deny), and the
#                columns it may not see (deny_columns). A role may extend
#                another (extends:), inheriting all of that - see below.
#   group_roles  Identity-provider group -> roles. Who is in which group
#                comes from the identity provider at sign-in (the IBAAM
#                side), never from this file.
#   scopes       Row scope dimensions (territory, salesperson, ...): how
#                each restricts each table - by a column, via a related
#                table, or not at all (unscoped). See row_scope.py.
#   group_grants Identity-provider group -> grants. A grant is a role (which
#                tables and columns) plus a scope (which rows): fixed
#                values, "unrestricted", or relative to the user (self,
#                team, reports). A role marked "scope: required" can only
#                be granted with a scope.
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
# Several grants with row scope: each grant is evaluated on its own and a
# row is visible under ANY grant covering its table. If those grants see
# different rows of a table, a column on it is shown only if EVERY one of
# them shows it - otherwise one grant's rows would be shown with a column
# only another grant allows. Access widens only through a grant that
# explicitly gives more; a missing or unresolvable scope gives no rows.
#
# Patterns are fnmatch patterns on "schema.table", case-insensitive, e.g.
# "erp.sales_*". A name without a schema is in "public".
#
# Inheritance (extends: <role>). The role starts as everything its parent
# has - allowed tables, denied tables, hidden columns - and its own allow,
# deny and deny_columns add to that. Adding a table or hiding more never
# widens what the parent restricts. The ONLY keys that do are:
#   undeny          tables the parent denies that this role may see
#   undeny_columns  columns the parent hides that this role may see
# Each must name something the parent actually denies or hides (exactly
# as the parent writes it), or startup stops - so a typo or a stale entry
# can't pass for a decision - and each is printed at startup as a widening.
# description and scope are each role's own; a role extending one with
# "scope: required" must say it too, so extends can't drop row scope.
# One parent per role; chains are allowed, cycles and unknown parents
# stop startup. Inheritance is resolved when the file is loaded: what the
# rest of the agent sees is each role's flattened lists.

import fnmatch
import os
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, ValidationError, model_validator

from sqlagent.config_files import (
    ConfigFileError,
    format_validation_error,
    load_yaml,
)
from sqlagent.controls.row_scope import RowScopeError, combine_filters, compile_grant
from sqlagent.controls.security_context import SecurityContext
from sqlagent.databases import DatabaseConfigError, active_database
from sqlagent.controls.security_utils import full_table_name


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
    # Another role whose tables, denied tables and hidden columns this one
    # starts from (see "Inheritance" above).
    extends: str | None = Field(None, min_length=1)
    allow: list[str] = []
    deny: list[str] = []
    deny_columns: dict[str, list[str]] = {}
    # With extends only: the parent's restrictions this role lifts.
    undeny: list[str] = []
    undeny_columns: dict[str, list[str]] = {}
    # "required": every grant of this role must say which rows (a scope,
    # or "unrestricted"); it can't be handed out through group_roles.
    scope: Literal["required"] | None = None

    @model_validator(mode="after")
    def _deny_columns_need_a_grant(self):
        if self.extends is None:
            if self.undeny or self.undeny_columns:
                raise ValueError("undeny / undeny_columns need extends: there is "
                                 "no parent restriction to lift")
            _check_deny_columns(self)
        return self


def _check_deny_columns(spec):
    for table in spec.deny_columns:
        if not any(_covers(table, allowed) for allowed in spec.allow):
            raise ValueError(
                f"deny_columns names '{table}', which this role's allow "
                "list doesn't grant - check for a typo")


def _flatten_roles(roles):
    """
    Each role with its inheritance applied: {name: RoleSpec} with flattened
    allow / deny / deny_columns, plus [widening messages] for the undenies.
    Raises ValueError for an unknown parent, a cycle, an undeny that names
    nothing the parent restricts, or a child of a scoped role that drops
    "scope: required".
    """
    by_lower = {name.lower(): name for name in roles}
    flat, widened = {}, []

    def resolve(name, chain):
        if name in flat:
            return flat[name]
        spec = roles[name]
        if spec.extends is None:
            flat[name] = spec
            return spec
        parent_key = spec.extends.strip().lower()
        if parent_key not in by_lower:
            raise ValueError(f"role '{name}' extends undefined role '{spec.extends}'")
        parent_name = by_lower[parent_key]
        if parent_name in chain:
            raise ValueError("roles extend each other in a cycle: "
                             + " -> ".join(chain + [parent_name]))
        parent = resolve(parent_name, chain + [parent_name])
        if parent.scope == "required" and spec.scope != "required":
            raise ValueError(
                f"role '{name}' extends '{parent_name}', which has scope: required; "
                "it must say scope: required too")

        deny = [d for d in parent.deny]
        for table in spec.undeny:
            matches = [d for d in deny if _norm(d) == _norm(table)]
            if not matches:
                raise ValueError(
                    f"role '{name}' undenies '{table}', which '{parent_name}' doesn't "
                    "deny (name it exactly as the parent's deny list does)")
            if any(_norm(d) == _norm(table) for d in spec.deny):
                raise ValueError(f"role '{name}' both denies and undenies '{table}'")
            deny = [d for d in deny if _norm(d) != _norm(table)]
            widened.append(f"{name} undenies table {_norm(table)}, denied by {parent_name}")

        hidden = {_norm(t): [c.strip().lower() for c in cols]
                  for t, cols in parent.deny_columns.items()}
        for table, columns in spec.undeny_columns.items():
            key = _norm(table)
            if key not in hidden:
                raise ValueError(
                    f"role '{name}' undenies columns on '{table}', where "
                    f"'{parent_name}' hides none (name the table exactly as the "
                    "parent's deny_columns does)")
            for column in columns:
                col = column.strip().lower()
                if col not in hidden[key]:
                    raise ValueError(
                        f"role '{name}' undenies column {key}.{col}, which "
                        f"'{parent_name}' doesn't hide")
                if col in [c.strip().lower() for c in spec.deny_columns.get(table, [])]:
                    raise ValueError(
                        f"role '{name}' both hides and undenies column {key}.{col}")
                hidden[key].remove(col)
                widened.append(f"{name} undenies column {key}.{col}, hidden by {parent_name}")
        for table, columns in spec.deny_columns.items():
            key = _norm(table)
            merged = hidden.setdefault(key, [])
            merged += [c.strip().lower() for c in columns if c.strip().lower() not in merged]

        allow = list(parent.allow) + [a for a in spec.allow
                                      if _norm(a) not in {_norm(p) for p in parent.allow}]
        result = spec.model_copy(update={
            "allow": allow,
            "deny": deny + [d for d in spec.deny if _norm(d) not in {_norm(x) for x in deny}],
            "deny_columns": {t: c for t, c in hidden.items() if c},
        })
        _check_deny_columns(result)
        flat[name] = result
        return result

    for name in roles:
        resolve(name, [name])
    return flat, widened


# -- row scope ---------------------------------------------------------------

RELATIVE_VALUES = ("self", "team", "reports")


class HierarchySpec(_Strict):
    """Who is below whom, for "team" and "reports": a table with each
    person's key and their parent's (manager's) key."""
    table: str = Field(..., min_length=1)
    key: str = Field(..., min_length=1)
    parent: str = Field(..., min_length=1)


class ColumnRule(_Strict):
    column: str = Field(..., min_length=1)


class ViaRule(_Strict):
    via: str = Field(..., min_length=1)
    # this table's column -> the related table's column. (Not "on": YAML
    # reads an unquoted on as true.) Optional: left out, it is taken from
    # the database's foreign key between the two tables - which must be
    # exactly one, or startup stops and asks for it (see _resolve_joins).
    # Give it when there's no foreign key, or more than one.
    join: dict[str, str] | None = Field(None, min_length=1)


class ScopeSpec(_Strict):
    description: str | None = None
    # The user attribute holding the user's own value in this dimension
    # (an employee ID), for the relative values self / team / reports.
    user_attribute: str | None = None
    hierarchy: HierarchySpec | None = None
    tables: dict[str, Literal["unscoped"] | ColumnRule | ViaRule] = Field(..., min_length=1)


class GrantSpec(_Strict):
    role: str = Field(..., min_length=1)
    # None: no row scope. "unrestricted": all rows, said explicitly.
    # Otherwise dimension -> a list of values, or self / team / reports.
    scope: Literal["unrestricted"] | dict[str, list[int | str] | Literal["self", "team", "reports"]] | None = None

    @model_validator(mode="before")
    @classmethod
    def _values(cls, data):
        # Checked on the raw YAML: a typed-in true would otherwise be
        # converted to the number 1 and grant whatever key 1 is.
        scope = data.get("scope") if isinstance(data, dict) else None
        if isinstance(scope, dict):
            if not scope:
                raise ValueError("scope is empty; say which rows, or 'unrestricted'")
            for dim, values in scope.items():
                if isinstance(values, list) and any(isinstance(v, bool) for v in values):
                    raise ValueError(f"scope {dim}: true/false is not a value")
        return data


class SecurityFile(_Strict):
    version: Literal[1] = 1
    # Required, and only "deny" is accepted: the file must say so.
    default: Literal["deny"]
    roles: dict[str, RoleSpec]
    group_roles: dict[str, list[str]] = {}
    scopes: dict[str, ScopeSpec] = {}
    group_grants: dict[str, list[GrantSpec]] = {}
    # What extends / undeny did, for the startup log (_flatten_roles).
    _inheritance: list[str] = PrivateAttr(default_factory=list)

    @model_validator(mode="after")
    def _check(self):
        names = [r.lower() for r in self.roles]
        if len(names) != len(set(names)):
            raise ValueError("two roles differ only by case")
        self.roles, widened = _flatten_roles(self.roles)
        self._inheritance = (
            [f"role {n} extends {spec.extends.strip().lower()}"
             for n, spec in self.roles.items() if spec.extends]
            + [f"WIDENS: {w}" for w in widened])
        known = set(names)
        required = {r.lower() for r, spec in self.roles.items() if spec.scope == "required"}
        for group, roles in self.group_roles.items():
            unknown = sorted({r.lower() for r in roles} - known)
            if unknown:
                raise ValueError(
                    f"group_roles '{group}' maps to undefined role(s): "
                    + ", ".join(unknown))
            scoped = sorted({r.lower() for r in roles} & required)
            if scoped:
                raise ValueError(
                    f"group_roles '{group}': role(s) {', '.join(scoped)} need a "
                    "scope - grant them through group_grants")

        dims = {d.lower(): spec for d, spec in self.scopes.items()}
        if len(dims) != len(self.scopes):
            raise ValueError("two scopes differ only by case")
        for dim, spec in dims.items():
            rules = {_norm(t): rule for t, rule in spec.tables.items()}
            for table, rule in rules.items():
                if isinstance(rule, ViaRule):
                    target = _norm(rule.via)
                    if target not in rules:
                        raise ValueError(
                            f"scopes.{dim}: {table} is scoped via {target}, "
                            "which has no rule in this scope")
                    if rules[target] == "unscoped":
                        raise ValueError(
                            f"scopes.{dim}: {table} is scoped via {target}, "
                            "which is unscoped - nothing would restrict it")
            for table in rules:          # cycles
                seen, current = {table}, rules[table]
                while isinstance(current, ViaRule):
                    nxt = _norm(current.via)
                    if nxt in seen:
                        raise ValueError(f"scopes.{dim}: 'via' rules form a cycle at {nxt}")
                    seen.add(nxt)
                    current = rules[nxt]

        for group, grants in self.group_grants.items():
            for grant in grants:
                role = grant.role.lower()
                if role not in known:
                    raise ValueError(f"group_grants '{group}': undefined role '{grant.role}'")
                if role in required and grant.scope is None:
                    raise ValueError(
                        f"group_grants '{group}': role '{grant.role}' needs a scope "
                        "(a scope, or 'unrestricted')")
                if isinstance(grant.scope, dict):
                    for dim, values in grant.scope.items():
                        spec = dims.get(dim.lower())
                        if spec is None:
                            raise ValueError(
                                f"group_grants '{group}': undefined scope '{dim}'")
                        if values in RELATIVE_VALUES and not spec.user_attribute:
                            raise ValueError(
                                f"group_grants '{group}': '{values}' needs "
                                f"scopes.{dim}.user_attribute")
                        if values in ("team", "reports") and spec.hierarchy is None:
                            raise ValueError(
                                f"group_grants '{group}': '{values}' needs "
                                f"scopes.{dim}.hierarchy")
        return self


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

class SecurityPolicy:

    def __init__(self, parsed, source="(in memory)"):
        self.source = str(source)
        self.roles = {name.lower(): spec for name, spec in parsed.roles.items()}
        # Printed so a reviewer sees what inheritance did - above all,
        # every restriction a role lifts from its parent.
        self.inheritance = list(parsed._inheritance)
        for line in self.inheritance:
            print(f"[security] {line}")
        self.group_roles = {
            group.lower(): {r.lower() for r in roles}
            for group, roles in parsed.group_roles.items()
        }
        self.group_grants = {
            group.lower(): list(grants)
            for group, grants in parsed.group_grants.items()
        }
        # dimension -> (spec, rules); rules: lower-case table ->
        # ("column", col) | ("via", parent, {col: parent_col}, parent as spelled)
        # | ("unscoped",). A via rule's join is None until _resolve_joins
        # takes it from the foreign keys.
        self.scopes = {}
        self._spelled = {}       # lower-case table -> as the policy spells it
        for dim, spec in parsed.scopes.items():
            rules = {}
            for table, rule in spec.tables.items():
                self._spelled[_norm(table)] = full_table_name(table.strip())
                if rule == "unscoped":
                    rules[_norm(table)] = ("unscoped",)
                elif isinstance(rule, ColumnRule):
                    rules[_norm(table)] = ("column", rule.column)
                else:
                    rules[_norm(table)] = ("via", _norm(rule.via),
                                           dict(rule.join) if rule.join else None,
                                           full_table_name(rule.via.strip()))
            self.scopes[dim.lower()] = (spec, rules)
        self._joins_resolved = False

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

    def build_context(self, user_id, roles, available_tables, log=True,
                      groups=(), attributes=None, read_hierarchy=None,
                      read_foreign_keys=None):
        """
        The SecurityContext for a user, resolved against `available_tables`
        (the "schema.table" names that exist; see sql_execution.list_tables).

        roles           roles held directly (no row scope), e.g. the REPL's
                        repl_roles or the demo API's demo_roles
        groups          identity-provider groups: their group_roles (no row
                        scope) and group_grants (role + scope)
        attributes      the user's attributes from sign-in, for relative
                        scope values (self / team / reports)
        read_hierarchy  (table, key, parent) -> [(key, parent), ...], for
                        team / reports
        read_foreign_keys
                        () -> [(table, [columns], referenced table,
                        [columns]), ...], for 'via' rules with no join;
                        read once, the first time a scoped grant needs it

        Raises SecurityPolicyError for an undefined role, a role that needs
        a scope granted without one, or a table a scoped role allows that
        its scope has no rule for.
        """
        attributes = attributes or {}
        grants = [(r.lower(), None) for r in roles]
        for group in groups:
            grants += [(r, None) for r in sorted(self.group_roles.get(group.lower(), ()))]
            grants += [(g.role.lower(), g.scope)
                       for g in self.group_grants.get(group.lower(), ())]

        held = {role for role, _ in grants}
        unknown = sorted(r for r in held if r not in self.roles)
        if unknown:
            raise SecurityPolicyError(
                f"{self.source}: undefined role(s) requested: {', '.join(unknown)}")

        tables = set()
        per_table = {}       # table -> [(row filter text | None, denies)] per grant
        grant_filters = []
        labels = []
        hierarchies = {}     # cache for this user: dimension -> rows

        for role, scope in sorted(grants, key=lambda g: (g[0], str(g[1]))):
            if scope is None and self.roles[role].scope == "required":
                raise SecurityPolicyError(
                    f"{self.source}: role '{role}' needs a scope; grant it "
                    "through group_grants")
            role_tables, role_denied = self.resolve_role(role, available_tables)
            tables |= role_tables

            if not isinstance(scope, dict):
                filters = {t.lower(): None for t in role_tables}
                labels.append(f"{role} ({scope or 'no row scope'})")
            else:
                self._resolve_joins(read_foreign_keys, log)
                values = {}
                for dim, value in scope.items():
                    dim = dim.lower()
                    values[dim] = self._resolve_values(
                        dim, value, attributes, read_hierarchy, hierarchies)
                    self._check_scope_size(user_id, role, dim, value, values[dim])
                    rules = self.scopes[dim][1]
                    missing = sorted(t for t in role_tables if t.lower() not in rules)
                    if missing:
                        raise SecurityPolicyError(
                            f"{self.source}: scope '{dim}' has no rule for "
                            f"{', '.join(missing)} (allowed by role '{role}'); "
                            "add a rule, or mark it unscoped")
                dimensions = {dim: self.scopes[dim][1] for dim in values}
                try:
                    filters = compile_grant(role_tables, values, dimensions)
                except RowScopeError as ex:
                    raise SecurityPolicyError(f"{self.source}: {ex}") from ex
                shown = ", ".join(f"{d} {v}" for d, v in values.items())
                labels.append(f"{role} ({shown})")
            grant_filters.append(filters)

            for table in role_tables:
                row_filter = filters[table.lower()]
                per_table.setdefault(table, []).append(
                    (None if row_filter is None else row_filter.sql(), role_denied[table]))

        denied_columns = {}
        narrowed = []
        for table, entries in per_table.items():
            denies = [d for _, d in entries]
            if len({key for key, _ in entries}) == 1:
                hidden = set.intersection(*denies)   # same rows: hidden only if every grant hides it
            else:
                hidden = set.union(*denies)          # different rows: shown only if every grant shows it
                if hidden != set.intersection(*denies):
                    narrowed.append(table)
            if hidden:
                denied_columns[table] = hidden

        context = SecurityContext(
            user_id=user_id,
            roles=held,
            tables=tables,
            denied_columns=denied_columns,
            row_filters=combine_filters(grant_filters),
            grants=labels,
        )
        if log:
            log_context(context)
            for table in sorted(narrowed):
                print(f"[security]   {table}: grants see different rows, so a "
                      "column is shown only if every grant shows it")
        return context

    def _resolve_joins(self, read_foreign_keys, log=True):
        """
        Fill in every 'via' rule that has no join from the database's
        foreign keys: the one foreign key between the table and the table
        it's scoped via, in either direction. None, or more than one, stops
        startup and asks for an explicit join - the rule never guesses.
        Done once; the joins it chose are printed so they can be reviewed.
        """
        if self._joins_resolved:
            return
        pending = [(dim, table, rule) for dim, (_, rules) in self.scopes.items()
                   for table, rule in rules.items()
                   if rule[0] == "via" and rule[2] is None]
        if pending and read_foreign_keys is None:
            dim, table, rule = pending[0]
            raise SecurityPolicyError(
                f"{self.source}: scopes.{dim}: {table} is scoped via {rule[1]} "
                "with no join, and the foreign keys can't be read here; add join:")

        foreign_keys = read_foreign_keys() if pending else []
        for dim, table, rule in pending:
            parent = rule[1]
            joins = []
            for from_table, from_cols, to_table, to_cols in foreign_keys:
                f, t = _norm(from_table), _norm(to_table)
                if f == table and t == parent:      # this table references the parent
                    join = dict(zip(from_cols, to_cols))
                elif f == parent and t == table:    # the parent references this table
                    join = dict(zip(to_cols, from_cols))
                else:
                    continue
                if join not in joins:
                    joins.append(join)
            shown = "; ".join(" AND ".join(f"{c} = {p}" for c, p in j.items()) for j in joins)
            if not joins:
                raise SecurityPolicyError(
                    f"{self.source}: scopes.{dim}: {table} is scoped via {parent}, "
                    "but no foreign key joins them; add join: {column: column}")
            if len(joins) > 1:
                raise SecurityPolicyError(
                    f"{self.source}: scopes.{dim}: {table} is scoped via {parent}, "
                    f"and more than one foreign key joins them ({shown}); "
                    "say which with join:")
            self.scopes[dim][1][table] = ("via", parent, joins[0], rule[3])
            if log:
                print(f"[security] scope {dim}: {self._spelled[table]} via {rule[3]} "
                      f"on {shown} (foreign key)")
        self._joins_resolved = True

    def _check_scope_size(self, user_id, role, dim, value, resolved):
        """
        Stop when a scope resolves to more values than query.yaml
        max_scope_values: each one is written into the SQL, once per scoped
        table, and a very long list is slow to plan and fails outright on
        SQL Server. Fails closed - no context, rather than a huge query or
        no filter.
        """
        from sqlagent.settings import get_settings
        limit = get_settings().query.max_scope_values
        if len(resolved) > limit:
            shown = value if isinstance(value, str) else "a fixed list"
            raise SecurityPolicyError(
                f"{self.source}: scope '{dim}' ({shown}) for user '{user_id}', "
                f"role '{role}', resolved to {len(resolved)} values - more than "
                f"query.max_scope_values ({limit}). Model it as a closure or "
                "entitlement table so the query carries one value (README "
                "\"Large scopes\"), or raise the limit")

    def _resolve_values(self, dim, value, attributes, read_hierarchy, cache):
        """A grant's scope values for this user: a fixed list as it is;
        self / team / reports from the user's attribute and the dimension's
        hierarchy. Unresolvable -> [] (no rows), with a warning."""
        if isinstance(value, list):
            return list(value)
        spec = self.scopes[dim][0]
        me = attributes.get(spec.user_attribute)
        if me is None:
            print(f"[security] WARNING: no '{spec.user_attribute}' attribute for "
                  f"scope {dim} ({value}) - no rows in that scope")
            return []
        if value == "self":
            return [me]
        if read_hierarchy is None:
            print(f"[security] WARNING: scope {dim} ({value}) needs the hierarchy, "
                  "which can't be read here - no rows in that scope")
            return []
        if dim not in cache:
            h = spec.hierarchy
            cache[dim] = read_hierarchy(full_table_name(h.table.strip()), h.key, h.parent)
        children = {}
        for key, parent in cache[dim]:
            children.setdefault(parent, []).append(key)
        below, queue = [], list(children.get(me, ()))
        while queue:
            key = queue.pop(0)
            if key in below or key == me:
                continue
            below.append(key)
            queue.extend(children.get(key, ()))
        return sorted(below) if value == "reports" else [me] + sorted(below)


def log_context(context):
    """Print what a SecurityContext resolved to (startup log), including
    each table's row filter, so what a user can see is reviewable."""
    roles = ", ".join(sorted(context.roles)) or "(none)"
    print(f"[security] user {context.user_id} (roles: {roles}): "
          f"{len(context.tables)} table(s)")
    if context.row_filters:
        print(f"[security] grants: {'; '.join(context.grants)}")
    try:
        from sqlagent.execution.engines import active_dialect
        dialect = active_dialect()
    except Exception:
        dialect = None
    for table in sorted(context.tables):
        denied = context.denied_columns.get(table)
        suffix = f"  [denied: {', '.join(sorted(denied))}]" if denied else ""
        row_filter = context.row_filters.get(table.lower())
        rows = f"  [rows: {row_filter.sql(dialect=dialect)}]" if row_filter is not None else ""
        print(f"[security]   {table}{suffix}{rows}")


def load_security_policy(path=None):
    """
    Load the security policy. path defaults to SQLAGENT_SECURITY_FILE,
    then the active database's security file (config/settings/databases.yaml).
    Raises SecurityPolicyError if the file is missing or invalid - there
    is no fallback.
    """
    if path is None:
        path = os.environ.get("SQLAGENT_SECURITY_FILE")
    if path is None:
        try:
            path = active_database().security_file
        except DatabaseConfigError as ex:
            raise SecurityPolicyError(str(ex)) from ex
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
