# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Database profiles: which database the agent runs against, and where
# that database's configuration lives (config/settings/databases.yaml).
#
# One name selects everything that belongs to a database, so switching
# is one setting rather than five that must agree:
#
#   engine            the database product (postgresql); see
#                     sqlagent/execution/engines/
#   default_schema    schema for a bare table name (the engine's default,
#                     e.g. public, unless set)
#   connection        host, port, database, user; password_env names the
#                     environment variable holding the password (a
#                     literal password in the file is rejected)
#   security_file     config/<name>/security.yaml unless set
#   semantic_path     config/<name>/semantic/ unless set
#   repl_roles        roles for the local REPL (main.py)
#   demo_roles        roles for every anonymous visitor (api.py)
#   identity          how the agent names the database in prompts and
#                     messages, and its example questions
#
# The active database is SQLAGENT_DATABASE, else the file's "default".
# Fail closed: a missing or invalid file, or an unknown name, raises
# DatabaseConfigError and startup stops. The connection is read from the
# profile only; PG_HOST / PG_DATABASE etc. are NOT consulted, so a value
# left over in a PowerShell window can't connect one database's security
# policy to another database.

import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from sqlagent.config_files import (
    CONFIG_DIR,
    ConfigFileError,
    format_validation_error,
    load_yaml,
)
from sqlagent.execution.engines import get_engine
from sqlagent.settings import reject_secret_keys, settings_dir


DATABASES_FILE = CONFIG_DIR / "settings" / "databases.yaml"


class DatabaseConfigError(ConfigFileError):
    """databases.yaml is missing or invalid, or names no such database."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# Connection settings only SQL Server understands.
_SQLSERVER_ONLY = ("driver", "encrypt", "trust_server_certificate")


class Connection(_Strict):
    # Server name; for SQL Server it may include an instance
    # (BRAD-Z640\SQLEXPRESS).
    host: str = "localhost"
    # Unset: the engine's default (5432 for PostgreSQL; for SQL Server the
    # default instance's port, or the named instance's via SQL Browser).
    port: int | None = Field(None, ge=1, le=65535)
    database: str = Field(..., min_length=1)
    user: str = Field(..., min_length=1)
    # The environment variable holding the password.
    password_env: str = Field("PG_PASSWORD", min_length=1)
    # SQL Server only: the ODBC driver (default: ODBC Driver 18 for SQL
    # Server), encryption (default on) and whether to trust a self-signed
    # server certificate (default no; yes for a local development server).
    driver: str | None = Field(None, min_length=1)
    encrypt: bool | None = None
    trust_server_certificate: bool | None = None


class SqlExample(_Strict):
    """A worked example for the SQL generation prompt."""
    question: str = Field(..., min_length=1)
    sql: str = Field(..., min_length=1)
    note: str | None = None


class Identity(_Strict):
    """How the agent talks about the database. Never affects access."""
    # Used in the LLM prompt and in user-facing messages.
    display_name: str | None = None
    # What users call the company/database ("what does Northwind have?").
    # Matched in overview questions; the LLM is told never to filter on them.
    names: list[str] = Field(default_factory=list)
    # Completes "<display_name> is ..." in the overview message.
    about: str = ""
    # Offered when a question is too vague or off topic.
    example_questions: list[str] = Field(default_factory=list)
    # Worked examples for the LLM, in this database's own table and column
    # names and SQL dialect. Shown after the generic examples (writes,
    # small talk, vague questions), which need no SQL.
    sql_examples: list[SqlExample] = Field(default_factory=list)


class DatabaseSpec(_Strict):
    description: str = ""
    engine: Literal["postgresql", "sqlserver"] = "postgresql"
    default_schema: str | None = Field(None, min_length=1)
    connection: Connection
    identity: Identity = Field(default_factory=Identity)
    security_file: Path | None = None
    semantic_path: Path | None = None
    repl_roles: list[str] = Field(..., min_length=1)
    demo_roles: list[str] = Field(..., min_length=1)

    @model_validator(mode="after")
    def _engine_options(self):
        if self.engine != "sqlserver":
            used = [k for k in _SQLSERVER_ONLY
                    if getattr(self.connection, k) is not None]
            if used:
                raise ValueError(
                    f"connection.{', '.join(used)}: only for engine: sqlserver")
        return self


class DatabasesFile(_Strict):
    version: Literal[1] = 1
    default: str
    databases: dict[str, DatabaseSpec] = Field(..., min_length=1)

    @model_validator(mode="after")
    def _check(self):
        names = [n.lower() for n in self.databases]
        if len(names) != len(set(names)):
            raise ValueError("two databases differ only by case")
        if self.default.lower() not in names:
            raise ValueError(f"default '{self.default}' is not in databases")
        return self


class DatabaseProfile:
    """One database's settings, with paths resolved."""

    def __init__(self, name, spec, config_dir=CONFIG_DIR):
        self.name = name
        self.description = spec.description
        self.engine = spec.engine
        engine = get_engine(spec.engine)
        self.default_schema = spec.default_schema or engine.default_schema
        self.connection = spec.connection
        if self.connection.port is None and engine.default_port:
            self.connection = self.connection.model_copy(
                update={"port": engine.default_port})
        self.security_file = _resolve(
            spec.security_file, config_dir / name / "security.yaml")
        self.semantic_path = _resolve(
            spec.semantic_path, config_dir / name / "semantic")
        self.repl_roles = {r.strip() for r in spec.repl_roles if r.strip()}
        self.demo_roles = {r.strip() for r in spec.demo_roles if r.strip()}
        ident = spec.identity
        self.display_name = (ident.display_name or name).strip()
        names = [n.strip() for n in ident.names if n.strip()]
        self.names = names or [self.display_name]
        self.about = ident.about.strip()
        self.example_questions = [q.strip() for q in ident.example_questions if q.strip()]
        self.sql_examples = list(ident.sql_examples)

    def password(self):
        return os.environ.get(self.connection.password_env)

    def describe(self):
        c = self.connection
        found = "set" if self.password() else "NOT SET"
        port = f":{c.port}" if c.port else ""
        return (f"{self.name}: {self.engine} {c.user}@{c.host}{port}/{c.database} "
                f"(password from ${c.password_env}: {found}; "
                f"security {self.security_file}, semantic {self.semantic_path})")


def _resolve(path, default):
    """A relative path in the file is relative to the project root."""
    if path is None:
        return default
    path = Path(path)
    return path if path.is_absolute() else CONFIG_DIR.parent / path


def load_database_profile(name=None, path=None):
    """
    The profile for database `name` (default: SQLAGENT_DATABASE, then the
    file's "default"). Names are case-insensitive.
    """
    path = Path(path or settings_dir() / "databases.yaml")
    if not path.is_file():
        raise DatabaseConfigError(f"database list not found: {path}")
    try:
        data = load_yaml(path)
        reject_secret_keys(data)
    except ConfigFileError as ex:
        raise DatabaseConfigError(str(ex)) from ex
    except ValueError as ex:
        raise DatabaseConfigError(f"{path}: {ex}") from ex
    try:
        parsed = DatabasesFile.model_validate(data)
    except ValidationError as ex:
        raise DatabaseConfigError(format_validation_error(path, ex)) from ex

    wanted = (name or os.environ.get("SQLAGENT_DATABASE") or parsed.default).strip()
    by_name = {n.lower(): (n, spec) for n, spec in parsed.databases.items()}
    if wanted.lower() not in by_name:
        raise DatabaseConfigError(
            f"{path}: no database named '{wanted}' "
            f"(known: {', '.join(sorted(parsed.databases))})")
    real_name, spec = by_name[wanted.lower()]
    return DatabaseProfile(real_name.lower(), spec)


@lru_cache(maxsize=1)
def active_database():
    """The database this process runs against, read once and printed."""
    profile = load_database_profile()
    print(f"[database] {profile.describe()}")
    return profile
