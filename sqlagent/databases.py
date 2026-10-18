# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Database profiles: which database the agent runs against, and where
# that database's configuration lives (config/databases.yaml).
#
# One name selects everything that belongs to a database, so switching
# is one setting rather than five that must agree:
#
#   connection        host, port, database, user (password from the
#                     environment, never the file)
#   security_file     config/security/<name>.yaml unless set
#   semantic_path     config/semantic/<name>/ unless set
#   repl_roles        roles for the local REPL (main.py)
#   demo_roles        roles for every anonymous visitor (api.py)
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


DATABASES_FILE = CONFIG_DIR / "databases.yaml"


class DatabaseConfigError(ConfigFileError):
    """config/databases.yaml is missing or invalid, or names no such database."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Connection(_Strict):
    host: str = "localhost"
    port: int = Field(5432, ge=1, le=65535)
    database: str = Field(..., min_length=1)
    user: str = Field(..., min_length=1)
    # The environment variable holding the password.
    password_env: str = Field("PG_PASSWORD", min_length=1)


class DatabaseSpec(_Strict):
    description: str = ""
    connection: Connection
    security_file: Path | None = None
    semantic_path: Path | None = None
    repl_roles: list[str] = Field(..., min_length=1)
    demo_roles: list[str] = Field(..., min_length=1)


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
        self.connection = spec.connection
        self.security_file = _resolve(
            spec.security_file, config_dir / "security" / f"{name}.yaml")
        self.semantic_path = _resolve(
            spec.semantic_path, config_dir / "semantic" / name)
        self.repl_roles = {r.strip() for r in spec.repl_roles if r.strip()}
        self.demo_roles = {r.strip() for r in spec.demo_roles if r.strip()}

    def password(self):
        return os.environ.get(self.connection.password_env)

    def describe(self):
        c = self.connection
        return (f"{self.name}: {c.user}@{c.host}:{c.port}/{c.database} "
                f"(security {self.security_file}, semantic {self.semantic_path})")


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
    path = Path(path or DATABASES_FILE)
    if not path.is_file():
        raise DatabaseConfigError(f"database list not found: {path}")
    try:
        data = load_yaml(path)
    except ConfigFileError as ex:
        raise DatabaseConfigError(str(ex)) from ex
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
