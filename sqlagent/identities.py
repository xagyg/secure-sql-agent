# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Local identities: stand-ins for sign-in, for the REPL and the row-scope
# checks only - DEMO ONLY (config/idp/<idp>.yaml).
#
# In a deployment the identity provider supplies who the user is, their
# groups and attributes (an employee ID). Locally there is no sign-in, so
# config/idp/ holds one file per organisation, as an identity provider
# would: northwind.yaml for the Northwind company, used by both the
# PostgreSQL and SQL Server copies of its database. A database picks its
# file with idp: in config/settings/databases.yaml (default: its own
# name). Each file names a few people to test as:
#
#     identities:
#       steven: {groups: [Sales-Team], attributes: {employee_id: 5}}
#
# and SQLAGENT_IDENTITY (.\run.ps1 -local -identity steven) picks one. The API
# never reads it. Like every config file it holds no secrets.

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from sqlagent.config_files import ConfigFileError, format_validation_error, load_yaml
from sqlagent.settings import reject_secret_keys


class IdentityError(ConfigFileError):
    """The identities file is missing or invalid, or names no such person."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LocalIdentity(_Strict):
    description: str | None = None
    groups: list[str] = Field(default_factory=list)
    attributes: dict[str, int | str] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _no_booleans(cls, data):
        # On the raw YAML: true would otherwise become the number 1.
        attributes = data.get("attributes") if isinstance(data, dict) else None
        if isinstance(attributes, dict):
            for key, value in attributes.items():
                if isinstance(value, bool):
                    raise ValueError(f"attribute {key}: true/false is not a value")
        return data


class IdentitiesFile(_Strict):
    version: Literal[1] = 1
    identities: dict[str, LocalIdentity] = Field(..., min_length=1)


def identities_file(profile):
    """Where a database's local identities live: config/idp/<idp>.yaml."""
    return Path(profile.idp_file)


def load_identities(path):
    """{name (lower case): LocalIdentity}."""
    path = Path(path)
    if not path.is_file():
        raise IdentityError(f"no local identities file: {path}")
    try:
        data = load_yaml(path)
        reject_secret_keys(data)
        parsed = IdentitiesFile.model_validate(data)
    except ConfigFileError as ex:
        raise IdentityError(str(ex)) from ex
    except ValidationError as ex:
        raise IdentityError(format_validation_error(path, ex)) from ex
    except ValueError as ex:
        raise IdentityError(f"{path}: {ex}") from ex
    return {name.lower(): ident for name, ident in parsed.identities.items()}


def load_identity(profile, name):
    """(name, LocalIdentity) for `name` in the database's identities file."""
    path = identities_file(profile)
    identities = load_identities(path)
    found = identities.get(name.strip().lower())
    if found is None:
        raise IdentityError(
            f"{path}: no identity named '{name}' "
            f"(known: {', '.join(sorted(identities))})")
    return name.strip().lower(), found
