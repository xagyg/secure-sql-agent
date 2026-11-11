# Copyright (c) 2026 Brad Long
# Author: Brad Long
#
# Database engines (see base.py). The active database's engine is named by
# "engine:" in config/settings/databases.yaml.

from sqlagent.execution.engines.base import Engine
from sqlagent.execution.engines.postgres import PostgresEngine
from sqlagent.execution.engines.sqlserver import SqlServerEngine


ENGINES = {
    engine.name: engine
    for engine in (PostgresEngine(), SqlServerEngine())
}


def get_engine(name):
    try:
        return ENGINES[name]
    except KeyError:
        raise ValueError(
            f"unknown database engine '{name}' "
            f"(known: {', '.join(sorted(ENGINES))})") from None


def active_engine():
    """The engine of the database this process runs against."""
    from sqlagent.databases import active_database
    return get_engine(active_database().engine)


def active_dialect():
    """The sqlglot dialect of the active database's engine."""
    return active_engine().dialect


__all__ = ["Engine", "ENGINES", "active_dialect", "active_engine", "get_engine"]
