# Copyright (c) 2026 Brad Long
# Author: Brad Long

from dataclasses import dataclass, field


@dataclass
class SecurityContext:
    user_id: str

    roles: set[str] = field(default_factory=set)

    tables: set[str] = field(default_factory=set)

    denied_columns: dict[str, set[str]] = field(
        default_factory=dict
    )

    # Row scope (controls/row_scope.py): lower-case "schema.table" -> the
    # filter its rows must pass. Tables not listed are visible in full.
    row_filters: dict = field(default_factory=dict)

    # The user's grants, for the log: "role (scope)".
    grants: list[str] = field(default_factory=list)
