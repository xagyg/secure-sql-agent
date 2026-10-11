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
