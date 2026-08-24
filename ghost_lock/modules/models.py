"""Общие модели данных ghost-lock.

    Shared data models for ghost-lock.
    """

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class Finding:
    ioc_type: str
    value: str
    weight: int
    source: str
    location: str
    context: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
