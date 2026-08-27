"""Common contracts implemented by operational data collectors."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol


@dataclass
class CollectionResult:
    events: list[Any] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class Collector(Protocol):
    name: str

    async def collect(self, start: datetime, end: datetime) -> CollectionResult:
        """Collect an inclusive time window and report its completeness."""
