from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, UTC

from ravshield.models import Severity


@dataclass(slots=True)
class URLReputationRecord:
    """
    Stores intelligence about a known URL.
    """

    url: str
    malicious: bool
    severity: Severity
    confidence: float

    tags: set[str] = field(default_factory=set)

    source: str = "ravshield"

    first_seen: datetime = field(
        default_factory=lambda: datetime.now(UTC)
    )

    last_seen: datetime = field(
        default_factory=lambda: datetime.now(UTC)
    )


class URLReputationStore:
    """
    Simple in-memory URL reputation database.
    """

    def __init__(self) -> None:
        self._records: dict[str, URLReputationRecord] = {}

    def add(
        self,
        record: URLReputationRecord,
    ) -> None:
        self._records[record.url] = record

    def get(
        self,
        url: str,
    ) -> URLReputationRecord | None:
        return self._records.get(url)

    def exists(
        self,
        url: str,
    ) -> bool:
        return url in self._records

    def remove(
        self,
        url: str,
    ) -> None:
        self._records.pop(url, None)

    def clear(self) -> None:
        self._records.clear()

    def __len__(self) -> int:
        return len(self._records)