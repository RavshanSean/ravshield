from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from ravshield.enums import Severity
from ravshield.intel.lifecycle import validate_lifecycle_fields


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
    source_confidence: float = 1.0
    expires_at: datetime | None = None

    first_seen: datetime = field(
        default_factory=lambda: datetime.now(UTC)
    )

    last_seen: datetime = field(
        default_factory=lambda: datetime.now(UTC)
    )

    def __post_init__(self) -> None:
        (
            self.confidence,
            self.source_confidence,
            self.source,
        ) = validate_lifecycle_fields(
            confidence=self.confidence,
            source_confidence=self.source_confidence,
            source=self.source,
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

    def purge_expired(
        self,
        *,
        now: datetime | None = None,
    ) -> int:
        from ravshield.intel.lifecycle import is_expired

        expired_keys = [
            key
            for key, record in self._records.items()
            if is_expired(record.expires_at, now=now)
        ]

        for key in expired_keys:
            del self._records[key]

        return len(expired_keys)

    def __len__(self) -> int:
        return len(self._records)
