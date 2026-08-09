from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from ravshield.enums import Severity
from ravshield.intel.domain.normalize import normalize_domain
from ravshield.intel.lifecycle import (
    is_expired,
    validate_lifecycle_fields,
)


@dataclass(slots=True)
class DomainReputationRecord:
    """
    Stores threat intelligence about a known domain.
    """

    domain: str
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
        self.domain = normalize_domain(self.domain)

        (
            self.confidence,
            self.source_confidence,
            self.source,
        ) = validate_lifecycle_fields(
            confidence=self.confidence,
            source_confidence=self.source_confidence,
            source=self.source,
        )


class DomainReputationStore:
    """
    In-memory repository for domain reputation records.
    """

    def __init__(self) -> None:
        self._records: dict[str, DomainReputationRecord] = {}

    def add(
        self,
        record: DomainReputationRecord,
    ) -> None:
        self._records[record.domain] = record

    def get(
        self,
        domain: str,
    ) -> DomainReputationRecord | None:
        normalized_domain = normalize_domain(domain)

        return self._records.get(normalized_domain)

    def exists(
        self,
        domain: str,
    ) -> bool:
        normalized_domain = normalize_domain(domain)

        return normalized_domain in self._records

    def remove(
        self,
        domain: str,
    ) -> DomainReputationRecord | None:
        normalized_domain = normalize_domain(domain)

        return self._records.pop(
            normalized_domain,
            None,
        )

    def clear(self) -> None:
        self._records.clear()

    def purge_expired(
        self,
        *,
        now: datetime | None = None,
    ) -> int:
        expired_keys = [
            key
            for key, record in self._records.items()
            if is_expired(record.expires_at, now=now)
        ]

        for key in expired_keys:
            del self._records[key]

        return len(expired_keys)

    def all(self) -> list[DomainReputationRecord]:
        return list(self._records.values())

    def __len__(self) -> int:
        return len(self._records)
