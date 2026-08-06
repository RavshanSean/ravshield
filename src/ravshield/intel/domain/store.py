from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from ravshield.enums import Severity
from ravshield.intel.domain.normalize import normalize_domain


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

    first_seen: datetime = field(
        default_factory=lambda: datetime.now(UTC)
    )

    last_seen: datetime = field(
        default_factory=lambda: datetime.now(UTC)
    )

    def __post_init__(self) -> None:
        self.domain = normalize_domain(self.domain)

        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                "Domain confidence must be between 0.0 and 1.0."
            )

        self.source = self.source.strip() or "ravshield"


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

    def all(self) -> list[DomainReputationRecord]:
        return list(self._records.values())

    def __len__(self) -> int:
        return len(self._records)