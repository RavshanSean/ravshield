from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from ravshield.enums import Severity
from ravshield.intel.ip.normalize import normalize_ip
from ravshield.intel.lifecycle import (
    is_expired,
    validate_lifecycle_fields,
)


@dataclass(slots=True)
class IPReputationRecord:
    """
    Stores threat intelligence about a known IP address.
    """

    ip: str
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
        self.ip = normalize_ip(self.ip)

        (
            self.confidence,
            self.source_confidence,
            self.source,
        ) = validate_lifecycle_fields(
            confidence=self.confidence,
            source_confidence=self.source_confidence,
            source=self.source,
        )


class IPReputationStore:
    """
    In-memory repository for IP reputation records.
    """

    def __init__(self) -> None:
        self._records: dict[str, IPReputationRecord] = {}

    def add(
        self,
        record: IPReputationRecord,
    ) -> None:
        self._records[record.ip] = record

    def get(
        self,
        ip: str,
    ) -> IPReputationRecord | None:
        normalized_ip = normalize_ip(ip)

        return self._records.get(normalized_ip)

    def exists(
        self,
        ip: str,
    ) -> bool:
        normalized_ip = normalize_ip(ip)

        return normalized_ip in self._records

    def remove(
        self,
        ip: str,
    ) -> IPReputationRecord | None:
        normalized_ip = normalize_ip(ip)

        return self._records.pop(
            normalized_ip,
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

    def all(self) -> list[IPReputationRecord]:
        return list(self._records.values())

    def __len__(self) -> int:
        return len(self._records)
