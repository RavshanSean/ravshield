from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from ravshield.enums import Severity
from ravshield.intel.ip.normalize import normalize_ip


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

    first_seen: datetime = field(
        default_factory=lambda: datetime.now(UTC)
    )

    last_seen: datetime = field(
        default_factory=lambda: datetime.now(UTC)
    )

    def __post_init__(self) -> None:
        self.ip = normalize_ip(self.ip)

        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                "IP confidence must be between 0.0 and 1.0."
            )

        self.source = self.source.strip() or "ravshield"


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

    def all(self) -> list[IPReputationRecord]:
        return list(self._records.values())

    def __len__(self) -> int:
        return len(self._records)