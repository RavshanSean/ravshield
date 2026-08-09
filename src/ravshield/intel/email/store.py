from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from ravshield.enums import Severity
from ravshield.intel.email.normalize import normalize_email
from ravshield.intel.lifecycle import (
    is_expired,
    validate_lifecycle_fields,
)


@dataclass(slots=True)
class EmailReputationRecord:
    """
    Stores threat intelligence about a known email address.
    """

    email: str
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
        self.email = normalize_email(self.email)

        (
            self.confidence,
            self.source_confidence,
            self.source,
        ) = validate_lifecycle_fields(
            confidence=self.confidence,
            source_confidence=self.source_confidence,
            source=self.source,
        )


class EmailReputationStore:
    """
    In-memory repository for email reputation records.
    """

    def __init__(self) -> None:
        self._records: dict[str, EmailReputationRecord] = {}

    def add(
        self,
        record: EmailReputationRecord,
    ) -> None:
        self._records[record.email] = record

    def get(
        self,
        email: str,
    ) -> EmailReputationRecord | None:
        normalized_email = normalize_email(email)

        return self._records.get(normalized_email)

    def exists(
        self,
        email: str,
    ) -> bool:
        normalized_email = normalize_email(email)

        return normalized_email in self._records

    def remove(
        self,
        email: str,
    ) -> EmailReputationRecord | None:
        normalized_email = normalize_email(email)

        return self._records.pop(
            normalized_email,
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

    def all(self) -> list[EmailReputationRecord]:
        return list(self._records.values())

    def __len__(self) -> int:
        return len(self._records)
