from __future__ import annotations

from dataclasses import dataclass

from ravshield.enums import Severity
from ravshield.intel.email.normalize import normalize_email
from ravshield.intel.email.store import (
    EmailReputationRecord,
    EmailReputationStore,
)
from ravshield.intel.email.validator import validate_email
from ravshield.intel.lifecycle import (
    effective_confidence,
    is_expired,
)


@dataclass(slots=True)
class EmailReputationResult:
    """
    Result returned after checking an email's reputation.
    """

    email: str
    known: bool
    malicious: bool
    severity: Severity
    confidence: float
    tags: set[str]
    source: str | None = None
    source_confidence: float | None = None
    expired: bool = False


class EmailReputationService:
    """
    Validate, normalize, store, and retrieve email reputation.
    """

    def __init__(
        self,
        store: EmailReputationStore | None = None,
    ) -> None:
        self.store = store or EmailReputationStore()

    def check(
        self,
        email: str,
    ) -> EmailReputationResult:
        """
        Check whether an email exists in reputation intelligence.
        """

        if not validate_email(email):
            raise ValueError("Invalid email.")

        normalized_email = normalize_email(email)
        record = self.store.get(normalized_email)

        if record is None:
            return EmailReputationResult(
                email=normalized_email,
                known=False,
                malicious=False,
                severity=Severity.INFO,
                confidence=0.0,
                tags=set(),
                source=None,
            )

        if is_expired(record.expires_at):
            return EmailReputationResult(
                email=normalized_email,
                known=False,
                malicious=False,
                severity=Severity.INFO,
                confidence=0.0,
                tags=set(),
                source=record.source,
                source_confidence=record.source_confidence,
                expired=True,
            )

        return EmailReputationResult(
            email=record.email,
            known=True,
            malicious=record.malicious,
            severity=record.severity,
            confidence=effective_confidence(
                record.confidence,
                record.source_confidence,
                expires_at=record.expires_at,
            ),
            tags=set(record.tags),
            source=record.source,
            source_confidence=record.source_confidence,
        )

    def add_record(
        self,
        record: EmailReputationRecord,
    ) -> None:
        """
        Validate and store an email reputation record.
        """

        if not validate_email(record.email):
            raise ValueError(
                "Invalid email reputation record."
            )

        self.store.add(record)
