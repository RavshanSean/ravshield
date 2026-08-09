from __future__ import annotations

from dataclasses import dataclass

from ravshield.enums import Severity
from ravshield.intel.domain.normalize import normalize_domain
from ravshield.intel.domain.store import (
    DomainReputationRecord,
    DomainReputationStore,
)
from ravshield.intel.domain.validator import validate_domain
from ravshield.intel.lifecycle import (
    effective_confidence,
    is_expired,
)


@dataclass(slots=True)
class DomainReputationResult:
    """
    Result returned after checking a domain's reputation.
    """

    domain: str
    known: bool
    malicious: bool
    severity: Severity
    confidence: float
    tags: set[str]
    source: str | None = None
    source_confidence: float | None = None
    expired: bool = False


class DomainReputationService:
    """
    Validate, normalize, store, and retrieve domain reputation.
    """

    def __init__(
        self,
        store: DomainReputationStore | None = None,
    ) -> None:
        self.store = store or DomainReputationStore()

    def check(
        self,
        domain: str,
    ) -> DomainReputationResult:
        """
        Check whether a domain exists in reputation intelligence.
        """

        if not validate_domain(domain):
            raise ValueError("Invalid domain.")

        normalized_domain = normalize_domain(domain)
        record = self.store.get(normalized_domain)

        if record is None:
            return DomainReputationResult(
                domain=normalized_domain,
                known=False,
                malicious=False,
                severity=Severity.INFO,
                confidence=0.0,
                tags=set(),
                source=None,
            )

        if is_expired(record.expires_at):
            return DomainReputationResult(
                domain=normalized_domain,
                known=False,
                malicious=False,
                severity=Severity.INFO,
                confidence=0.0,
                tags=set(),
                source=record.source,
                source_confidence=record.source_confidence,
                expired=True,
            )

        return DomainReputationResult(
            domain=record.domain,
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
        record: DomainReputationRecord,
    ) -> None:
        """
        Validate and store a domain reputation record.
        """

        if not validate_domain(record.domain):
            raise ValueError("Invalid domain reputation record.")

        self.store.add(record)
