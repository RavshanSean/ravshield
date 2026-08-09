from __future__ import annotations

from dataclasses import dataclass

from ravshield.enums import Severity
from ravshield.intel.lifecycle import (
    effective_confidence,
    is_expired,
)
from ravshield.intel.url.normalize import normalize_url
from ravshield.intel.url.store import (
    URLReputationRecord,
    URLReputationStore,
)
from ravshield.intel.url.validator import validate_url


@dataclass(slots=True)
class URLReputationResult:
    """
    Result returned after checking URL reputation.
    """

    url: str
    known: bool
    malicious: bool
    severity: Severity
    confidence: float
    tags: set[str]
    source: str | None = None
    source_confidence: float | None = None
    expired: bool = False


class URLReputationService:
    """
    Checks URL reputation using a reputation store.
    """

    def __init__(
        self,
        store: URLReputationStore | None = None,
    ) -> None:
        self.store = store or URLReputationStore()

    def check(
        self,
        url: str,
    ) -> URLReputationResult:
        """
        Validate, normalize, and look up a URL.
        """

        validate_url(url)

        normalized_url = normalize_url(url)

        record = self.store.get(normalized_url)

        if record is None:
            return URLReputationResult(
                url=normalized_url,
                known=False,
                malicious=False,
                severity=Severity.INFO,
                confidence=0.0,
                tags=set(),
                source=None,
            )

        if is_expired(record.expires_at):
            return URLReputationResult(
                url=normalized_url,
                known=False,
                malicious=False,
                severity=Severity.INFO,
                confidence=0.0,
                tags=set(),
                source=record.source,
                source_confidence=record.source_confidence,
                expired=True,
            )

        return URLReputationResult(
            url=record.url,
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
        record: URLReputationRecord,
    ) -> None:
        """
        Normalize and validate a record before storing it.
        """

        validate_url(record.url)

        normalized_url = normalize_url(record.url)

        normalized_record = URLReputationRecord(
            url=normalized_url,
            malicious=record.malicious,
            severity=record.severity,
            confidence=record.confidence,
            tags=set(record.tags),
            source=record.source,
            source_confidence=record.source_confidence,
            expires_at=record.expires_at,
            first_seen=record.first_seen,
            last_seen=record.last_seen,
        )

        self.store.add(normalized_record)
