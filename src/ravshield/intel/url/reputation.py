from __future__ import annotations

from dataclasses import dataclass

from ravshield.models import Severity

from .normalize import normalize_url
from .store import (
    URLReputationRecord,
    URLReputationStore,
)
from .validator import validate_url


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

        return URLReputationResult(
            url=record.url,
            known=True,
            malicious=record.malicious,
            severity=record.severity,
            confidence=record.confidence,
            tags=set(record.tags),
            source=record.source,
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
            first_seen=record.first_seen,
            last_seen=record.last_seen,
        )

        self.store.add(normalized_record)