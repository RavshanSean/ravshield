from __future__ import annotations

from dataclasses import dataclass

from ravshield.enums import Severity
from ravshield.intel.ip.normalize import normalize_ip
from ravshield.intel.ip.store import (
    IPReputationRecord,
    IPReputationStore,
)
from ravshield.intel.ip.validator import validate_ip


@dataclass(slots=True)
class IPReputationResult:
    """
    Result returned after checking an IP's reputation.
    """

    ip: str
    known: bool
    malicious: bool
    severity: Severity
    confidence: float
    tags: set[str]
    source: str | None = None


class IPReputationService:
    """
    Validate, normalize, store, and retrieve IP reputation.
    """

    def __init__(
        self,
        store: IPReputationStore | None = None,
    ) -> None:
        self.store = store or IPReputationStore()

    def check(
        self,
        ip: str,
    ) -> IPReputationResult:
        """
        Check whether an IP exists in reputation intelligence.
        """

        if not validate_ip(ip):
            raise ValueError("Invalid IP address.")

        normalized_ip = normalize_ip(ip)
        record = self.store.get(normalized_ip)

        if record is None:
            return IPReputationResult(
                ip=normalized_ip,
                known=False,
                malicious=False,
                severity=Severity.INFO,
                confidence=0.0,
                tags=set(),
                source=None,
            )

        return IPReputationResult(
            ip=record.ip,
            known=True,
            malicious=record.malicious,
            severity=record.severity,
            confidence=record.confidence,
            tags=set(record.tags),
            source=record.source,
        )

    def add_record(
        self,
        record: IPReputationRecord,
    ) -> None:
        """
        Validate and store an IP reputation record.
        """

        if not validate_ip(record.ip):
            raise ValueError(
                "Invalid IP reputation record."
            )

        self.store.add(record)