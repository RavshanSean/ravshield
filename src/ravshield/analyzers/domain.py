from __future__ import annotations

from ravshield.analyzers.base import BaseAnalyzer
from ravshield.intel.domain import DomainReputationService
from ravshield.models import DetectionFinding


class DomainReputationAnalyzer(BaseAnalyzer):
    """
    Analyze domains using RavShield reputation intelligence.
    """

    name = "domain_reputation"

    def __init__(
        self,
        reputation_service: DomainReputationService | None = None,
    ) -> None:
        self.reputation_service = (
            reputation_service or DomainReputationService()
        )

    def analyze(
        self,
        target: str,
    ) -> list[DetectionFinding]:
        """
        Check domain reputation and convert the result into findings.
        """

        result = self.reputation_service.check(target)

        if not result.known:
            return []

        confidence = round(result.confidence * 100)

        if result.malicious:
            return [
                DetectionFinding(
                    code="DOMAIN_REPUTATION_MALICIOUS",
                    title="Known malicious domain",
                    description=(
                        "The domain matches a known malicious "
                        "reputation record."
                    ),
                    severity=result.severity,
                    confidence=confidence,
                    evidence={
                        "domain": result.domain,
                        "source": result.source,
                        "tags": sorted(result.tags),
                        "malicious": True,
                    },
                )
            ]

        return [
            DetectionFinding(
                code="DOMAIN_REPUTATION_KNOWN",
                title="Known domain reputation",
                description=(
                    "The domain exists in reputation intelligence "
                    "and is not currently marked as malicious."
                ),
                severity=result.severity,
                confidence=confidence,
                evidence={
                    "domain": result.domain,
                    "source": result.source,
                    "tags": sorted(result.tags),
                    "malicious": False,
                },
            )
        ]