from __future__ import annotations

from ravshield.analyzers.base import BaseAnalyzer
from ravshield.intel.ip import IPReputationService
from ravshield.models import DetectionFinding


class IPReputationAnalyzer(BaseAnalyzer):
    """
    Analyze IP addresses using RavShield reputation intelligence.
    """

    name = "ip_reputation"

    def __init__(
        self,
        reputation_service: IPReputationService | None = None,
    ) -> None:
        self.reputation_service = (
            reputation_service or IPReputationService()
        )

    def analyze(
        self,
        target: str,
    ) -> list[DetectionFinding]:
        """
        Check IP reputation and convert the result into findings.
        """

        result = self.reputation_service.check(target)

        if not result.known:
            return []

        confidence = round(result.confidence * 100)

        if result.malicious:
            return [
                DetectionFinding(
                    code="IP_REPUTATION_MALICIOUS",
                    title="Known malicious IP address",
                    description=(
                        "The IP address matches a known malicious "
                        "reputation record."
                    ),
                    severity=result.severity,
                    confidence=confidence,
                    evidence={
                        "ip": result.ip,
                        "source": result.source,
                        "tags": sorted(result.tags),
                        "malicious": True,
                    },
                )
            ]

        return [
            DetectionFinding(
                code="IP_REPUTATION_KNOWN",
                title="Known IP reputation",
                description=(
                    "The IP address exists in reputation intelligence "
                    "and is not currently marked as malicious."
                ),
                severity=result.severity,
                confidence=confidence,
                evidence={
                    "ip": result.ip,
                    "source": result.source,
                    "tags": sorted(result.tags),
                    "malicious": False,
                },
            )
        ]