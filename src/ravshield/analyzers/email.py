from __future__ import annotations

from ravshield.analyzers.base import BaseAnalyzer
from ravshield.intel.email import EmailReputationService
from ravshield.models import DetectionFinding


class EmailReputationAnalyzer(BaseAnalyzer):
    """
    Analyze email addresses using RavShield reputation intelligence.
    """

    name = "email_reputation"

    def __init__(
        self,
        reputation_service: EmailReputationService | None = None,
    ) -> None:
        self.reputation_service = (
            reputation_service or EmailReputationService()
        )

    def analyze(
        self,
        target: str,
    ) -> list[DetectionFinding]:
        """
        Check email reputation and convert the result into findings.
        """

        result = self.reputation_service.check(target)

        if not result.known:
            return []

        confidence = round(result.confidence * 100)

        if result.malicious:
            return [
                DetectionFinding(
                    code="EMAIL_REPUTATION_MALICIOUS",
                    title="Known malicious email address",
                    description=(
                        "The email address matches a known malicious "
                        "reputation record."
                    ),
                    severity=result.severity,
                    confidence=confidence,
                    evidence={
                        "email": result.email,
                        "source": result.source,
                        "tags": sorted(result.tags),
                        "malicious": True,
                    },
                )
            ]

        return [
            DetectionFinding(
                code="EMAIL_REPUTATION_KNOWN",
                title="Known email reputation",
                description=(
                    "The email address exists in reputation intelligence "
                    "and is not currently marked as malicious."
                ),
                severity=result.severity,
                confidence=confidence,
                evidence={
                    "email": result.email,
                    "source": result.source,
                    "tags": sorted(result.tags),
                    "malicious": False,
                },
            )
        ]