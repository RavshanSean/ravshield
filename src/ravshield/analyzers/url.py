from __future__ import annotations

from ravshield.intel.url import URLReputationService
from ravshield.models import DetectionFinding

from .base import BaseAnalyzer


class URLAnalyzer(BaseAnalyzer):
    """
    Analyze URLs using RavShield URL reputation intelligence.
    """

    name = "url_reputation"

    def __init__(
        self,
        reputation_service: URLReputationService | None = None,
    ) -> None:
        self.reputation_service = (
            reputation_service or URLReputationService()
        )

    def analyze(
        self,
        target: str,
    ) -> list[DetectionFinding]:
        """
        Check a URL and convert its reputation into findings.
        """

        result = self.reputation_service.check(target)

        if not result.known:
            return []

        confidence = round(result.confidence * 100)

        if result.malicious:
            return [
                DetectionFinding(
                    code="URL_REPUTATION_MALICIOUS",
                    title="Known malicious URL",
                    description=(
                        "The URL matches a known malicious "
                        "reputation record."
                    ),
                    severity=result.severity,
                    confidence=confidence,
                    evidence={
                        "url": result.url,
                        "source": result.source,
                        "tags": sorted(result.tags),
                        "malicious": True,
                    },
                )
            ]

        return [
            DetectionFinding(
                code="URL_REPUTATION_KNOWN",
                title="Known URL reputation",
                description=(
                    "The URL exists in the reputation store "
                    "and is not currently marked as malicious."
                ),
                severity=result.severity,
                confidence=confidence,
                evidence={
                    "url": result.url,
                    "source": result.source,
                    "tags": sorted(result.tags),
                    "malicious": False,
                },
            )
        ]