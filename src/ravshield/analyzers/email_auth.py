from __future__ import annotations

from typing import Any

from ravshield.analyzers.base import BaseAnalyzer
from ravshield.enums import Severity
from ravshield.intel.email.auth import analyze_email_auth_headers
from ravshield.models import DetectionFinding


SIGNAL_CONFIG = {
    "spf_fail": {
        "code": "EMAIL_SPF_FAIL",
        "title": "SPF authentication failed",
        "severity": Severity.HIGH,
        "confidence": 85,
        "description": (
            "Authentication headers report an SPF failure."
        ),
    },
    "dkim_fail": {
        "code": "EMAIL_DKIM_FAIL",
        "title": "DKIM authentication failed",
        "severity": Severity.HIGH,
        "confidence": 85,
        "description": (
            "Authentication headers report a DKIM failure."
        ),
    },
    "dmarc_fail": {
        "code": "EMAIL_DMARC_FAIL",
        "title": "DMARC authentication failed",
        "severity": Severity.HIGH,
        "confidence": 90,
        "description": (
            "Authentication headers report a DMARC failure."
        ),
    },
    "auth_headers_missing": {
        "code": "EMAIL_AUTH_HEADERS_MISSING",
        "title": "Email authentication headers missing",
        "severity": Severity.LOW,
        "confidence": 40,
        "description": (
            "No SPF/DKIM/DMARC authentication results were present "
            "on the supplied message headers."
        ),
    },
}


def _extract_headers(target: Any) -> dict[str, str] | None:
    if isinstance(target, dict):
        headers = target.get("headers")

        if isinstance(headers, dict):
            return {
                str(key): str(value)
                for key, value in headers.items()
            }

        # Allow callers to pass the header map directly.
        if all(isinstance(key, str) for key in target):
            lowered_keys = {key.lower() for key in target}

            interesting = {
                "authentication-results",
                "received-spf",
                "dkim-signature",
            }

            if lowered_keys & interesting:
                return {
                    str(key): str(value)
                    for key, value in target.items()
                }

    return None


class EmailAuthAnalyzer(BaseAnalyzer):
    """
    Offline SPF/DKIM/DMARC header analysis.

    Accepts either a header mapping or
    ``{"address": "...", "headers": {...}}``.
    Plain email address strings produce no findings.
    """

    name = "email_auth"

    def analyze(
        self,
        target: Any,
    ) -> list[DetectionFinding]:
        headers = _extract_headers(target)

        if headers is None:
            return []

        result = analyze_email_auth_headers(headers)
        findings: list[DetectionFinding] = []

        for signal in sorted(result.signals):
            config = SIGNAL_CONFIG[signal]
            evidence = {
                "spf": result.spf,
                "dkim": result.dkim,
                "dmarc": result.dmarc,
                "signal": signal,
            }
            evidence.update(result.details)

            findings.append(
                DetectionFinding(
                    code=config["code"],
                    title=config["title"],
                    severity=config["severity"],
                    confidence=config["confidence"],
                    description=config["description"],
                    evidence=evidence,
                )
            )

        return findings
