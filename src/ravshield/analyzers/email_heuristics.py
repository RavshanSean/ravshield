from __future__ import annotations

from ravshield.analyzers.base import BaseAnalyzer
from ravshield.enums import Severity
from ravshield.intel.email import analyze_email_heuristics
from ravshield.models import DetectionFinding


SIGNAL_CONFIG = {
    "disposable_provider": {
        "code": "EMAIL_DISPOSABLE_PROVIDER",
        "title": "Disposable email provider detected",
        "severity": Severity.MEDIUM,
        "confidence": 85,
        "description": (
            "The email address uses a temporary or disposable "
            "email provider."
        ),
    },
    "suspicious_local_keywords": {
        "code": "EMAIL_SUSPICIOUS_LOCAL_KEYWORDS",
        "title": "Suspicious email keywords detected",
        "severity": Severity.MEDIUM,
        "confidence": 70,
        "description": (
            "The local part contains keywords commonly used in "
            "phishing or impersonation attempts."
        ),
    },
    "numeric_heavy_local_part": {
        "code": "EMAIL_NUMERIC_HEAVY_LOCAL_PART",
        "title": "Numeric-heavy email local part detected",
        "severity": Severity.LOW,
        "confidence": 60,
        "description": (
            "The local part contains an unusually high proportion "
            "of numeric characters."
        ),
    },
    "long_local_part": {
        "code": "EMAIL_LONG_LOCAL_PART",
        "title": "Unusually long email local part detected",
        "severity": Severity.LOW,
        "confidence": 55,
        "description": (
            "The local part of the email address is unusually long."
        ),
    },
    "punycode_domain": {
        "code": "EMAIL_PUNYCODE_DOMAIN",
        "title": "Punycode email domain detected",
        "severity": Severity.HIGH,
        "confidence": 90,
        "description": (
            "The email domain uses Punycode and may be attempting "
            "to imitate another domain."
        ),
    },
}


class EmailHeuristicAnalyzer(BaseAnalyzer):
    """
    Convert email heuristic signals into detection findings.
    """

    name = "email_heuristics"

    def analyze(
        self,
        target: str,
    ) -> list[DetectionFinding]:
        result = analyze_email_heuristics(target)

        findings: list[DetectionFinding] = []

        for signal in sorted(result.signals):
            config = SIGNAL_CONFIG[signal]

            evidence = {
                "email": result.email,
                "signal": signal,
            }

            evidence.update(result.details)

            findings.append(
                DetectionFinding(
                    code=config["code"],
                    title=config["title"],
                    description=config["description"],
                    severity=config["severity"],
                    confidence=config["confidence"],
                    evidence=evidence,
                )
            )

        return findings