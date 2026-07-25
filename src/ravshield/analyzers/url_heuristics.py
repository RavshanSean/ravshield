from __future__ import annotations

from ravshield.analyzers.base import BaseAnalyzer
from ravshield.intel.url import analyze_url_heuristics
from ravshield.models import DetectionFinding, Severity


SIGNAL_SEVERITY = {
    "embedded_credentials": Severity.HIGH,
    "punycode_hostname": Severity.HIGH,
    "suspicious_keywords": Severity.MEDIUM,
    "excessive_subdomains": Severity.MEDIUM,
    "long_hostname": Severity.LOW,
    "long_url": Severity.LOW,
    "encoded_characters": Severity.MEDIUM,
}


class URLHeuristicAnalyzer(BaseAnalyzer):
    """
    Detect suspicious URL characteristics.
    """

    name = "url_heuristics"

    def analyze(self, target: str):
        result = analyze_url_heuristics(target)

        findings = []

        for signal in sorted(result.signals):
            findings.append(
                DetectionFinding(
                    code=f"URL_{signal.upper()}",
                    title=signal.replace("_", " ").title(),
                    severity=SIGNAL_SEVERITY[signal],
                    confidence=70,
                    description=f"Detected heuristic: {signal}",
                    evidence=result.details,
                )
            )

        return findings