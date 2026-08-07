from __future__ import annotations

from ravshield.analyzers.base import BaseAnalyzer
from ravshield.enums import Severity
from ravshield.intel.ip import analyze_ip_heuristics
from ravshield.models import DetectionFinding


SIGNAL_CONFIG = {
    "loopback": {
        "code": "IP_LOOPBACK",
        "title": "Loopback IP detected",
        "severity": Severity.HIGH,
        "confidence": 95,
        "description": (
            "The IP address points to the local host and should not "
            "normally be treated as a public internet target."
        ),
    },
    "private_address": {
        "code": "IP_PRIVATE_ADDRESS",
        "title": "Private IP address detected",
        "severity": Severity.MEDIUM,
        "confidence": 90,
        "description": (
            "The IP address belongs to a private network range."
        ),
    },
    "link_local": {
        "code": "IP_LINK_LOCAL",
        "title": "Link-local IP detected",
        "severity": Severity.HIGH,
        "confidence": 95,
        "description": (
            "The IP address belongs to a link-local range and may "
            "reference local infrastructure or metadata services."
        ),
    },
    "multicast": {
        "code": "IP_MULTICAST",
        "title": "Multicast IP detected",
        "severity": Severity.MEDIUM,
        "confidence": 85,
        "description": (
            "The IP address belongs to a multicast range rather than "
            "a standard public host."
        ),
    },
    "reserved": {
        "code": "IP_RESERVED",
        "title": "Reserved IP detected",
        "severity": Severity.MEDIUM,
        "confidence": 85,
        "description": (
            "The IP address belongs to a reserved network range."
        ),
    },
}


class IPHeuristicAnalyzer(BaseAnalyzer):
    """
    Convert IP heuristic signals into detection findings.
    """

    name = "ip_heuristics"

    def analyze(
        self,
        target: str,
    ) -> list[DetectionFinding]:
        result = analyze_ip_heuristics(target)

        findings: list[DetectionFinding] = []

        for signal in sorted(result.signals):
            config = SIGNAL_CONFIG[signal]

            evidence = {
                "ip": result.ip,
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