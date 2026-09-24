from __future__ import annotations

from pathlib import Path

from ravshield.analyzers.base import BaseAnalyzer
from ravshield.enums import Severity
from ravshield.intel.file.heuristics import analyze_file_heuristics
from ravshield.models import DetectionFinding


SIGNAL_CONFIG = {
    "risky_extension": {
        "code": "FILE_RISKY_EXTENSION",
        "title": "Risky file extension detected",
        "severity": Severity.MEDIUM,
        "confidence": 75,
        "description": (
            "The file uses an extension commonly associated with "
            "executable or script content."
        ),
    },
    "double_extension": {
        "code": "FILE_DOUBLE_EXTENSION",
        "title": "Suspicious double extension detected",
        "severity": Severity.HIGH,
        "confidence": 90,
        "description": (
            "The filename uses a decoy-looking extension followed by "
            "an executable or script extension."
        ),
    },
}


class FileHeuristicAnalyzer(BaseAnalyzer):
    """
    Convert file heuristic signals into detection findings.
    """

    name = "file_heuristics"

    def analyze(
        self,
        target: str | Path,
    ) -> list[DetectionFinding]:
        result = analyze_file_heuristics(target)

        findings: list[DetectionFinding] = []

        for signal in sorted(result.signals):
            config = SIGNAL_CONFIG[signal]

            evidence = {
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