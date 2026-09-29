from __future__ import annotations

from pathlib import Path

from ravshield.analyzers.base import BaseAnalyzer
from ravshield.enums import Severity
from ravshield.intel.file.archive import (
    analyze_archive_size_risk,
    find_encrypted_archive_files,
    find_nested_archives,
    find_suspicious_archive_files,
    inspect_zip,
)
from ravshield.models import DetectionFinding


SIGNAL_CONFIG = {
    "risky_extension": {
        "code": "ARCHIVE_RISKY_FILE",
        "title": "Risky file found inside archive",
        "severity": Severity.MEDIUM,
        "confidence": 75,
        "description": (
            "The archive contains a file with an extension commonly "
            "associated with executable or script content."
        ),
    },
    "double_extension": {
        "code": "ARCHIVE_DOUBLE_EXTENSION",
        "title": "Suspicious double extension inside archive",
        "severity": Severity.HIGH,
        "confidence": 90,
        "description": (
            "The archive contains a filename using a decoy-looking "
            "extension followed by an executable or script extension."
        ),
    },
    "excessive_uncompressed_size": {
        "code": "ARCHIVE_EXCESSIVE_SIZE",
        "title": "Excessive archive expansion size",
        "severity": Severity.HIGH,
        "confidence": 90,
        "description": (
            "The archive reports an unusually large total "
            "uncompressed size."
        ),
    },
    "excessive_compression_ratio": {
        "code": "ARCHIVE_HIGH_COMPRESSION_RATIO",
        "title": "Excessive archive compression ratio",
        "severity": Severity.HIGH,
        "confidence": 90,
        "description": (
            "The archive has a compression ratio associated with "
            "possible decompression-bomb behavior."
        ),
    },
    "encrypted_entry": {
        "code": "ARCHIVE_ENCRYPTED_ENTRY",
        "title": "Encrypted file inside archive",
        "severity": Severity.LOW,
        "confidence": 100,
        "description": (
            "The archive contains an encrypted file whose contents "
            "cannot be fully inspected without decryption."
        ),
    },
    "nested_archive": {
        "code": "ARCHIVE_NESTED_ZIP",
        "title": "Nested ZIP archive detected",
        "severity": Severity.LOW,
        "confidence": 100,
        "description": (
            "The archive contains another ZIP archive that may "
            "require additional inspection."
        ),
    },
}


class ArchiveAnalyzer(BaseAnalyzer):
    """
    Convert ZIP archive security signals into detection findings.
    """

    name = "archive"

    def analyze(
        self,
        target: str | Path,
    ) -> list[DetectionFinding]:
        inspection = inspect_zip(target)

        findings: list[DetectionFinding] = []

        suspicious_files = find_suspicious_archive_files(
            inspection.filenames,
        )

        for filename, signals in suspicious_files.items():
            for signal in sorted(signals):
                config = SIGNAL_CONFIG[signal]

                findings.append(
                    DetectionFinding(
                        code=config["code"],
                        title=config["title"],
                        description=config["description"],
                        severity=config["severity"],
                        confidence=config["confidence"],
                        evidence={
                            "signal": signal,
                            "filename": filename,
                        },
                    )
                )

        size_risk = analyze_archive_size_risk(target)

        for signal in sorted(size_risk.signals):
            config = SIGNAL_CONFIG[signal]

            findings.append(
                DetectionFinding(
                    code=config["code"],
                    title=config["title"],
                    description=config["description"],
                    severity=config["severity"],
                    confidence=config["confidence"],
                    evidence={
                        "signal": signal,
                        "compressed_size": size_risk.compressed_size,
                        "uncompressed_size": size_risk.uncompressed_size,
                        "compression_ratio": size_risk.compression_ratio,
                    },
                )
            )

        encrypted_files = find_encrypted_archive_files(target)

        for filename in encrypted_files:
            config = SIGNAL_CONFIG["encrypted_entry"]

            findings.append(
                DetectionFinding(
                    code=config["code"],
                    title=config["title"],
                    description=config["description"],
                    severity=config["severity"],
                    confidence=config["confidence"],
                    evidence={
                        "signal": "encrypted_entry",
                        "filename": filename,
                    },
                )
            )

        nested_archives = find_nested_archives(
            inspection.filenames,
        )

        for filename in nested_archives:
            config = SIGNAL_CONFIG["nested_archive"]

            findings.append(
                DetectionFinding(
                    code=config["code"],
                    title=config["title"],
                    description=config["description"],
                    severity=config["severity"],
                    confidence=config["confidence"],
                    evidence={
                        "signal": "nested_archive",
                        "filename": filename,
                    },
                )
            )

        return findings