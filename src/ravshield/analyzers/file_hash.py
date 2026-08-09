from __future__ import annotations

from pathlib import Path

from ravshield.analyzers.base import BaseAnalyzer
from ravshield.engines.hash_engine import (
    calculate_sha256,
    normalize_hash,
    validate_hash,
)
from ravshield.enums import Severity, Verdict
from ravshield.intel import IOCStore, match_ioc
from ravshield.models import DetectionFinding
from ravshield.reputation import get_hash_reputation


class FileHashAnalyzer(BaseAnalyzer):
    """
    Hash a local file and check it against IOC + built-in hash intel.
    """

    name = "file_hash"

    def __init__(
        self,
        store: IOCStore | None = None,
    ) -> None:
        self.store = store or IOCStore()

    def analyze(
        self,
        target: str | Path,
    ) -> list[DetectionFinding]:
        path = Path(target)

        if not path.is_file():
            raise ValueError(
                f"FileHashAnalyzer target is not a file: {path}"
            )

        digest = calculate_sha256(path)
        findings: list[DetectionFinding] = []

        ioc_finding = match_ioc(
            self.store,
            "sha256",
            digest,
        )

        if ioc_finding is not None:
            findings.append(
                DetectionFinding(
                    code="FILE_HASH_IOC_MATCH",
                    title=ioc_finding.title,
                    description=ioc_finding.description,
                    severity=ioc_finding.severity,
                    confidence=ioc_finding.confidence,
                    evidence={
                        **ioc_finding.evidence,
                        "path": str(path),
                        "algorithm": "sha256",
                        "digest": digest,
                    },
                )
            )

        builtin = get_hash_reputation(digest)

        if builtin is Verdict.MALICIOUS:
            findings.append(
                DetectionFinding(
                    code="HASH_REPUTATION_MALICIOUS",
                    title="Known malicious file hash",
                    description=(
                        "The file SHA-256 matches built-in "
                        "malicious hash intelligence."
                    ),
                    severity=Severity.CRITICAL,
                    confidence=95,
                    evidence={
                        "path": str(path),
                        "digest": digest,
                        "algorithm": "sha256",
                    },
                )
            )
        elif builtin is Verdict.SAFE:
            findings.append(
                DetectionFinding(
                    code="HASH_REPUTATION_CLEAN",
                    title="Known clean file hash",
                    description=(
                        "The file SHA-256 matches built-in "
                        "clean hash intelligence."
                    ),
                    severity=Severity.INFO,
                    confidence=90,
                    evidence={
                        "path": str(path),
                        "digest": digest,
                        "algorithm": "sha256",
                    },
                )
            )

        return findings


class HashIOCAnalyzer(BaseAnalyzer):
    """
    Match a raw hash string against the IOC store and built-in intel.
    """

    name = "hash_ioc"

    def __init__(
        self,
        store: IOCStore | None = None,
    ) -> None:
        self.store = store or IOCStore()

    def analyze(
        self,
        target: str,
    ) -> list[DetectionFinding]:
        value = normalize_hash(target)

        for algorithm in ("sha256", "sha1", "md5"):
            if not validate_hash(value, algorithm):
                continue

            finding = match_ioc(
                self.store,
                algorithm,
                value,
            )

            if finding is not None:
                return [
                    DetectionFinding(
                        code="FILE_HASH_IOC_MATCH",
                        title=finding.title,
                        description=finding.description,
                        severity=finding.severity,
                        confidence=finding.confidence,
                        evidence={
                            **finding.evidence,
                            "algorithm": algorithm,
                            "digest": value,
                        },
                    )
                ]

            builtin = get_hash_reputation(value)

            if builtin is Verdict.MALICIOUS:
                return [
                    DetectionFinding(
                        code="HASH_REPUTATION_MALICIOUS",
                        title="Known malicious hash",
                        description=(
                            "The hash matches built-in malicious "
                            "hash intelligence."
                        ),
                        severity=Severity.CRITICAL,
                        confidence=95,
                        evidence={
                            "digest": value,
                            "algorithm": algorithm,
                        },
                    )
                ]

            if builtin is Verdict.SAFE:
                return [
                    DetectionFinding(
                        code="HASH_REPUTATION_CLEAN",
                        title="Known clean hash",
                        description=(
                            "The hash matches built-in clean "
                            "hash intelligence."
                        ),
                        severity=Severity.INFO,
                        confidence=90,
                        evidence={
                            "digest": value,
                            "algorithm": algorithm,
                        },
                    )
                ]

        return []
