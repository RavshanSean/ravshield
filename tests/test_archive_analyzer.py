from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from ravshield.analyzers.archive import ArchiveAnalyzer
from ravshield.enums import Severity
from unittest.mock import patch


def test_archive_analyzer_returns_no_findings_for_safe_zip(
    tmp_path: Path,
):
    zip_path = tmp_path / "safe.zip"

    with ZipFile(zip_path, "w") as archive:
        archive.writestr("notes.txt", "hello")
        archive.writestr("report.pdf", "fake pdf")

    analyzer = ArchiveAnalyzer()

    findings = analyzer.analyze(zip_path)

    assert findings == []


def test_archive_analyzer_detects_risky_file(
    tmp_path: Path,
):
    zip_path = tmp_path / "risky.zip"

    with ZipFile(zip_path, "w") as archive:
        archive.writestr("tools/setup.exe", "fake executable")

    analyzer = ArchiveAnalyzer()

    findings = analyzer.analyze(zip_path)

    assert len(findings) == 1

    finding = findings[0]

    assert finding.code == "ARCHIVE_RISKY_FILE"
    assert finding.severity == Severity.MEDIUM
    assert finding.confidence == 75
    assert finding.evidence["signal"] == "risky_extension"
    assert finding.evidence["filename"] == "tools/setup.exe"


def test_archive_analyzer_detects_double_extension(
    tmp_path: Path,
):
    zip_path = tmp_path / "suspicious.zip"

    with ZipFile(zip_path, "w") as archive:
        archive.writestr(
            "documents/invoice.pdf.exe",
            "fake executable",
        )

    analyzer = ArchiveAnalyzer()

    findings = analyzer.analyze(zip_path)

    codes = {
        finding.code
        for finding in findings
    }

    assert codes == {
        "ARCHIVE_RISKY_FILE",
        "ARCHIVE_DOUBLE_EXTENSION",
    }
    
def test_archive_analyzer_detects_high_compression_ratio(
    tmp_path: Path,
):
    zip_path = tmp_path / "compressed.zip"

    with ZipFile(
        zip_path,
        "w",
        compression=ZIP_DEFLATED,
    ) as archive:
        archive.writestr(
            "repeated.txt",
            "A" * 100_000,
        )

    analyzer = ArchiveAnalyzer()

    findings = analyzer.analyze(zip_path)

    matching = [
        finding
        for finding in findings
        if finding.code == "ARCHIVE_HIGH_COMPRESSION_RATIO"
    ]

    assert len(matching) == 1

    finding = matching[0]

    assert finding.severity == Severity.HIGH
    assert finding.confidence == 90
    assert finding.evidence["signal"] == "excessive_compression_ratio"
    assert finding.evidence["compression_ratio"] > 100
    
def test_archive_analyzer_creates_encrypted_entry_finding(
    tmp_path: Path,
):
    zip_path = tmp_path / "encrypted.zip"

    with ZipFile(zip_path, "w") as archive:
        archive.writestr("secret.txt", "hidden data")

    analyzer = ArchiveAnalyzer()

    with patch(
        "ravshield.analyzers.archive.find_encrypted_archive_files",
        return_value=["secret.txt"],
    ):
        findings = analyzer.analyze(zip_path)

    matching = [
        finding
        for finding in findings
        if finding.code == "ARCHIVE_ENCRYPTED_ENTRY"
    ]

    assert len(matching) == 1

    finding = matching[0]

    assert finding.severity == Severity.LOW
    assert finding.confidence == 100
    assert finding.evidence["signal"] == "encrypted_entry"
    assert finding.evidence["filename"] == "secret.txt"