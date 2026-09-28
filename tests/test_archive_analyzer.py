from pathlib import Path
from zipfile import ZipFile

from ravshield.analyzers.archive import ArchiveAnalyzer
from ravshield.enums import Severity


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