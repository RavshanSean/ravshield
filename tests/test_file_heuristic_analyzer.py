from pathlib import Path

from ravshield.analyzers.file_heuristics import FileHeuristicAnalyzer
from ravshield.enums import Severity


def test_normal_file_returns_no_findings(tmp_path: Path):
    file_path = tmp_path / "notes.txt"
    file_path.write_text("normal file")

    analyzer = FileHeuristicAnalyzer()
    findings = analyzer.analyze(file_path)

    assert findings == []


def test_risky_extension_creates_finding(tmp_path: Path):
    file_path = tmp_path / "program.exe"
    file_path.write_text("test")

    analyzer = FileHeuristicAnalyzer()
    findings = analyzer.analyze(file_path)

    assert len(findings) == 1

    finding = findings[0]

    assert finding.code == "FILE_RISKY_EXTENSION"
    assert finding.severity == Severity.MEDIUM
    assert finding.confidence == 75
    assert finding.evidence["extension"] == ".exe"


def test_double_extension_creates_two_findings(tmp_path: Path):
    file_path = tmp_path / "invoice.pdf.exe"
    file_path.write_text("test")

    analyzer = FileHeuristicAnalyzer()
    findings = analyzer.analyze(file_path)

    codes = {finding.code for finding in findings}

    assert codes == {
        "FILE_DOUBLE_EXTENSION",
        "FILE_RISKY_EXTENSION",
    }


def test_double_extension_is_high_severity(tmp_path: Path):
    file_path = tmp_path / "invoice.pdf.exe"
    file_path.write_text("test")

    analyzer = FileHeuristicAnalyzer()
    findings = analyzer.analyze(file_path)

    double_extension = next(
        finding
        for finding in findings
        if finding.code == "FILE_DOUBLE_EXTENSION"
    )

    assert double_extension.severity == Severity.HIGH
    assert double_extension.confidence == 90