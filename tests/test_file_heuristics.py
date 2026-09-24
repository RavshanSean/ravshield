from pathlib import Path

from ravshield.intel.file.heuristics import analyze_file_heuristics


def test_normal_text_file_has_no_signals(tmp_path: Path):
    file_path = tmp_path / "notes.txt"
    file_path.write_text("normal file")

    result = analyze_file_heuristics(file_path)

    assert result.suspicious is False
    assert result.signals == set()


def test_executable_extension_is_flagged(tmp_path: Path):
    file_path = tmp_path / "program.exe"
    file_path.write_text("test executable")

    result = analyze_file_heuristics(file_path)

    assert result.suspicious is True
    assert "risky_extension" in result.signals


def test_powershell_extension_is_flagged(tmp_path: Path):
    file_path = tmp_path / "script.ps1"
    file_path.write_text("Write-Host 'Hello'")

    result = analyze_file_heuristics(file_path)

    assert "risky_extension" in result.signals


def test_double_extension_is_flagged(tmp_path: Path):
    file_path = tmp_path / "invoice.pdf.exe"
    file_path.write_text("test")

    result = analyze_file_heuristics(file_path)

    assert result.suspicious is True
    assert "risky_extension" in result.signals
    assert "double_extension" in result.signals


def test_safe_double_extension_is_not_flagged(tmp_path: Path):
    file_path = tmp_path / "archive.backup.txt"
    file_path.write_text("test")

    result = analyze_file_heuristics(file_path)

    assert "double_extension" not in result.signals


def test_details_include_file_metadata(tmp_path: Path):
    file_path = tmp_path / "sample.txt"
    file_path.write_text("ravshield")

    result = analyze_file_heuristics(file_path)

    assert result.details["name"] == "sample.txt"
    assert result.details["extension"] == ".txt"
    assert result.details["size"] == 9