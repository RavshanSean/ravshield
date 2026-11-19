"""Tests for safe report file export."""
import json

import pytest

from ravshield.cli import main


def test_scan_json_saved(tmp_path, capsys):
    target = tmp_path / "input.bin"
    target.write_bytes(b"unknown format")
    out = tmp_path / "report.json"
    assert main(["scan", str(target), "--json", "--output", str(out)]) == 0
    assert json.loads(out.read_text())["report_type"] == "explained"
    assert "Report saved:" in capsys.readouterr().out


def test_scan_text_saved(tmp_path):
    target = tmp_path / "input.bin"
    target.write_bytes(b"unknown format")
    out = tmp_path / "report.txt"
    assert main(["scan", str(target), "--output", str(out)]) == 0
    assert "Risk: unknown" in out.read_text()


def test_batch_json_saved(tmp_path):
    folder = tmp_path / "input"
    folder.mkdir()
    (folder / "x.bin").write_bytes(b"unknown format")
    out = tmp_path / "batch.json"
    assert main(["batch", str(folder), "--json", "--output", str(out)]) == 0
    assert json.loads(out.read_text())["scanned"] == 1


def test_batch_text_saved(tmp_path):
    folder = tmp_path / "input"
    folder.mkdir()
    (folder / "x.bin").write_bytes(b"unknown format")
    out = tmp_path / "batch.txt"
    assert main(["batch", str(folder), "--output", str(out)]) == 0
    assert "Summary: 1 scanned, 0 failed" in out.read_text()


def test_existing_file_not_overwritten(tmp_path, capsys):
    target = tmp_path / "input.bin"
    target.write_bytes(b"original")
    assert main(["scan", str(target), "--output", str(target)]) == 2
    assert target.read_bytes() == b"original"
    assert "cannot save report" in capsys.readouterr().err


def test_existing_report_not_overwritten(tmp_path):
    target = tmp_path / "input.bin"
    target.write_bytes(b"unknown")
    out = tmp_path / "report.json"
    out.write_text("existing")
    assert main(["scan", str(target), "--json", "--output", str(out)]) == 2
    assert out.read_text() == "existing"


def test_missing_parent_returns_error(tmp_path, capsys):
    target = tmp_path / "input.bin"
    target.write_bytes(b"unknown")
    assert main(["scan", str(target), "--output", str(tmp_path / "missing" / "report.json")]) == 2
    assert "cannot save report" in capsys.readouterr().err


def test_stdout_unchanged_without_output(tmp_path, capsys):
    target = tmp_path / "input.bin"
    target.write_bytes(b"unknown")
    assert main(["scan", str(target), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["risk_level"] == "unknown"


def test_batch_json_stdout_unchanged(tmp_path, capsys):
    assert main(["batch", str(tmp_path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["scanned"] == 0


def test_batch_output_inside_folder_not_in_scan(tmp_path):
    (tmp_path / "x.bin").write_bytes(b"unknown")
    out = tmp_path / "batch.json"
    assert main(["batch", str(tmp_path), "--json", "--output", str(out)]) == 0
    assert json.loads(out.read_text())["scanned"] == 1


def test_scan_raw_json_saved(tmp_path):
    target = tmp_path / "input.bin"
    target.write_bytes(b"unknown")
    out = tmp_path / "raw.json"
    assert main(["scan", str(target), "--json", "--raw", "--output", str(out)]) == 0
    assert json.loads(out.read_text())["report_type"] == "security"


def test_batch_raw_json_saved(tmp_path):
    (tmp_path / "x.bin").write_bytes(b"unknown")
    out = tmp_path / "raw.json"
    assert main(["batch", str(tmp_path), "--json", "--raw", "--output", str(out)]) == 0
    assert json.loads(out.read_text())["results"][0]["report"]["report_type"] == "security"
