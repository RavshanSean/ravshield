"""CLI regression tests using inert local files and synthetic reports."""
from __future__ import annotations

import json

import pytest

from ravshield import cli
from ravshield.intel.file.report import SecurityFinding, SecurityReport


def _report(*findings, risk="informational", complete=True, warnings=()):
    return SecurityReport("pdf", "pdf", risk, tuple(findings), tuple(warnings), complete)


def test_cli_help(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--help"])
    assert exc.value.code == 0
    assert "scan" in capsys.readouterr().out


def test_scan_help(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["scan", "--help"])
    assert exc.value.code == 0
    assert "--json" in capsys.readouterr().out


def test_requires_command():
    with pytest.raises(SystemExit) as exc:
        cli.main([])
    assert exc.value.code == 2


def test_requires_file():
    with pytest.raises(SystemExit) as exc:
        cli.main(["scan"])
    assert exc.value.code == 2


def test_explained_text(monkeypatch, capsys):
    monkeypatch.setattr(cli, "scan_file", lambda _: _report(
        SecurityFinding("pdf_javascript", "high", "JavaScript indicator."), risk="high"))
    assert cli.main(["scan", "example.pdf"]) == 0
    out = capsys.readouterr().out
    assert "Risk: high" in out
    assert "Recommendation:" in out
    assert "not a malware verdict" in out


def test_raw_text(monkeypatch, capsys):
    monkeypatch.setattr(cli, "scan_file", lambda _: _report(
        SecurityFinding("pdf_javascript", "high", "JavaScript indicator."), risk="high"))
    assert cli.main(["scan", "example.pdf", "--raw"]) == 0
    out = capsys.readouterr().out
    assert "JavaScript indicator." in out
    assert "Recommendation:" not in out


@pytest.mark.parametrize("raw,expected", [(False, "explained"), (True, "security")])
def test_json_output(monkeypatch, capsys, raw, expected):
    monkeypatch.setattr(cli, "scan_file", lambda _: _report())
    args = ["scan", "example.pdf", "--json"] + (["--raw"] if raw else [])
    assert cli.main(args) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["report_type"] == expected
    assert payload["risk_level"] == "informational"
    assert "safe" not in payload


def test_incomplete_report(monkeypatch, capsys):
    monkeypatch.setattr(cli, "scan_file", lambda _: _report(
        risk="unknown", complete=False, warnings=("Unsupported format.",)))
    assert cli.main(["scan", "unknown.bin"]) == 0
    out = capsys.readouterr().out
    assert "Scan complete: no" in out
    assert "Unsupported format." in out


def test_missing_file_is_error(capsys, tmp_path):
    assert cli.main(["scan", str(tmp_path / "missing.pdf")]) == 2
    assert "scan failed" in capsys.readouterr().err


def test_scan_real_pdf(capsys, tmp_path):
    path = tmp_path / "sample.bin"
    path.write_bytes(b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n")
    assert cli.main(["scan", str(path), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["file_type"] == "pdf"
    assert data["scan_complete"] is True


def test_scan_real_unknown(capsys, tmp_path):
    path = tmp_path / "unknown.txt"
    path.write_text("unknown file signature", encoding="utf-8")
    assert cli.main(["scan", str(path), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["risk_level"] == "unknown"
    assert data["needs_review"] is True
