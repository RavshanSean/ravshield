"""Regression tests for RavShield's versioned, JSON-only report exporter."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from ravshield.intel.file.report import SecurityFinding, SecurityReport
from ravshield.intel.file.report_explain import explain_security_report
from ravshield.intel.file import report_json


def _report(*, findings=(), warnings=(), complete=True, risk="informational"):
    return SecurityReport("pdf", "pdf", risk, tuple(findings), tuple(warnings), complete)


def test_security_report_schema_and_values():
    finding = SecurityFinding("pdf_javascript", "high", "JavaScript indicator.")
    data = report_json.report_to_dict(_report(findings=(finding,), risk="high"))
    assert data == {
        "schema_version": "1.0", "report_type": "security", "file_type": "pdf",
        "analyzer": "pdf", "risk_level": "high", "scan_complete": True,
        "needs_review": True,
        "findings": [{"code": "pdf_javascript", "severity": "high", "description": "JavaScript indicator."}],
        "warnings": [],
    }


def test_explained_report_schema_and_values():
    finding = SecurityFinding("pdf_javascript", "high", "JavaScript indicator.")
    explained = explain_security_report(_report(findings=(finding,), risk="high"))
    data = report_json.report_to_dict(explained)
    assert data["report_type"] == "explained"
    assert data["risk_level"] == "high"
    assert "not a malware verdict" in data["summary"]
    assert data["findings"][0]["code"] == "pdf_javascript"
    assert data["findings"][0]["explanation"]
    assert data["findings"][0]["recommendation"]
    assert "analyzer" not in data


def test_incomplete_report_is_not_reported_safe():
    data = report_json.report_to_dict(_report(complete=False, risk="unknown", warnings=("Unsupported.",)))
    assert data["scan_complete"] is False
    assert data["needs_review"] is True
    assert data["risk_level"] == "unknown"
    assert data["warnings"] == ["Unsupported."]


def test_order_is_preserved_and_input_is_not_mutated():
    findings = (SecurityFinding("a", "low", "A"), SecurityFinding("b", "medium", "B"))
    source = _report(findings=findings, risk="medium", warnings=("First", "Second"))
    data = report_json.report_to_dict(source)
    assert [f["code"] for f in data["findings"]] == ["a", "b"]
    assert data["warnings"] == ["First", "Second"]
    data["findings"].clear()
    assert len(source.findings) == 2


def test_json_is_valid_and_deterministic():
    source = _report()
    first = report_json.report_to_json(source)
    assert first == report_json.report_to_json(source)
    assert json.loads(first) == report_json.report_to_dict(source)


def test_unicode_and_compact_output():
    source = _report(warnings=("Échec — проверка",))
    output = report_json.report_to_json(source, indent=None)
    assert "проверка" in output
    assert "\n" not in output
    assert json.loads(output)["warnings"] == ["Échec — проверка"]


@pytest.mark.parametrize("invalid", [None, {}, "report", 123])
def test_invalid_input_rejected(invalid):
    with pytest.raises(TypeError, match="Expected SecurityReport or ExplainedReport"):
        report_json.report_to_dict(invalid)


def test_scan_file_json_uses_existing_pipeline(monkeypatch, tmp_path):
    target = tmp_path / "sample.pdf"
    calls = []
    def fake_scan(path):
        calls.append(path)
        return _report()
    monkeypatch.setattr(report_json, "scan_file", fake_scan)
    output = json.loads(report_json.scan_file_json(target))
    assert calls == [target]
    assert output["report_type"] == "explained"
    assert "does not prove" in output["summary"]
    assert not target.exists()


def test_scan_file_json_raw_mode(monkeypatch, tmp_path):
    monkeypatch.setattr(report_json, "scan_file", lambda _: _report())
    output = json.loads(report_json.scan_file_json(tmp_path / "sample", explained=False))
    assert output["report_type"] == "security"


def test_scan_file_json_real_unknown_file(tmp_path):
    target = tmp_path / "unknown.bin"
    target.write_bytes(b"not a recognized file format")
    output = json.loads(report_json.scan_file_json(target))
    assert output["risk_level"] == "unknown"
    assert output["scan_complete"] is False
    assert output["needs_review"] is True


def test_scan_file_json_real_pdf(tmp_path):
    target = tmp_path / "sample.bin"
    target.write_bytes(b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n")
    output = json.loads(report_json.scan_file_json(target))
    assert output["file_type"] == "pdf"
    assert output["scan_complete"] is True
    assert output["risk_level"] == "informational"
    assert "does not prove" in output["summary"]


def test_scan_file_json_propagates_errors(monkeypatch, tmp_path):
    def fail(_):
        raise ValueError("Invalid file path.")
    monkeypatch.setattr(report_json, "scan_file", fail)
    with pytest.raises(ValueError, match="Invalid file path"):
        report_json.scan_file_json(tmp_path / "missing")
