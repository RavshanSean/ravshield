"""Tests for the presentation-only security report explanation layer."""
from dataclasses import FrozenInstanceError

import pytest

from ravshield.intel.file.report import SecurityFinding, SecurityReport
from ravshield.intel.file.report_explain import explain_security_report


def _report(*findings, risk="informational", complete=True, warnings=()):
    return SecurityReport("pdf", "pdf", risk, tuple(findings), tuple(warnings), complete)


@pytest.mark.parametrize("code", [
    "pdf_javascript", "pdf_actions", "pdf_embedded", "pdf_links", "pdf_submit",
    "office_macros", "office_activex", "office_vba", "office_ole",
    "office_embedded", "office_external", "office_encrypted",
    "archive_names", "archive_nested", "archive_encrypted",
    "pe_writable_executable", "pe_high_entropy",
])
def test_known_findings_have_explanations_and_actions(code):
    result = explain_security_report(_report(SecurityFinding(code, "medium", "Original."), risk="medium"))
    assert result.findings[0].code == code
    assert result.findings[0].explanation
    assert result.findings[0].recommendation
    assert result.risk_level == "medium"


def test_unknown_finding_falls_back_to_original_description():
    result = explain_security_report(_report(SecurityFinding("future_rule", "low", "Future detection."), risk="low"))
    assert result.findings[0].explanation == "Future detection."
    assert result.findings[0].recommendation


def test_archive_size_signal_has_specific_fallback():
    result = explain_security_report(_report(SecurityFinding("archive_ratio", "high", "ZIP size risk: ratio."), risk="high"))
    assert "ZIP size risk" in result.findings[0].explanation
    assert "decompression" in result.findings[0].recommendation


def test_clean_report_never_claims_safe():
    result = explain_security_report(_report())
    assert "does not prove" in result.summary
    assert result.findings == ()
    assert not result.needs_review


def test_incomplete_scan_preserves_warnings_and_review():
    result = explain_security_report(_report(complete=False, risk="unknown", warnings=("Unsupported format.",)))
    assert result.scan_complete is False
    assert result.needs_review is True
    assert result.warnings == ("Unsupported format.",)
    assert "incomplete" in result.summary.lower()


def test_findings_keep_order_and_severity():
    findings = (SecurityFinding("pdf_links", "low", "Links."), SecurityFinding("pdf_javascript", "high", "JS."))
    result = explain_security_report(_report(*findings, risk="high"))
    assert [(f.code, f.severity) for f in result.findings] == [("pdf_links", "low"), ("pdf_javascript", "high")]
    assert result.risk_level == "high"


def test_explained_report_is_immutable():
    result = explain_security_report(_report())
    with pytest.raises(FrozenInstanceError):
        result.summary = "Safe"


def test_invalid_input_rejected():
    with pytest.raises(TypeError):
        explain_security_report(None)
