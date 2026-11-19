"""Regression tests for RavShield's conservative security report layer.

All test inputs are inert synthetic data. These tests do not run executables,
extract archives, access the network, or assert that a file is safe.
"""
from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path
from types import SimpleNamespace
from zipfile import ZipFile

import pytest

from ravshield.intel.file.pipeline import FileAnalysisResult
from ravshield.intel.file.pdf_models import PDFAnalysisResult
from ravshield.intel.file.office import OfficeAnalysisResult
from ravshield.intel.file import report


def _result(analyzer, details, *, file_type="sample", warnings=()):
    return FileAnalysisResult(file_type, analyzer, details, tuple(warnings))


def _pdf(**overrides):
    values = dict(
        is_pdf=True, version="1.7", has_eof_marker=True,
        has_javascript=False, has_dangerous_actions=False,
        has_embedded_files=False, has_external_links=False,
        has_submit_form=False,
    )
    values.update(overrides)
    return PDFAnalysisResult(**values)


def _office(**overrides):
    values = dict(
        file_type="docx", is_ooxml=True, has_macros=False,
        has_embedded_objects=False, has_external_relationships=False,
        encrypted=False, entry_count=2, warnings=(),
        has_activex=False, has_ole_objects=False, has_vba_project=False,
    )
    values.update(overrides)
    return OfficeAnalysisResult(**values)


def _codes(security_report):
    return {finding.code for finding in security_report.findings}


def test_clean_pdf_is_informational_not_a_safety_verdict():
    result = report.build_security_report(_result("pdf", _pdf(), file_type="pdf"))
    assert result.file_type == "pdf"
    assert result.analyzer == "pdf"
    assert result.risk_level == "informational"
    assert result.findings == ()
    assert result.warnings == ()
    assert result.scan_complete is True
    assert result.needs_review is False


@pytest.mark.parametrize("attribute,code,severity", [
    ("has_javascript", "pdf_javascript", "high"),
    ("has_dangerous_actions", "pdf_actions", "high"),
    ("has_embedded_files", "pdf_embedded", "medium"),
    ("has_external_links", "pdf_links", "low"),
    ("has_submit_form", "pdf_submit", "medium"),
])
def test_pdf_individual_indicators(attribute, code, severity):
    result = report.build_security_report(_result("pdf", _pdf(**{attribute: True})))
    assert result.risk_level == severity
    assert result.scan_complete is True
    assert len(result.findings) == 1
    assert result.findings[0].code == code
    assert result.findings[0].severity == severity
    assert result.findings[0].description
    assert result.needs_review is True


def test_pdf_highest_severity_wins_and_findings_keep_order():
    details = _pdf(has_external_links=True, has_embedded_files=True,
                   has_javascript=True, has_submit_form=True)
    result = report.build_security_report(_result("pdf", details))
    assert result.risk_level == "high"
    assert [finding.code for finding in result.findings] == [
        "pdf_javascript", "pdf_embedded", "pdf_links", "pdf_submit"
    ]


def test_pdf_missing_eof_and_version_add_warnings_but_not_risk():
    result = report.build_security_report(_result(
        "pdf", _pdf(has_eof_marker=False, version=None)
    ))
    assert result.risk_level == "informational"
    assert result.scan_complete is True
    assert "PDF EOF marker was not detected." in result.warnings
    assert "PDF version header could not be validated." in result.warnings


def test_unrecognized_pdf_is_incomplete_and_unknown():
    result = report.build_security_report(_result("pdf", _pdf(is_pdf=False)))
    assert result.risk_level == "unknown"
    assert result.scan_complete is False
    assert result.needs_review is True
    assert any("incomplete" in warning.lower() for warning in result.warnings)


@pytest.mark.parametrize("attribute,code,severity", [
    ("has_macros", "office_macros", "high"),
    ("has_activex", "office_activex", "high"),
    ("has_vba_project", "office_vba", "high"),
    ("has_ole_objects", "office_ole", "medium"),
    ("has_embedded_objects", "office_embedded", "medium"),
    ("has_external_relationships", "office_external", "medium"),
    ("encrypted", "office_encrypted", "medium"),
])
def test_office_individual_indicators(attribute, code, severity):
    result = report.build_security_report(_result("office", _office(**{attribute: True})))
    assert result.risk_level == severity
    assert result.scan_complete is True
    assert _codes(result) == {code}
    assert result.findings[0].severity == severity


def test_office_clean_document_is_informational():
    result = report.build_security_report(_result("office", _office(), file_type="docx"))
    assert result.risk_level == "informational"
    assert result.scan_complete is True
    assert result.needs_review is False


def test_office_combined_indicators_and_warnings_are_preserved():
    details = _office(has_macros=True, has_ole_objects=True,
                      warnings=("Relationship part exceeds scan limit.",))
    result = report.build_security_report(_result(
        "office", details, warnings=("Pipeline warning.",)
    ))
    assert result.risk_level == "high"
    assert _codes(result) == {"office_macros", "office_ole"}
    assert result.warnings == (
        "Pipeline warning.", "Relationship part exceeds scan limit."
    )


def test_office_unrecognized_package_is_incomplete():
    result = report.build_security_report(_result("office", _office(is_ooxml=False)))
    assert result.scan_complete is False
    assert result.risk_level == "unknown"


def _archive(**overrides):
    details = dict(
        inspection=SimpleNamespace(file_count=1),
        size_risk=SimpleNamespace(signals=()),
        suspicious_filenames=[], nested_archives=[], encrypted_files=[],
    )
    details.update(overrides)
    return details


def test_clean_archive_is_informational():
    result = report.build_security_report(_result("archive", _archive(), file_type="zip"))
    assert result.scan_complete is True
    assert result.risk_level == "informational"
    assert result.findings == ()


@pytest.mark.parametrize("field,code,severity", [
    ("suspicious_filenames", "archive_names", "medium"),
    ("nested_archives", "archive_nested", "low"),
    ("encrypted_files", "archive_encrypted", "medium"),
])
def test_archive_member_indicators(field, code, severity):
    result = report.build_security_report(_result(
        "archive", _archive(**{field: ["example.bin"]})
    ))
    assert result.scan_complete is True
    assert result.risk_level == severity
    assert _codes(result) == {code}


def test_archive_size_risk_signals_are_high_and_sorted():
    details = _archive(size_risk=SimpleNamespace(signals=("zeta", "alpha")))
    result = report.build_security_report(_result("archive", details))
    assert result.risk_level == "high"
    assert [finding.code for finding in result.findings] == [
        "archive_alpha", "archive_zeta"
    ]
    assert all(finding.severity == "high" for finding in result.findings)


def test_archive_missing_required_keys_is_incomplete():
    result = report.build_security_report(_result("archive", {"inspection": object()}))
    assert result.scan_complete is False
    assert result.risk_level == "unknown"


def test_archive_findings_can_coexist_with_incomplete_analysis():
    result = report.build_security_report(_result(
        "archive", {"suspicious_filenames": ["invoice.pdf.exe"]}
    ))
    assert result.scan_complete is False
    assert result.risk_level == "medium"
    assert "archive_names" in _codes(result)
    assert result.needs_review is True


def _pe(sections=()):
    return {"header": {}, "sections": list(sections), "imports": {}}


def test_pe_clean_sections_are_informational():
    result = report.build_security_report(_result("pe", _pe([{
        "characteristics": 0x20000000, "entropy": 5.0
    }])))
    assert result.risk_level == "informational"
    assert result.scan_complete is True


def test_pe_writable_and_executable_section_is_high():
    result = report.build_security_report(_result("pe", _pe([{
        "characteristics": 0x20000000 | 0x80000000, "entropy": 5.0
    }])))
    assert result.risk_level == "high"
    assert _codes(result) == {"pe_writable_executable"}


@pytest.mark.parametrize("entropy,expected", [
    (7.49, "informational"), (7.5, "medium"), (8.0, "medium")
])
def test_pe_entropy_threshold(entropy, expected):
    result = report.build_security_report(_result("pe", _pe([{"entropy": entropy}])))
    assert result.risk_level == expected
    assert ("pe_high_entropy" in _codes(result)) == (expected == "medium")


def test_pe_combined_findings_use_highest_severity():
    result = report.build_security_report(_result("pe", _pe([{
        "characteristics": 0xA0000000, "entropy": 7.9
    }])))
    assert result.risk_level == "high"
    assert _codes(result) == {"pe_writable_executable", "pe_high_entropy"}


def test_pe_duplicate_section_indicators_are_deduplicated():
    result = report.build_security_report(_result("pe", _pe([
        {"entropy": 7.6}, {"entropy": 7.8}
    ])))
    assert [finding.code for finding in result.findings] == ["pe_high_entropy"]


def test_pe_non_dict_sections_are_ignored():
    result = report.build_security_report(_result("pe", _pe([None, "bad", 123])))
    assert result.scan_complete is True
    assert result.findings == ()


def test_pe_missing_required_keys_is_incomplete():
    result = report.build_security_report(_result("pe", {"sections": []}))
    assert result.scan_complete is False
    assert result.risk_level == "unknown"


def test_unknown_format_preserves_warnings_and_requires_review():
    result = report.build_security_report(_result(
        None, None, file_type="unknown",
        warnings=("No supported file signature detected.",)
    ))
    assert result.file_type == "unknown"
    assert result.analyzer is None
    assert result.risk_level == "unknown"
    assert result.scan_complete is False
    assert result.needs_review is True
    assert result.warnings[0] == "No supported file signature detected."


def test_missing_details_is_incomplete_even_with_named_analyzer():
    result = report.build_security_report(_result("pe", None, file_type="pe_candidate"))
    assert result.risk_level == "unknown"
    assert result.scan_complete is False


def test_duplicate_warnings_are_removed_without_reordering():
    result = report.build_security_report(_result(
        None, None, warnings=("Repeated.", "Other.", "Repeated.")
    ))
    assert result.warnings[:2] == ("Repeated.", "Other.")
    assert result.warnings.count("Repeated.") == 1


def test_security_report_and_finding_are_immutable():
    result = report.build_security_report(_result("pdf", _pdf(has_external_links=True)))
    with pytest.raises(FrozenInstanceError):
        result.risk_level = "high"
    with pytest.raises(FrozenInstanceError):
        result.findings[0].severity = "high"


def test_scan_file_calls_pipeline_and_builds_report(monkeypatch, tmp_path):
    file_path = tmp_path / "sample.pdf"
    expected = _result("pdf", _pdf(has_javascript=True), file_type="pdf")
    seen = []
    def fake_analyze_file(path):
        seen.append(path)
        return expected
    monkeypatch.setattr(report, "analyze_file", fake_analyze_file)
    result = report.scan_file(file_path)
    assert seen == [file_path]
    assert result.file_type == "pdf"
    assert result.risk_level == "high"
    assert "pdf_javascript" in _codes(result)


def test_scan_file_propagates_pipeline_errors(monkeypatch, tmp_path):
    def fail(_path):
        raise ValueError("Invalid file path.")
    monkeypatch.setattr(report, "analyze_file", fail)
    with pytest.raises(ValueError, match="Invalid file path"):
        report.scan_file(tmp_path / "missing.pdf")


def test_scan_file_integration_with_real_pdf(tmp_path):
    path = tmp_path / "document.bin"
    path.write_bytes(b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n")
    result = report.scan_file(path)
    assert result.file_type == "pdf"
    assert result.analyzer == "pdf"
    assert result.scan_complete is True
    assert result.risk_level == "informational"


def test_scan_file_integration_with_real_zip(tmp_path):
    path = tmp_path / "sample.bin"
    with ZipFile(path, "w") as archive:
        archive.writestr("readme.txt", "harmless synthetic fixture")
    result = report.scan_file(path)
    assert result.file_type == "zip"
    assert result.analyzer == "archive"
    assert result.scan_complete is True
    assert result.risk_level == "informational"


def test_scan_file_integration_with_unknown_format(tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("No recognized signature.", encoding="utf-8")
    result = report.scan_file(path)
    assert result.file_type == "unknown"
    assert result.risk_level == "unknown"
    assert result.scan_complete is False
