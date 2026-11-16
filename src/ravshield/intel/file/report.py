"""Conservative, explainable summaries of RavShield file analysis findings.

This module does not certify files as safe or malicious. Risk levels are
triage priorities based on observable indicators, not probabilities.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ravshield.intel.file.pipeline import FileAnalysisResult, analyze_file


@dataclass(frozen=True, slots=True)
class SecurityFinding:
    code: str
    severity: str
    description: str


@dataclass(frozen=True, slots=True)
class SecurityReport:
    file_type: str
    analyzer: str | None
    risk_level: str
    findings: tuple[SecurityFinding, ...]
    warnings: tuple[str, ...]
    scan_complete: bool

    @property
    def needs_review(self) -> bool:
        return self.risk_level != "informational" or not self.scan_complete


def _add(findings: list[SecurityFinding], condition: Any, code: str,
         severity: str, description: str) -> None:
    if condition:
        findings.append(SecurityFinding(code, severity, description))


def build_security_report(result: FileAnalysisResult) -> SecurityReport:
    """Convert an existing analysis result into an actionable triage summary.

    Accepts the public FileAnalysisResult contract; never reads or executes files.
    Missing analysis or unsupported formats are explicitly marked incomplete.
    """
    findings: list[SecurityFinding] = []
    warnings = list(result.warnings)
    details = result.details
    complete = details is not None and result.analyzer is not None

    if result.analyzer == "pdf" and details is not None:
        complete = bool(getattr(details, "is_pdf", False))
        for attr, code, severity, label in (
            ("has_javascript", "pdf_javascript", "high", "PDF contains JavaScript indicators."),
            ("has_dangerous_actions", "pdf_actions", "high", "PDF contains action indicators."),
            ("has_embedded_files", "pdf_embedded", "medium", "PDF contains embedded-file indicators."),
            ("has_external_links", "pdf_links", "low", "PDF contains URI indicators."),
            ("has_submit_form", "pdf_submit", "medium", "PDF contains form-submission indicators."),
        ):
            _add(findings, getattr(details, attr, False), code, severity, label)
        if not getattr(details, "has_eof_marker", False):
            warnings.append("PDF EOF marker was not detected.")
        if getattr(details, "version", None) is None:
            warnings.append("PDF version header could not be validated.")

    elif result.analyzer == "office" and details is not None:
        complete = bool(getattr(details, "is_ooxml", False))
        for attr, code, severity, label in (
            ("has_macros", "office_macros", "high", "Office package contains macro indicators."),
            ("has_activex", "office_activex", "high", "Office package contains ActiveX indicators."),
            ("has_vba_project", "office_vba", "high", "Office package contains a VBA project indicator."),
            ("has_ole_objects", "office_ole", "medium", "Office package contains OLE object indicators."),
            ("has_embedded_objects", "office_embedded", "medium", "Office package contains embedded objects."),
            ("has_external_relationships", "office_external", "medium", "Office package contains external relationships."),
            ("encrypted", "office_encrypted", "medium", "Office package has encrypted ZIP entries."),
        ):
            _add(findings, getattr(details, attr, False), code, severity, label)
        warnings.extend(getattr(details, "warnings", ()))

    elif result.analyzer == "archive" and isinstance(details, dict):
        size_risk = details.get("size_risk")
        for signal in sorted(getattr(size_risk, "signals", ())):
            _add(findings, True, f"archive_{signal}", "high", f"ZIP size risk: {signal}.")
        _add(findings, bool(details.get("suspicious_filenames")), "archive_names", "medium",
             "ZIP contains suspicious filename extensions.")
        _add(findings, bool(details.get("nested_archives")), "archive_nested", "low",
             "ZIP contains nested archive filenames.")
        _add(findings, bool(details.get("encrypted_files")), "archive_encrypted", "medium",
             "ZIP contains encrypted members that were not inspected.")
        complete = all(k in details for k in (
            "inspection", "size_risk", "suspicious_filenames", "nested_archives", "encrypted_files"
        ))

    elif result.analyzer == "pe" and isinstance(details, dict):
        sections = details.get("sections", ())
        for section in sections if isinstance(sections, (list, tuple)) else ():
            if not isinstance(section, dict):
                continue
            flags = section.get("characteristics", 0)
            if isinstance(flags, int):
                _add(findings, bool(flags & 0x20000000 and flags & 0x80000000),
                     "pe_writable_executable", "high", "PE has a writable and executable section.")
            entropy = section.get("entropy")
            _add(findings, isinstance(entropy, (int, float)) and entropy >= 7.5,
                 "pe_high_entropy", "medium", "PE has a high-entropy section.")
        complete = "header" in details and "sections" in details and "imports" in details

    if not complete:
        warnings.append("Analysis incomplete or format unsupported; no safety conclusion possible.")

    # De-duplicate findings and warnings without losing original order.
    findings = list({finding.code: finding for finding in findings}.values())
    unique_warnings = tuple(dict.fromkeys(warnings))
    severities = {finding.severity for finding in findings}
    if "high" in severities:
        risk = "high"
    elif "medium" in severities:
        risk = "medium"
    elif "low" in severities:
        risk = "low"
    elif not complete:
        risk = "unknown"
    else:
        risk = "informational"
    return SecurityReport(result.file_type, result.analyzer, risk,
                          tuple(findings), unique_warnings, complete)


def scan_file(file_path: str | Path) -> SecurityReport:
    """Analyze a file and produce a conservative triage report."""
    return build_security_report(analyze_file(file_path))
