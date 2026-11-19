"""Human-readable, conservative explanations for RavShield security reports.

This module is presentation-only: it never scans, opens, or executes files.
It deliberately does not turn heuristic findings into malware verdicts.
"""
from __future__ import annotations

from dataclasses import dataclass

from ravshield.intel.file.report import SecurityReport


@dataclass(frozen=True, slots=True)
class ExplainedFinding:
    code: str
    severity: str
    explanation: str
    recommendation: str


@dataclass(frozen=True, slots=True)
class ExplainedReport:
    file_type: str
    risk_level: str
    summary: str
    findings: tuple[ExplainedFinding, ...]
    warnings: tuple[str, ...]
    scan_complete: bool
    needs_review: bool


_EXPLANATIONS: dict[str, tuple[str, str]] = {
    "pdf_javascript": ("JavaScript indicators were found in the PDF. Scripts can be legitimate but deserve review.", "Inspect the PDF in a controlled environment before trusting its active content."),
    "pdf_actions": ("The PDF contains action indicators that may trigger behavior when opened.", "Review document actions before opening it in a normal viewer."),
    "pdf_embedded": ("The PDF appears to contain embedded files.", "Inspect embedded attachments separately before opening them."),
    "pdf_links": ("The PDF contains links to external locations.", "Verify links before following them."),
    "pdf_submit": ("The PDF contains form-submission indicators.", "Review the destination and data before submitting a form."),
    "office_macros": ("The Office document contains macro indicators. Macros may automate tasks or run unwanted code.", "Do not enable macros unless the document and source are trusted."),
    "office_activex": ("The Office package contains ActiveX indicators.", "Review ActiveX components and avoid enabling untrusted active content."),
    "office_vba": ("A VBA project indicator was found in the Office package.", "Inspect the VBA project before enabling macros."),
    "office_ole": ("The Office package contains an OLE object indicator.", "Inspect embedded objects before opening or activating them."),
    "office_embedded": ("The Office document contains embedded objects.", "Check embedded objects separately before opening them."),
    "office_external": ("The Office document references external content.", "Verify external destinations before allowing connections."),
    "office_encrypted": ("Some Office ZIP members are encrypted and were not inspected.", "Treat the scan as limited and inspect encrypted content through an approved process."),
    "archive_names": ("An archive member has a suspicious-looking filename.", "Check the actual file type before opening archive members."),
    "archive_nested": ("The archive contains another archive by filename.", "Inspect nested archives separately before using their contents."),
    "archive_encrypted": ("The archive contains encrypted members that were not inspected.", "Do not assume encrypted contents are safe; arrange an authorized inspection."),
    "pe_writable_executable": ("A Windows executable has a section marked both writable and executable.", "Review the executable with additional trusted analysis tools."),
    "pe_high_entropy": ("A Windows executable section has unusually high randomness, which can have benign or suspicious causes.", "Investigate packing or encryption indicators; entropy alone does not establish malware."),
}


def explain_security_report(report: SecurityReport) -> ExplainedReport:
    """Explain existing findings without changing their risk or completeness."""
    if not isinstance(report, SecurityReport):
        raise TypeError("Expected a SecurityReport.")

    explained: list[ExplainedFinding] = []
    for finding in report.findings:
        explanation, recommendation = _EXPLANATIONS.get(
            finding.code,
            (finding.description or "An indicator requires further review.",
             "Review this finding with additional context before drawing conclusions."),
        )
        if finding.code.startswith("archive_") and finding.code not in _EXPLANATIONS:
            explanation = finding.description or "An archive size-risk indicator was detected."
            recommendation = "Check archive size and decompression limits before processing it."
        explained.append(ExplainedFinding(finding.code, finding.severity, explanation, recommendation))

    if not report.scan_complete:
        summary = "Analysis was incomplete. The reported indicators are not a safety verdict."
    elif report.risk_level == "informational":
        summary = "No configured suspicious indicators were reported. This does not prove the file is safe."
    else:
        summary = f"The scan reported {len(report.findings)} indicator(s); highest triage level: {report.risk_level}. This is not a malware verdict."

    return ExplainedReport(
        file_type=report.file_type,
        risk_level=report.risk_level,
        summary=summary,
        findings=tuple(explained),
        warnings=report.warnings,
        scan_complete=report.scan_complete,
        needs_review=report.needs_review,
    )
