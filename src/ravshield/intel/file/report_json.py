"""Deterministic JSON export for existing RavShield security reports.

Serialization only: no scanning, file execution, or safety verdicts.
"""
from __future__ import annotations

import json
from pathlib import Path

from ravshield.intel.file.report import SecurityReport, scan_file
from ravshield.intel.file.report_explain import ExplainedReport, explain_security_report

SCHEMA_VERSION = "1.0"


def report_to_dict(report: SecurityReport | ExplainedReport) -> dict:
    """Convert a report into a JSON-compatible, versioned dictionary."""
    if isinstance(report, SecurityReport):
        return {
            "schema_version": SCHEMA_VERSION,
            "report_type": "security",
            "file_type": report.file_type,
            "analyzer": report.analyzer,
            "risk_level": report.risk_level,
            "scan_complete": report.scan_complete,
            "needs_review": report.needs_review,
            "findings": [
                {"code": f.code, "severity": f.severity, "description": f.description}
                for f in report.findings
            ],
            "warnings": list(report.warnings),
        }
    if isinstance(report, ExplainedReport):
        return {
            "schema_version": SCHEMA_VERSION,
            "report_type": "explained",
            "file_type": report.file_type,
            "risk_level": report.risk_level,
            "summary": report.summary,
            "scan_complete": report.scan_complete,
            "needs_review": report.needs_review,
            "findings": [
                {"code": f.code, "severity": f.severity,
                 "explanation": f.explanation, "recommendation": f.recommendation}
                for f in report.findings
            ],
            "warnings": list(report.warnings),
        }
    raise TypeError("Expected SecurityReport or ExplainedReport.")


def report_to_json(report: SecurityReport | ExplainedReport, *, indent: int | None = 2) -> str:
    """Serialize a report to UTF-8-ready JSON text without writing a file."""
    return json.dumps(report_to_dict(report), ensure_ascii=False, indent=indent, allow_nan=False)


def scan_file_json(file_path: str | Path, *, explained: bool = True, indent: int | None = 2) -> str:
    """Scan via the existing pipeline and return JSON text; no output file is written."""
    result = scan_file(file_path)
    if explained:
        result = explain_security_report(result)
    return report_to_json(result, indent=indent)
