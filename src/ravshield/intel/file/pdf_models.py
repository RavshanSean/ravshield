from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PDFAnalysisResult:
    """Structured results of PDF security checks."""

    is_pdf: bool
    version: str | None
    has_eof_marker: bool
    has_javascript: bool
    has_dangerous_actions: bool
    has_embedded_files: bool
    has_external_links: bool
    has_submit_form: bool