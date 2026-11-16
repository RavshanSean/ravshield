"""Result models for PDF heuristic scanning."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PDFAnalysisResult:
    """Independent indicators, not a verdict that a PDF is safe or malicious."""

    is_pdf: bool
    version: str | None
    has_eof_marker: bool
    has_javascript: bool
    has_dangerous_actions: bool
    has_embedded_files: bool
    has_external_links: bool
    has_submit_form: bool
