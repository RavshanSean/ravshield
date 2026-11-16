"""Bounded, non-executing heuristic checks for PDF candidates.

These checks are not a PDF parser and do not determine whether a file is safe.
"""
from __future__ import annotations

import re
from pathlib import Path

from ravshield.intel.file.pdf_models import PDFAnalysisResult
from ravshield.intel.file.validator import validate_file

PDF_SIGNATURE = b"%PDF-"
MAX_PDF_SCAN_SIZE = 50 * 1024 * 1024

# A PDF name ends at whitespace or a PDF delimiter. This is still a byte-level
# heuristic: comments, streams, and encoded names are not parsed.
_PDF_NAME_END = rb"(?=[\x00\x09\x0a\x0c\x0d\x20()<>{}\[\]/%]|$)"
PDF_JS_NAME_PATTERN = re.compile(rb"/(?:JavaScript|JS)" + _PDF_NAME_END)
PDF_DANGEROUS_ACTION_PATTERN = re.compile(rb"/(?:OpenAction|Launch|AA)" + _PDF_NAME_END)
PDF_EMBEDDED_FILE_PATTERN = re.compile(rb"/(?:EmbeddedFile|EmbeddedFiles)" + _PDF_NAME_END)
PDF_URI_PATTERN = re.compile(rb"/URI" + _PDF_NAME_END)
PDF_SUBMIT_FORM_PATTERN = re.compile(rb"/SubmitForm" + _PDF_NAME_END)


def read_pdf_safely(
    file_path: str | Path, max_size: int = MAX_PDF_SCAN_SIZE
) -> bytes:
    """Read at most max_size + 1 bytes, rejecting oversized inputs."""
    if not isinstance(max_size, int) or isinstance(max_size, bool) or max_size <= 0:
        raise ValueError("Invalid PDF size limit.")
    if not validate_file(file_path):
        raise ValueError("Invalid file path.")
    path = Path(file_path).expanduser()
    with path.open("rb") as file:
        data = file.read(max_size + 1)
    if len(data) > max_size:
        raise ValueError("PDF exceeds maximum scan size.")
    return data


def _pdf_version(data: bytes) -> str:
    header = data[:8]
    if (
        len(header) != 8
        or not header.startswith(PDF_SIGNATURE)
        or header[5:6] not in (b"1", b"2")
        or header[6:7] != b"."
        or not header[7:8].isdigit()
    ):
        raise ValueError("Invalid PDF version header.")
    return header[5:8].decode("ascii")


def has_pdf_signature(file_path: str | Path) -> bool:
    """Check the first five bytes without reading the whole file."""
    if not validate_file(file_path):
        raise ValueError("Invalid file path.")
    with Path(file_path).expanduser().open("rb") as file:
        return file.read(len(PDF_SIGNATURE)) == PDF_SIGNATURE


def get_pdf_version(file_path: str | Path) -> str:
    """Read a basic PDF header version, without structural validation."""
    if not validate_file(file_path):
        raise ValueError("Invalid file path.")
    with Path(file_path).expanduser().open("rb") as file:
        return _pdf_version(file.read(8))


def has_pdf_eof_marker(file_path: str | Path) -> bool:
    """Check for %%EOF in the final 1024 bytes."""
    if not validate_file(file_path):
        raise ValueError("Invalid file path.")
    with Path(file_path).expanduser().open("rb") as file:
        file.seek(0, 2)
        size = file.tell()
        file.seek(-min(size, 1024), 2)
        return b"%%EOF" in file.read(1024)


def has_pdf_javascript(file_path: str | Path) -> bool:
    return PDF_JS_NAME_PATTERN.search(read_pdf_safely(file_path)) is not None


def has_pdf_dangerous_actions(file_path: str | Path) -> bool:
    return PDF_DANGEROUS_ACTION_PATTERN.search(read_pdf_safely(file_path)) is not None


def has_pdf_embedded_files(file_path: str | Path) -> bool:
    return PDF_EMBEDDED_FILE_PATTERN.search(read_pdf_safely(file_path)) is not None


def has_pdf_external_links(file_path: str | Path) -> bool:
    return PDF_URI_PATTERN.search(read_pdf_safely(file_path)) is not None


def has_pdf_submit_form(file_path: str | Path) -> bool:
    return PDF_SUBMIT_FORM_PATTERN.search(read_pdf_safely(file_path)) is not None


def analyze_pdf(file_path: str | Path) -> PDFAnalysisResult:
    """Scan once and return independent heuristic indicators.

    Non-PDF files return is_pdf=False with no inferred findings. A PDF
    signature with an invalid version keeps is_pdf=True and version=None.
    """
    data = read_pdf_safely(file_path)
    is_pdf = data.startswith(PDF_SIGNATURE)
    if not is_pdf:
        return PDFAnalysisResult(
            is_pdf=False,
            version=None,
            has_eof_marker=False,
            has_javascript=False,
            has_dangerous_actions=False,
            has_embedded_files=False,
            has_external_links=False,
            has_submit_form=False,
        )
    try:
        version = _pdf_version(data)
    except ValueError:
        version = None
    return PDFAnalysisResult(
        is_pdf=True,
        version=version,
        has_eof_marker=b"%%EOF" in data[-1024:],
        has_javascript=PDF_JS_NAME_PATTERN.search(data) is not None,
        has_dangerous_actions=PDF_DANGEROUS_ACTION_PATTERN.search(data) is not None,
        has_embedded_files=PDF_EMBEDDED_FILE_PATTERN.search(data) is not None,
        has_external_links=PDF_URI_PATTERN.search(data) is not None,
        has_submit_form=PDF_SUBMIT_FORM_PATTERN.search(data) is not None,
    )
