"""Read-only file analysis dispatcher for RavShield.

Format detection uses file signatures and ZIP package members, not extensions.
Results are heuristic findings, never a malware/safety verdict.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
from zipfile import BadZipFile, ZipFile

from ravshield.intel.file.validator import validate_file
from ravshield.intel.file.pdf import analyze_pdf
from ravshield.intel.file.office import analyze_office
from ravshield.intel.file.pe import analyze_pe
from ravshield.intel.file.archive import (
    inspect_zip,
    analyze_archive_size_risk,
    find_suspicious_archive_files,
    find_nested_archives,
    find_encrypted_archive_files,
)

MAX_ZIP_DISPATCH_ENTRIES = 4096


@dataclass(frozen=True, slots=True)
class FileAnalysisResult:
    file_type: str
    analyzer: str | None
    details: Any | None
    warnings: tuple[str, ...] = ()


def _zip_is_ooxml(path: Path) -> bool:
    """Identify a recognizable OOXML package using ZIP directory metadata."""
    with ZipFile(path) as archive:
        entries = archive.infolist()
        if len(entries) > MAX_ZIP_DISPATCH_ENTRIES:
            raise ValueError("ZIP archive has too many entries for dispatch.")
        names = {entry.filename.lower() for entry in entries}
        return "[content_types].xml" in names and bool(
            {"word/document.xml", "xl/workbook.xml", "ppt/presentation.xml"} & names
        )


def analyze_file(file_path: str | Path) -> FileAnalysisResult:
    """Dispatch PDF, PE, OOXML and ZIP files to existing RavShield analyzers.

    Never executes files, extracts archives, or follows external links.
    Raises ValueError for missing files or invalid ZIP metadata.
    """
    if not validate_file(file_path):
        raise ValueError("Invalid file path.")

    path = Path(file_path).expanduser()
    with path.open("rb") as stream:
        signature = stream.read(8)

    if signature.startswith(b"%PDF-"):
        return FileAnalysisResult("pdf", "pdf", analyze_pdf(path))

    if signature.startswith(b"MZ"):
        # A DOS MZ header alone is not proof of a valid PE executable.
        try:
            details = analyze_pe(path)
        except (ValueError, OSError, EOFError, IndexError, KeyError) as exc:
            return FileAnalysisResult(
                "pe_candidate", "pe", None,
                (f"PE analysis incomplete: {type(exc).__name__}.",),
            )
        return FileAnalysisResult("pe", "pe", details)

    if signature.startswith(b"PK\x03\x04") or signature.startswith(b"PK\x05\x06"):
        try:
            if _zip_is_ooxml(path):
                result = analyze_office(path)
                return FileAnalysisResult(result.file_type or "office", "office", result)
            inspection = inspect_zip(path)
            risk = analyze_archive_size_risk(path)
            details = {
                "inspection": inspection,
                "size_risk": risk,
                "suspicious_filenames": find_suspicious_archive_files(inspection.filenames),
                "nested_archives": find_nested_archives(inspection.filenames),
                "encrypted_files": find_encrypted_archive_files(path),
            }
            return FileAnalysisResult("zip", "archive", details)
        except BadZipFile as exc:
            raise ValueError("Invalid ZIP archive.") from exc

    return FileAnalysisResult(
        "unknown", None, None,
        ("No supported file signature detected.",),
    )
