"""Bounded, read-only inspection of OOXML Office documents.

This is a ZIP-container heuristic scanner, not a malware verdict or a
complete OOXML parser. It never extracts files or executes document content.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from zipfile import BadZipFile, ZipFile

from ravshield.intel.file.validator import validate_file

MAX_OFFICE_FILE_SIZE = 50 * 1024 * 1024
MAX_OFFICE_ENTRIES = 4096
MAX_OFFICE_UNCOMPRESSED_SIZE = 100 * 1024 * 1024
MAX_RELATIONSHIP_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class OfficeAnalysisResult:
    file_type: str | None
    is_ooxml: bool
    has_macros: bool
    has_embedded_objects: bool
    has_external_relationships: bool
    encrypted: bool
    entry_count: int
    warnings: tuple[str, ...]


def analyze_office(file_path: str | Path) -> OfficeAnalysisResult:
    """Inspect an OOXML package without unpacking it onto disk.

    Raises ValueError for invalid paths, oversized packages, and malformed ZIPs.
    Encrypted entries are reported but not decrypted. External relationship
    detection scans bounded relationship XML bytes and may have false positives.
    """
    if not validate_file(file_path):
        raise ValueError("Invalid file path.")

    path = Path(file_path).expanduser()
    if path.stat().st_size > MAX_OFFICE_FILE_SIZE:
        raise ValueError("Office file exceeds maximum scan size.")

    try:
        with ZipFile(path) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_OFFICE_ENTRIES:
                raise ValueError("Office archive has too many entries.")
            if sum(item.file_size for item in entries) > MAX_OFFICE_UNCOMPRESSED_SIZE:
                raise ValueError("Office archive exceeds uncompressed size limit.")

            names = {item.filename.lower() for item in entries}
            file_type = None
            if "word/document.xml" in names:
                file_type = "docx"
            elif "xl/workbook.xml" in names:
                file_type = "xlsx"
            elif "ppt/presentation.xml" in names:
                file_type = "pptx"

            is_ooxml = file_type is not None and "[content_types].xml" in names
            has_macros = any(name.endswith("vbaproject.bin") for name in names)
            has_embedded_objects = any(
                "/embeddings/" in f"/{name}" or name.startswith("embeddings/")
                for name in names
            )
            encrypted = any(bool(item.flag_bits & 0x1) for item in entries)
            has_external_relationships = False
            warnings: list[str] = []

            for item in entries:
                if not item.filename.lower().endswith(".rels"):
                    continue
                if item.file_size > MAX_RELATIONSHIP_BYTES:
                    warnings.append("Relationship part exceeds scan limit.")
                    continue
                if item.flag_bits & 0x1:
                    warnings.append("Encrypted relationship part not inspected.")
                    continue
                try:
                    with archive.open(item) as part:
                        content = part.read(MAX_RELATIONSHIP_BYTES + 1)
                except (RuntimeError, BadZipFile, OSError, ValueError) as exc:
                    warnings.append(f"Relationship part unreadable: {type(exc).__name__}.")
                    continue
                # XML attribute values may use either quote style or whitespace.
                import re
                if re.search(rb'\bTargetMode\s*=\s*[\"\']External[\"\']', content, re.I):
                    has_external_relationships = True

            if not is_ooxml:
                warnings.append("Not a recognized OOXML Word, Excel, or PowerPoint package.")
            if encrypted:
                warnings.append("Encrypted ZIP entries were not inspected.")

            return OfficeAnalysisResult(
                file_type=file_type,
                is_ooxml=is_ooxml,
                has_macros=has_macros,
                has_embedded_objects=has_embedded_objects,
                has_external_relationships=has_external_relationships,
                encrypted=encrypted,
                entry_count=len(entries),
                warnings=tuple(warnings),
            )
    except BadZipFile as exc:
        raise ValueError("Invalid Office ZIP container.") from exc
