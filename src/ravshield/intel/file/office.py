"""Bounded, read-only heuristic inspection of OOXML Office packages."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from xml.etree import ElementTree
from zipfile import BadZipFile, ZipFile

from ravshield.intel.file.validator import validate_file

MAX_OFFICE_FILE_SIZE = 50 * 1024 * 1024
MAX_OFFICE_ENTRIES = 4096
MAX_OFFICE_UNCOMPRESSED_SIZE = 100 * 1024 * 1024
MAX_RELATIONSHIP_BYTES = 2 * 1024 * 1024
MAX_COMPRESSION_RATIO = 1000


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
    has_activex: bool = False
    has_ole_objects: bool = False
    has_vba_project: bool = False


def _unsafe_zip_path(name: str) -> bool:
    if not name or name.startswith(("/", "\\")) or "\\" in name:
        return True
    segments = name.split("/")
    return any(segment in (".", "..") for segment in segments)


def _has_external_relationship(xml_bytes: bytes) -> bool:
    root = ElementTree.fromstring(xml_bytes)
    for element in root.iter():
        if element.tag.split("}")[-1] != "Relationship":
            continue
        if any(
            key.split("}")[-1] == "TargetMode" and value.lower() == "external"
            for key, value in element.attrib.items()
        ):
            return True
    return False


def analyze_office(file_path: str | Path) -> OfficeAnalysisResult:
    """Inspect an Office ZIP container without extracting or executing content.

    Raises ValueError on invalid paths, oversized archives or malformed ZIPs.
    Findings are indicators, not a malware verdict.
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
            # OOXML package member names are indicators, not proof of execution.
            has_vba_project = any(
                name.rsplit("/", 1)[-1] == "vbaproject.bin"
                for name in names
            )
            has_activex = any(
                name.startswith(("word/activex/", "xl/activex/", "ppt/activex/"))
                for name in names
            )
            has_ole_objects = any(
                "/embeddings/" in f"/{name}"
                and name.rsplit("/", 1)[-1].startswith("oleobject")
                and name.endswith(".bin")
                for name in names
            )
            encrypted = any(bool(item.flag_bits & 0x1) for item in entries)
            has_external_relationships = False
            warnings: list[str] = []

            if any(_unsafe_zip_path(item.filename) for item in entries):
                warnings.append("Potentially unsafe ZIP entry path detected.")

            normalized_names = [item.filename.lower() for item in entries]
            if len(normalized_names) != len(set(normalized_names)):
                warnings.append("Duplicate ZIP entry names detected.")

            if any(
                item.file_size > 0
                and (
                    item.compress_size == 0
                    or item.file_size / item.compress_size > MAX_COMPRESSION_RATIO
                )
                for item in entries
            ):
                warnings.append("High ZIP compression ratio detected.")

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
                    if len(content) > MAX_RELATIONSHIP_BYTES:
                        warnings.append("Relationship part exceeds scan limit.")
                        continue
                    if _has_external_relationship(content):
                        has_external_relationships = True
                except ElementTree.ParseError:
                    warnings.append("Malformed relationship XML not inspected.")
                except (RuntimeError, BadZipFile, OSError, ValueError, NotImplementedError) as exc:
                    warnings.append(
                        f"Relationship part unreadable: {type(exc).__name__}."
                    )

            if not is_ooxml:
                warnings.append(
                    "Not a recognized OOXML Word, Excel, or PowerPoint package."
                )
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
                has_activex=has_activex,
                has_ole_objects=has_ole_objects,
                has_vba_project=has_vba_project,
            )
    except BadZipFile as exc:
        raise ValueError("Invalid Office ZIP container.") from exc
