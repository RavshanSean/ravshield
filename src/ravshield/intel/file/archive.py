from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from zipfile import BadZipFile, ZipFile

from ravshield.intel.file.heuristics import (
    DECOY_EXTENSIONS,
    RISKY_EXTENSIONS,
)
from ravshield.intel.file.validator import validate_file

MAX_ARCHIVE_UNCOMPRESSED_SIZE = 500 * 1024 * 1024
MAX_ARCHIVE_COMPRESSION_RATIO = 100.0


@dataclass(slots=True)
class ArchiveInspectionResult:
    file_count: int
    filenames: list[str] = field(default_factory=list)
    
@dataclass(slots=True)
class ArchiveSizeRiskResult:
    compressed_size: int
    uncompressed_size: int
    compression_ratio: float
    signals: set[str] = field(default_factory=set)

    @property
    def suspicious(self) -> bool:
        return bool(self.signals)

def find_suspicious_archive_files(
    filenames: list[str],
) -> dict[str, set[str]]:
    """
    Find suspicious filenames stored inside an archive.

    These signals do not prove that the archived files are malicious.
    """

    suspicious: dict[str, set[str]] = {}

    for filename in filenames:
        path = PurePosixPath(filename)
        suffixes = [
            suffix.lower()
            for suffix in path.suffixes
        ]

        signals: set[str] = set()

        if suffixes and suffixes[-1] in RISKY_EXTENSIONS:
            signals.add("risky_extension")

        if (
            len(suffixes) >= 2
            and suffixes[-1] in RISKY_EXTENSIONS
            and suffixes[-2] in DECOY_EXTENSIONS
        ):
            signals.add("double_extension")

        if signals:
            suspicious[filename] = signals

    return suspicious

def find_nested_archives(
    filenames: list[str],
) -> list[str]:
    """
    Find ZIP archives stored inside another ZIP archive.
    """

    nested_archives: list[str] = []

    for filename in filenames:
        path = PurePosixPath(filename)

        if path.suffix.lower() == ".zip":
            nested_archives.append(filename)

    return nested_archives

def find_encrypted_archive_files(
    file_path: str | Path,
) -> list[str]:
    """
    Find encrypted files stored inside a ZIP archive.

    The archive contents are not decrypted or extracted.
    """

    if not validate_file(file_path):
        raise ValueError("Invalid file path.")

    try:
        with ZipFile(file_path, "r") as archive:
            encrypted_files = [
                info.filename
                for info in archive.infolist()
                if not info.is_dir()
                and info.flag_bits & 0x1
            ]
    except BadZipFile as exc:
        raise ValueError("Invalid ZIP archive.") from exc

    return encrypted_files

def analyze_archive_size_risk(
    file_path: str | Path,
    *,
    max_uncompressed_size: int = MAX_ARCHIVE_UNCOMPRESSED_SIZE,
    max_compression_ratio: float = MAX_ARCHIVE_COMPRESSION_RATIO,
) -> ArchiveSizeRiskResult:
    """
    Inspect ZIP size metadata for possible decompression-bomb behavior.

    The archive contents are not extracted.
    """

    if not validate_file(file_path):
        raise ValueError("Invalid file path.")

    try:
        with ZipFile(file_path, "r") as archive:
            entries = [
                info
                for info in archive.infolist()
                if not info.is_dir()
            ]
    except BadZipFile as exc:
        raise ValueError("Invalid ZIP archive.") from exc

    compressed_size = sum(
        info.compress_size
        for info in entries
    )

    uncompressed_size = sum(
        info.file_size
        for info in entries
    )

    if compressed_size == 0:
        compression_ratio = (
            float("inf")
            if uncompressed_size > 0
            else 0.0
        )
    else:
        compression_ratio = (
            uncompressed_size / compressed_size
        )

    signals: set[str] = set()

    if uncompressed_size > max_uncompressed_size:
        signals.add("excessive_uncompressed_size")

    if compression_ratio > max_compression_ratio:
        signals.add("excessive_compression_ratio")

    return ArchiveSizeRiskResult(
        compressed_size=compressed_size,
        uncompressed_size=uncompressed_size,
        compression_ratio=compression_ratio,
        signals=signals,
    )


def inspect_zip(
    file_path: str | Path,
) -> ArchiveInspectionResult:
    """
    Inspect the contents of a ZIP archive without extracting it.
    """

    if not validate_file(file_path):
        raise ValueError("Invalid file path.")

    try:
        with ZipFile(file_path, "r") as archive:
            filenames = [
                info.filename
                for info in archive.infolist()
                if not info.is_dir()
            ]
    except BadZipFile as exc:
        raise ValueError("Invalid ZIP archive.") from exc

    return ArchiveInspectionResult(
        file_count=len(filenames),
        filenames=filenames,
    )