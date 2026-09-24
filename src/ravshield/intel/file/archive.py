from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from zipfile import BadZipFile, ZipFile

from ravshield.intel.file.heuristics import (
    DECOY_EXTENSIONS,
    RISKY_EXTENSIONS,
)
from ravshield.intel.file.validator import validate_file


@dataclass(slots=True)
class ArchiveInspectionResult:
    file_count: int
    filenames: list[str] = field(default_factory=list)

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