from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ravshield.intel.file.validator import validate_file


@dataclass(slots=True)
class FileMetadata:
    """
    Basic metadata collected from a file.
    """

    name: str
    extension: str
    size: int


def get_file_metadata(
    file_path: str | Path,
) -> FileMetadata:
    """
    Collect basic metadata from an existing file.
    """

    if not validate_file(file_path):
        raise ValueError("Invalid file path.")

    path = Path(file_path).expanduser()

    return FileMetadata(
        name=path.name,
        extension=path.suffix.lower(),
        size=path.stat().st_size,
    )