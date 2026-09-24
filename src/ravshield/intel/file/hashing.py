from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ravshield.engines.hash_engine import calculate_sha256
from ravshield.intel.file.validator import validate_file


@dataclass(slots=True)
class FileHashResult:
    """
    Cryptographic hash information collected from a file.
    """

    sha256: str


def hash_file(
    file_path: str | Path,
) -> FileHashResult:
    """
    Calculate cryptographic hashes for an existing file.
    """

    if not validate_file(file_path):
        raise ValueError("Invalid file path.")

    return FileHashResult(
        sha256=calculate_sha256(file_path),
    )