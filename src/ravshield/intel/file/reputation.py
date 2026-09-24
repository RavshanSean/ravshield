from __future__ import annotations

from pathlib import Path

from ravshield.intel.file.hashing import hash_file
from ravshield.intel.matcher import match_ioc
from ravshield.intel.store import IOCStore
from ravshield.models import DetectionFinding


def check_file_reputation(
    file_path: str | Path,
    store: IOCStore,
) -> DetectionFinding | None:
    """
    Check a file's SHA-256 hash against the IOC store.
    """

    file_hash = hash_file(file_path)

    return match_ioc(
        store,
        "sha256",
        file_hash.sha256,
    )