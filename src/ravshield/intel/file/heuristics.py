from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ravshield.intel.file.metadata import get_file_metadata


RISKY_EXTENSIONS = {
    ".exe",
    ".dll",
    ".scr",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
    ".jar",
    ".msi",
}

DECOY_EXTENSIONS = {
    ".pdf",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".txt",
}


@dataclass(slots=True)
class FileHeuristicResult:
    path: Path
    signals: set[str] = field(default_factory=set)
    details: dict[str, object] = field(default_factory=dict)

    @property
    def suspicious(self) -> bool:
        return bool(self.signals)


def analyze_file_heuristics(
    file_path: str | Path,
) -> FileHeuristicResult:
    """
    Inspect basic file characteristics for suspicious patterns.

    These signals do not prove that a file is malicious.
    """

    path = Path(file_path)
    metadata = get_file_metadata(path)

    signals: set[str] = set()
    details: dict[str, object] = {
        "name": metadata.name,
        "extension": metadata.extension,
        "size": metadata.size,
    }

    if metadata.extension in RISKY_EXTENSIONS:
        signals.add("risky_extension")

    suffixes = [suffix.lower() for suffix in path.suffixes]

    if (
        len(suffixes) >= 2
        and suffixes[-1] in RISKY_EXTENSIONS
        and suffixes[-2] in DECOY_EXTENSIONS
    ):
        signals.add("double_extension")

    return FileHeuristicResult(
        path=path,
        signals=signals,
        details=details,
    )