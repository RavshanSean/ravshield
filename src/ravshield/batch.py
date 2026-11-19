"""Bounded, non-recursive, read-only batch file triage."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ravshield.intel.file.report import scan_file
from ravshield.intel.file.report_explain import explain_security_report
from ravshield.intel.file.report_json import report_to_dict

MAX_BATCH_FILES = 1000


@dataclass(frozen=True, slots=True)
class BatchResult:
    directory: str
    scanned: int
    failed: int
    results: tuple[dict, ...]

    def to_dict(self) -> dict:
        return {
            "schema_version": "1.0",
            "report_type": "batch",
            "directory": self.directory,
            "scanned": self.scanned,
            "failed": self.failed,
            "results": list(self.results),
            "note": "Heuristic triage only; no malware or safety verdict.",
        }


def scan_directory(directory: str | Path, *, raw: bool = False, limit: int = MAX_BATCH_FILES) -> BatchResult:
    """Scan regular files in one directory; never follow symlinks or recurse."""
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_BATCH_FILES:
        raise ValueError(f"limit must be between 1 and {MAX_BATCH_FILES}.")
    folder = Path(directory).expanduser()
    if not folder.is_dir():
        raise ValueError("Invalid directory path.")
    results: list[dict] = []
    scanned = failed = 0
    try:
        entries = sorted(folder.iterdir(), key=lambda p: p.name)
        files = [p for p in entries if not p.is_symlink() and p.is_file()]
    except OSError as exc:
        raise ValueError("Cannot list directory.") from exc
    if len(files) > limit:
        raise ValueError(f"Directory contains {len(files)} files; limit is {limit}. No files scanned.")
    for path in files:
        try:
            report = scan_file(path)
            rendered = report if raw else explain_security_report(report)
            results.append({"path": str(path), "status": "ok", "report": report_to_dict(rendered)})
            scanned += 1
        except (OSError, ValueError, PermissionError) as exc:
            results.append({"path": str(path), "status": "error", "error": f"{type(exc).__name__}: {exc}"})
            failed += 1
    return BatchResult(str(folder), scanned, failed, tuple(results))
