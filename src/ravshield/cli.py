"""Read-only command-line interface for RavShield file analysis."""
from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from ravshield.intel.file.report import scan_file
from ravshield.intel.file.report_explain import explain_security_report
from ravshield.intel.file.report_json import report_to_json
from ravshield.batch import MAX_BATCH_FILES, scan_directory


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ravshield", description="Static file triage, not a malware or safety verdict.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="Analyze a single file without executing it")
    scan.add_argument("file", help="Path to a file to analyze")
    scan.add_argument("--json", action="store_true", help="Print a machine-readable JSON report")
    scan.add_argument("--raw", action="store_true", help="Show technical findings instead of explanations")
    scan.add_argument("--output", metavar="PATH", help="Save the report to a new file (never overwrite)")
    batch = subparsers.add_parser("batch", help="Analyze regular files in one directory (non-recursive)")
    batch.add_argument("directory", help="Directory containing files to analyze")
    batch.add_argument("--json", action="store_true", help="Print a machine-readable combined JSON report")
    batch.add_argument("--raw", action="store_true", help="Show technical findings instead of explanations")
    batch.add_argument("--limit", type=int, default=MAX_BATCH_FILES, help=f"Maximum files allowed (1-{MAX_BATCH_FILES})")
    batch.add_argument("--output", metavar="PATH", help="Save the report to a new file (never overwrite)")
    return parser


def _emit(text: str, output: str | None) -> bool:
    """Print or create a new UTF-8 file without replacing an existing path."""
    if output is None:
        print(text)
        return True
    try:
        with Path(output).expanduser().open("x", encoding="utf-8") as handle:
            handle.write(text + "\n")
    except OSError as exc:
        print(f"ravshield: cannot save report: {exc}", file=sys.stderr)
        return False
    print(f"Report saved: {Path(output).expanduser()}")
    return True


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "batch":
        try:
            batch = scan_directory(args.directory, raw=args.raw, limit=args.limit)
        except (OSError, ValueError) as exc:
            print(f"ravshield: batch failed: {exc}", file=sys.stderr)
            return 2
        if args.json:
            output_text = json.dumps(batch.to_dict(), ensure_ascii=False, indent=2)
        else:
            lines = [f"Directory: {batch.directory}"]
            for item in batch.results:
                if item["status"] == "error":
                    lines.append(f"[ERROR] {item['path']}: {item['error']}")
                else:
                    report = item["report"]
                    lines.append(f"[{report['risk_level'].upper()}] {item['path']} ({len(report['findings'])} findings; complete={report['scan_complete']})")
            lines.append(f"Summary: {batch.scanned} scanned, {batch.failed} failed")
            lines.append("Note: Results are heuristic indicators, not a malware verdict.")
            output_text = "\n".join(lines)
        if not _emit(output_text, args.output):
            return 2
        return 1 if batch.failed else 0
    try:
        raw_report = scan_file(args.file)
        report = raw_report if args.raw else explain_security_report(raw_report)
    except (OSError, ValueError) as exc:
        print(f"ravshield: scan failed: {exc}", file=sys.stderr)
        return 2
    if args.json:
        output_text = report_to_json(report)
    else:
        lines = [
            f"File: {args.file}",
            f"Type: {report.file_type}",
            f"Risk: {report.risk_level}",
            f"Scan complete: {'yes' if report.scan_complete else 'no'}",
            f"Needs review: {'yes' if report.needs_review else 'no'}",
        ]
        if not args.raw:
            lines.append(f"Summary: {report.summary}")
        if report.findings:
            lines.append("Findings:")
            for finding in report.findings:
                lines.append(f"  [{finding.severity}] {finding.code}")
                if args.raw:
                    lines.append(f"    {finding.description}")
                else:
                    lines.append(f"    {finding.explanation}")
                    lines.append(f"    Recommendation: {finding.recommendation}")
        else:
            lines.append("Findings: none reported (not proof of safety)")
        if report.warnings:
            lines.append("Warnings:")
            for warning in report.warnings:
                lines.append(f"  - {warning}")
        lines.append("Note: Results are heuristic indicators, not a malware verdict.")
        output_text = "\n".join(lines)
    return 0 if _emit(output_text, args.output) else 2


if __name__ == "__main__":
    raise SystemExit(main())
