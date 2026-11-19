"""Read-only command-line interface for RavShield file analysis."""
from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from ravshield.intel.file.report import scan_file
from ravshield.intel.file.report_explain import explain_security_report
from ravshield.intel.file.report_json import report_to_json


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ravshield", description="Static file triage, not a malware or safety verdict.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="Analyze a single file without executing it")
    scan.add_argument("file", help="Path to a file to analyze")
    scan.add_argument("--json", action="store_true", help="Print a machine-readable JSON report")
    scan.add_argument("--raw", action="store_true", help="Show technical findings instead of explanations")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command != "scan":
        return 2
    try:
        raw_report = scan_file(args.file)
        report = raw_report if args.raw else explain_security_report(raw_report)
    except (OSError, ValueError) as exc:
        print(f"ravshield: scan failed: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(report_to_json(report))
        return 0

    print(f"File: {args.file}")
    print(f"Type: {report.file_type}")
    print(f"Risk: {report.risk_level}")
    print(f"Scan complete: {'yes' if report.scan_complete else 'no'}")
    print(f"Needs review: {'yes' if report.needs_review else 'no'}")
    if not args.raw:
        print(f"Summary: {report.summary}")
    if report.findings:
        print("Findings:")
        for finding in report.findings:
            print(f"  [{finding.severity}] {finding.code}")
            if args.raw:
                print(f"    {finding.description}")
            else:
                print(f"    {finding.explanation}")
                print(f"    Recommendation: {finding.recommendation}")
    else:
        print("Findings: none reported (not proof of safety)")
    if report.warnings:
        print("Warnings:")
        for warning in report.warnings:
            print(f"  - {warning}")
    print("Note: Results are heuristic indicators, not a malware verdict.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
