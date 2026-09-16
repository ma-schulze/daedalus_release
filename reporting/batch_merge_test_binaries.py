#!/usr/bin/env python3
"""
Discover TA report folders under ./reports and run merge_reports.py once per folder.

By default the entire reports tree is scanned (e.g. test_binaries/, llm_constr/, ...).
Use --scan-root to limit to one subtree.

Run from repo root:
  python reporting/batch_merge_test_binaries.py

Each *.ta/*.elf folder is merged independently, even when basenames repeat.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def discover_ta_report_dirs(scan_root: Path) -> list[Path]:
    if not scan_root.is_dir():
        return []
    dirs: list[Path] = []
    for p in scan_root.rglob("*"):
        if p.is_dir() and (p.name.endswith(".ta") or p.name.endswith(".elf")):
            dirs.append(p)
    return sorted(dirs)


def has_mergeable_reports(ta_report_dir: Path, binary_name: str) -> bool:
    pattern = f"report_{binary_name}_*.json"
    return any(ta_report_dir.glob(pattern))


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(
        description="Run merge_reports.py for each TA report folder under ./reports."
    )
    parser.add_argument(
        "--reports-dir",
        type=Path,
        default=repo_root / "reports",
        help="Root reports directory (default: <repo>/reports)",
    )
    parser.add_argument(
        "--scan-root",
        type=str,
        default=".",
        help=(
            "Subdirectory of reports-dir to scan for *.ta folders "
            "(default: ., entire reports tree including test_binaries, llm_constr, ...)"
        ),
    )
    parser.add_argument(
        "--test-binaries",
        type=str,
        default=None,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print merge commands without running them",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Forwarded to merge_reports.py (default: INFO)",
    )
    args = parser.parse_args()

    reports_dir = args.reports_dir.resolve()
    scan_root_name = args.test_binaries if args.test_binaries is not None else args.scan_root
    scan_root = (reports_dir / scan_root_name).resolve()
    merge_script = Path(__file__).resolve().parent / "merge_reports.py"

    if not merge_script.is_file():
        print(f"merge_reports.py not found at {merge_script}", file=sys.stderr)
        return 1
    if not reports_dir.is_dir():
        print(f"Reports directory not found: {reports_dir}", file=sys.stderr)
        return 1
    if not scan_root.is_dir():
        print(f"Scan root not found: {scan_root}", file=sys.stderr)
        return 1

    ta_report_dirs = discover_ta_report_dirs(scan_root)
    if not ta_report_dirs:
        print(f"No *.ta directories under {scan_root}", file=sys.stderr)
        return 1

    print(f"Scanning {scan_root.relative_to(reports_dir)}: found {len(ta_report_dirs)} TA folders", file=sys.stderr)

    failures = 0
    skipped = 0
    merged = 0
    for ta_report_dir in ta_report_dirs:
        binary_name = ta_report_dir.name
        if not has_mergeable_reports(ta_report_dir, binary_name):
            print(f"skip (no report_* json): {ta_report_dir.relative_to(reports_dir)}", file=sys.stderr)
            skipped += 1
            continue
        try:
            ta_report_rel = ta_report_dir.relative_to(reports_dir)
        except ValueError:
            ta_report_rel = ta_report_dir
        cmd = [
            sys.executable,
            str(merge_script),
            binary_name,
            "--reports-dir",
            str(reports_dir),
            "--ta-report-dir",
            str(ta_report_rel),
            "--log-level",
            args.log_level,
        ]
        if args.dry_run:
            print(subprocess.list2cmdline(cmd))
            merged += 1
            continue
        print(f"--- merging {ta_report_rel} ---", flush=True)
        r = subprocess.run(cmd, cwd=str(repo_root))
        if r.returncode != 0:
            print(f"merge failed for {ta_report_rel} (exit {r.returncode})", file=sys.stderr)
            failures += 1
        else:
            merged += 1

    if args.dry_run:
        print(f"Would merge {merged} TA folders, skip {skipped}.", file=sys.stderr)
        return 0
    if failures:
        print(f"Done with {failures} failure(s), {merged} merged, {skipped} skipped.", file=sys.stderr)
        return 1
    print(f"Done. {merged} merged, {skipped} skipped.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
