#!/usr/bin/env python3
"""Validate the pinned KSA-38 traceability matrix and render its human view."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from traceability import TraceabilityError, load_json, render_report, validate_matrix


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--matrix", type=Path, default=root / "traceability/ksa38/traceability.v1.json"
    )
    parser.add_argument(
        "--schema", type=Path, default=root / "traceability/ksa38/schema.v1.json"
    )
    parser.add_argument(
        "--report", type=Path, default=root / "traceability/ksa38/README.md"
    )
    parser.add_argument("--write-report", action="store_true")
    parser.add_argument("--check-report", action="store_true")
    parser.add_argument("--summary-json", action="store_true")
    args = parser.parse_args()
    try:
        matrix = load_json(args.matrix)
        schema = load_json(args.schema)
        summary = validate_matrix(root, matrix, schema)
        report = render_report(matrix)
        if args.write_report:
            args.report.write_text(report, encoding="utf-8")
        if args.check_report and args.report.read_text(encoding="utf-8") != report:
            raise TraceabilityError("checked-in human report differs from deterministic rendering")
        if args.summary_json:
            print(json.dumps(summary, indent=2, sort_keys=True))
        else:
            print(
                "KSA-38 traceability PASS: "
                f"{summary['trace_rows']} rows, "
                f"{summary['ksa_coverage']['covered_items']}/{summary['ksa_coverage']['required_items']} KSAs, "
                f"{summary['changed_path_coverage']['expected_paths']} changed paths."
            )
        return 0
    except (TraceabilityError, OSError) as exc:
        print(f"KSA-38 traceability FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
