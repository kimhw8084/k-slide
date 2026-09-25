"""Run the already-accepted security control suites without persisting test payloads."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import unittest
from pathlib import Path
from typing import Any

from k_slide.security_release import SECURITY_RELEASE_POLICY


def _result(module: str, source: Path, *, run_id: str, attempt: int) -> dict[str, Any]:
    sink = io.StringIO()
    suite = unittest.defaultTestLoader.loadTestsFromName(module)
    result = unittest.TestResult()
    with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
        suite.run(result)
    tests_run = result.testsRun
    failures = len(result.failures) + len(result.errors)
    skipped = len(result.skipped)
    return {
        "id": next(item["id"] for item in SECURITY_RELEASE_POLICY["required_controls"] if item["test_module"] == module),
        "status": "PASS" if tests_run > skipped and failures == 0 else "FAIL",
        "tests_run": tests_run,
        "tests_failed": failures,
        "tests_skipped": skipped,
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "run_id": run_id,
        "run_attempt": attempt,
    }


def collect(*, root: Path, run_id: str, attempt: int) -> list[dict[str, Any]]:
    if not run_id.isdigit() or int(run_id) < 1 or attempt < 1:
        raise ValueError("workflow run identity is malformed")
    rows = []
    for control in SECURITY_RELEASE_POLICY["required_controls"]:
        source = root / control["source_path"]
        if source.is_symlink() or not source.is_file():
            raise ValueError("required security control source is missing")
        row = _result(control["test_module"], source, run_id=run_id, attempt=attempt)
        rows.append(row)
        if row["status"] != "PASS":
            raise ValueError("required security control suite failed or was unavailable")
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run candidate-bound KSA-15/17/18/21/32 controls")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run-id", default=os.environ.get("GITHUB_RUN_ID", ""))
    parser.add_argument("--run-attempt", type=int, default=int(os.environ.get("GITHUB_RUN_ATTEMPT", "0")))
    args = parser.parse_args(argv)
    try:
        rows = collect(root=args.root.resolve(), run_id=args.run_id, attempt=args.run_attempt)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(rows, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    except (OSError, ValueError, TypeError) as exc:
        print(json.dumps({"status": "FAIL", "reason": f"Required security controls failed ({type(exc).__name__})."}, sort_keys=True))
        return 2
    print(json.dumps({"status": "PASS", "control_count": len(rows), "tests_run": sum(row["tests_run"] for row in rows)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
