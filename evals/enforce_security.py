"""Enforce security scanner results without requiring a certifying candidate."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from k_slide.evidence_adapters import AdapterError, enforce_security_scanners


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fail closed on K-Slide security scanner failures or findings")
    for role in ("pip-audit", "gitleaks", "semgrep", "scanner-exits"):
        parser.add_argument(f"--{role}", required=True, type=Path)
    args = parser.parse_args(argv)
    sources = {
        "pip_audit": args.pip_audit,
        "gitleaks": args.gitleaks,
        "semgrep": args.semgrep,
        "scanner_exits": args.scanner_exits,
    }
    try:
        result = enforce_security_scanners(sources)
    except (AdapterError, OSError, ValueError) as exc:
        print(json.dumps({"status": "FAIL", "reason": str(exc)}, ensure_ascii=False))
        return 2
    print(json.dumps({"status": "PASS", **result}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
