"""Freeze and verify the exact Python dependency subject for production runs.

The interpreter running this command is the production dependency subject.  A
private lock may be supplied by an approved environment; in that mode the
installed distribution inventory must equal the lock before the artifacts are
written.  Scanner tooling is intentionally installed outside this interpreter.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from k_slide.certification import (
    EvidenceValidationError,
    dependency_lock_text,
    installed_dependency_inventory,
    load_dependency_lock,
)
from k_slide.io import atomic_write_json, atomic_write_text


def freeze(*, inventory_output: Path, lock_output: Path, lock_input: Path | None = None) -> dict[str, object]:
    expected = load_dependency_lock(lock_input) if lock_input is not None else None
    actual = installed_dependency_inventory()
    if expected is not None and actual != expected:
        raise EvidenceValidationError("installed production environment does not equal the supplied dependency lock")
    inventory = expected or actual
    atomic_write_json(inventory_output, inventory, mode=0o600)
    atomic_write_text(lock_output, dependency_lock_text(inventory), mode=0o600)
    return inventory


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Freeze the exact production Python dependency subject")
    parser.add_argument("--inventory-output", type=Path, required=True)
    parser.add_argument("--lock-output", type=Path, required=True)
    parser.add_argument("--lock-input", type=Path, help="Approved private exact lock to verify against the active interpreter")
    args = parser.parse_args(argv)
    try:
        inventory = freeze(
            inventory_output=args.inventory_output.expanduser(),
            lock_output=args.lock_output.expanduser(),
            lock_input=args.lock_input.expanduser() if args.lock_input else None,
        )
    except (EvidenceValidationError, OSError, UnicodeError, ValueError) as exc:
        print(json.dumps({"status": "BLOCKED", "reason": str(exc)}, ensure_ascii=False))
        return 2
    print(json.dumps({"status": "PASS", "package_count": len(inventory["packages"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
