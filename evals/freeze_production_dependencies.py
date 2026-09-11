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
    dependency_inventory_hash,
    dependency_lock_text,
    installed_dependency_inventory,
    load_dependency_lock,
    load_dependency_inventory,
    sha256_file,
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


def retain_heavy_dependency_context(*, inventory_path: Path, lock_path: Path, built_image_inventory_path: Path, output: Path, subject_git_sha: str, deployment_fingerprint: str | None = None) -> dict[str, object]:
    """Persist the dependency proof that a later heavy adapter can rederive."""

    if len(subject_git_sha) != 40 or set(subject_git_sha.lower()) - set("0123456789abcdef"):
        raise EvidenceValidationError("heavy dependency proof subject SHA is invalid")
    inventory = load_dependency_inventory(inventory_path)
    lock_inventory = load_dependency_lock(lock_path)
    built_inventory = load_dependency_inventory(built_image_inventory_path)
    if not inventory["packages"]:
        raise EvidenceValidationError("heavy dependency inventory is empty")
    if lock_inventory != inventory:
        raise EvidenceValidationError("heavy production lock does not equal the frozen inventory")
    if built_inventory != inventory:
        raise EvidenceValidationError("built heavy image inventory does not equal the frozen inventory")
    inventory_hash = dependency_inventory_hash(inventory)
    lock_hash = sha256_file(lock_path)
    context: dict[str, object] = {
        "schema_version": "1.0",
        "dependency_subject": "production-env",
        "subject_git_sha": subject_git_sha,
        "expected_dependency_set_sha256": inventory_hash,
        "frozen_dependency_set_sha256": inventory_hash,
        "built_image_dependency_set_sha256": inventory_hash,
        "production_lock_sha256": lock_hash,
        "package_count": len(inventory["packages"]),
    }
    if deployment_fingerprint is not None:
        context["deployment_fingerprint"] = deployment_fingerprint
    atomic_write_json(output, context, mode=0o600)
    return context


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Freeze the exact production Python dependency subject")
    parser.add_argument("--inventory-output", type=Path, help="Write the initial frozen inventory")
    parser.add_argument("--lock-output", type=Path, help="Write the initial exact production lock")
    parser.add_argument("--inventory-input", type=Path, help="Existing frozen inventory for --retain-only")
    parser.add_argument("--retain-only", action="store_true", help="Verify and retain an already-frozen production subject without discovering or rewriting it")
    parser.add_argument("--lock-input", type=Path, help="Approved private exact lock to verify against the active interpreter")
    parser.add_argument("--built-image-inventory", type=Path, help="Installed package inventory extracted from the built heavy image")
    parser.add_argument("--dependency-context-output", type=Path, help="Retained heavy dependency proof context output")
    parser.add_argument("--subject-sha", default="UNSET")
    parser.add_argument("--deployment-fingerprint")
    args = parser.parse_args(argv)
    try:
        if args.retain_only:
            if args.inventory_input is None or args.lock_input is None or args.built_image_inventory is None or args.dependency_context_output is None:
                raise EvidenceValidationError("--retain-only requires inventory input, lock input, built image inventory, and dependency context output")
            if args.inventory_output is not None or args.lock_output is not None:
                raise EvidenceValidationError("--retain-only cannot receive freeze output paths")
            retain_heavy_dependency_context(
                inventory_path=args.inventory_input.expanduser(),
                lock_path=args.lock_input.expanduser(),
                built_image_inventory_path=args.built_image_inventory.expanduser(),
                output=args.dependency_context_output.expanduser(),
                subject_git_sha=args.subject_sha,
                deployment_fingerprint=args.deployment_fingerprint,
            )
            inventory = load_dependency_inventory(args.inventory_input.expanduser())
        else:
            if args.inventory_output is None or args.lock_output is None:
                raise EvidenceValidationError("initial freeze requires --inventory-output and --lock-output")
            if args.built_image_inventory is not None or args.dependency_context_output is not None:
                raise EvidenceValidationError("heavy retention must use --retain-only after the image is built")
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
