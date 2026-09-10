"""Materialize an authorized private certification bundle safely.

The bundle is transported as a restricted Actions artifact or an equivalent
private file package.  Its manifest contains only relative paths and hashes;
the payload is never printed or copied into public release artifacts.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from k_slide.certification import EvidenceValidationError, dependency_inventory_hash, load_candidate_spec, load_dependency_lock, sha256_file
from k_slide.io import atomic_write_bytes


BUNDLE_SCHEMA_VERSION = "1.0"
_ROLES = frozenset({"candidate_profile", "production_dependency_lock", "termbase_overlay", "ocr_asset_manifest", "ocr_asset"})
_FIXED_TARGETS = {
    "candidate_profile": ".k-slide-config/production-candidate.json",
    "production_dependency_lock": ".k-slide-config/production-requirements.lock",
    "termbase_overlay": ".k-slide-config/termbase.local.json",
}


def _safe_relative(raw: Any, label: str) -> Path:
    if not isinstance(raw, str) or not raw.strip():
        raise EvidenceValidationError(f"certification bundle {label} is missing")
    path = Path(raw)
    if path.is_absolute() or ".." in path.parts or path == Path("."):
        raise EvidenceValidationError(f"certification bundle {label} must be relative and stay inside the bundle")
    return path


def _destination(root: Path, raw: Any, label: str) -> Path:
    path = _safe_relative(raw, label)
    if label in _FIXED_TARGETS:
        expected = Path(_FIXED_TARGETS[label])
        if path != expected:
            raise EvidenceValidationError(f"certification bundle {label} has an unexpected destination")
    elif not path.parts or path.parts[0] != "ocr":
        raise EvidenceValidationError("certification bundle support files must be under ocr/")
    raw_destination = root / path
    current = root
    for part in path.parts:
        current = current / part
        if current.is_symlink():
            raise EvidenceValidationError("certification bundle destination may not traverse symlinks")
    destination = raw_destination.resolve()
    try:
        destination.relative_to(root)
    except ValueError as exc:
        raise EvidenceValidationError("certification bundle destination escapes the workspace") from exc
    return destination


def materialize(*, bundle_root: Path, manifest_path: Path, output_root: Path, subject_git_sha: str) -> dict[str, Any]:
    bundle_root = bundle_root.expanduser().resolve()
    manifest_unresolved = manifest_path.expanduser()
    if manifest_unresolved.is_symlink():
        raise EvidenceValidationError("certification bundle manifest may not be a symlink")
    manifest_path = manifest_unresolved.resolve()
    output_root = output_root.expanduser().resolve()
    if len(subject_git_sha) != 40 or set(subject_git_sha.lower()) - set("0123456789abcdef"):
        raise EvidenceValidationError("certification bundle subject SHA is invalid")
    try:
        manifest_path.relative_to(bundle_root)
        value = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise EvidenceValidationError("certification bundle manifest is unreadable") from exc
    if not isinstance(value, dict) or value.get("schema_version") != BUNDLE_SCHEMA_VERSION or value.get("subject_git_sha") != subject_git_sha:
        raise EvidenceValidationError("certification bundle manifest schema or subject is invalid")
    entries = value.get("files")
    if not isinstance(entries, list) or not entries:
        raise EvidenceValidationError("certification bundle has no files")
    seen_roles: set[str] = set()
    seen_targets: set[Path] = set()
    copied: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("role") not in _ROLES:
            raise EvidenceValidationError("certification bundle contains an unsupported role")
        role = str(entry["role"])
        if role in seen_roles:
            raise EvidenceValidationError(f"certification bundle repeats role {role}")
        seen_roles.add(role)
        source_relative = _safe_relative(entry.get("path"), f"{role}.path")
        source_unresolved = bundle_root / source_relative
        current_source = bundle_root
        for part in source_relative.parts:
            current_source = current_source / part
            if current_source.is_symlink():
                raise EvidenceValidationError(f"certification bundle source is missing or symlinked: {role}")
        source = source_unresolved.resolve()
        try:
            source.relative_to(bundle_root)
        except ValueError as exc:
            raise EvidenceValidationError("certification bundle source escapes the bundle") from exc
        if source.is_symlink() or not source.is_file():
            raise EvidenceValidationError(f"certification bundle source is missing or symlinked: {role}")
        expected_hash = str(entry.get("sha256") or "").lower()
        if len(expected_hash) != 64 or set(expected_hash) - set("0123456789abcdef") or sha256_file(source) != expected_hash:
            raise EvidenceValidationError(f"certification bundle source hash mismatch: {role}")
        destination = _destination(output_root, entry.get("target"), role)
        if destination in seen_targets:
            raise EvidenceValidationError("certification bundle has duplicate destinations")
        seen_targets.add(destination)
        if destination.exists() or destination.is_symlink():
            if destination.is_symlink() or not destination.is_file() or sha256_file(destination) != expected_hash:
                raise EvidenceValidationError(f"certification bundle refuses to overwrite existing file: {role}")
        else:
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            try:
                destination.parent.chmod(0o700)
            except OSError as exc:
                raise EvidenceValidationError(f"certification bundle destination permissions could not be restricted: {role}") from exc
            atomic_write_bytes(destination, source.read_bytes(), mode=0o600)
        copied[role] = expected_hash
    for required in ("candidate_profile", "production_dependency_lock"):
        if required not in seen_roles:
            raise EvidenceValidationError(f"certification bundle is missing {required}")
    candidate_path = output_root / _FIXED_TARGETS["candidate_profile"]
    lock_path = output_root / _FIXED_TARGETS["production_dependency_lock"]
    candidate = load_candidate_spec(candidate_path, root=output_root, require_identity=True, strict=True)
    if candidate.get("subject_git_sha") != subject_git_sha:
        raise EvidenceValidationError("certification bundle candidate subject does not match the requested subject")
    expected_dependency = str(candidate.get("resolved_dependency_set_sha256") or "").lower()
    if expected_dependency not in {"", "unset"} and dependency_inventory_hash(load_dependency_lock(lock_path)) != expected_dependency:
        raise EvidenceValidationError("certification bundle candidate does not match the production lock")
    return {"status": "PASS", "subject_git_sha": subject_git_sha, "roles": sorted(copied), "sha256": copied}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Materialize an authorized private K-Slide certification bundle")
    parser.add_argument("--bundle-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=None)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--subject-sha", required=True)
    args = parser.parse_args(argv)
    manifest = args.manifest or args.bundle_root / "certification-bundle.json"
    try:
        result = materialize(bundle_root=args.bundle_root, manifest_path=manifest, output_root=args.output_root, subject_git_sha=args.subject_sha)
    except (EvidenceValidationError, OSError, UnicodeError, ValueError) as exc:
        print(json.dumps({"status": "BLOCKED", "reason": str(exc)}, ensure_ascii=False))
        return 2
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
