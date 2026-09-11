"""Materialize an authorized private certification bundle safely.

The bundle is transported as a restricted Actions artifact or an equivalent
private file package.  Its manifest contains only relative paths and hashes;
the payload is never printed or copied into public release artifacts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import stat
import tempfile
from typing import Any
import zipfile

from k_slide.certification import EvidenceValidationError, dependency_inventory_hash, load_candidate_spec, load_dependency_lock, safe_relative_path, safe_path_under, sha256_file, validate_ocr_asset_manifest
from k_slide.io import atomic_write_bytes


BUNDLE_SCHEMA_VERSION = "1.0"
_ROLES = frozenset({"candidate_profile", "production_dependency_lock", "termbase_overlay", "ocr_asset_manifest", "ocr_asset"})
_FIXED_TARGETS = {
    "candidate_profile": ".k-slide-config/production-candidate.json",
    "production_dependency_lock": ".k-slide-config/production-requirements.lock",
    "termbase_overlay": ".k-slide-config/termbase.local.json",
}
_SINGLETON_ROLES = frozenset({"candidate_profile", "production_dependency_lock", "termbase_overlay", "ocr_asset_manifest"})


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
    elif label == "ocr_asset_manifest" and path != Path("ocr/manifest.json"):
        raise EvidenceValidationError("certification bundle OCR manifest must use ocr/manifest.json")
    elif not path.parts or path.parts[0] != "ocr":
        raise EvidenceValidationError("certification bundle support files must be under ocr/")
    return safe_relative_path(root, path, label=f"certification bundle {label} destination")


def materialize(*, bundle_root: Path, manifest_path: Path, output_root: Path, subject_git_sha: str) -> dict[str, Any]:
    bundle_root = bundle_root.expanduser().absolute()
    manifest_path = safe_path_under(bundle_root, manifest_path, label="certification bundle manifest", require_file=True)
    output_root = output_root.expanduser().absolute()
    if len(subject_git_sha) != 40 or set(subject_git_sha.lower()) - set("0123456789abcdef"):
        raise EvidenceValidationError("certification bundle subject SHA is invalid")
    try:
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
    copied_roles: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("role") not in _ROLES:
            raise EvidenceValidationError("certification bundle contains an unsupported role")
        role = str(entry["role"])
        if role in _SINGLETON_ROLES and role in seen_roles:
            raise EvidenceValidationError(f"certification bundle repeats role {role}")
        seen_roles.add(role)
        try:
            source_relative = _safe_relative(entry.get("path"), f"{role}.path")
            source = safe_relative_path(bundle_root, source_relative, label=f"certification bundle {role} source", require_file=True)
        except EvidenceValidationError as exc:
            raise EvidenceValidationError(f"certification bundle source is missing or unsafe: {role}") from exc
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
        copied[destination.relative_to(output_root).as_posix()] = expected_hash
        copied_roles.add(role)
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
    if candidate.get("ocr_provider") == "paddle":
        raw_manifest = candidate.get("ocr_asset_manifest")
        if not isinstance(raw_manifest, str) or raw_manifest.upper() == "UNSET":
            raise EvidenceValidationError("certification bundle candidate has no OCR asset manifest")
        if raw_manifest != "ocr/manifest.json":
            raise EvidenceValidationError("certification bundle candidate OCR manifest is not in the canonical ocr/manifest.json location")
        manifest = safe_path_under(output_root, raw_manifest, label="materialized OCR asset manifest", require_file=True)
        identity = validate_ocr_asset_manifest(manifest, expected_sha256=str(candidate.get("ocr_asset_manifest_sha256") or ""))
        manifest_relative = manifest.relative_to(output_root)
        listed_targets = {manifest_relative.parent.joinpath(item).as_posix() for item in identity["files"]}
        materialized_targets = {key for key in copied if key.startswith("ocr/") and key != manifest_relative.as_posix()}
        if listed_targets != materialized_targets:
            raise EvidenceValidationError("certification bundle OCR asset entries do not exactly match the candidate manifest")
    return {"status": "PASS", "subject_git_sha": subject_git_sha, "roles": sorted(copied_roles), "sha256": copied}


def _archive_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _extract_archive(archive: Path, destination: Path, expected_sha256: str) -> Path:
    if archive.is_symlink() or not archive.is_file():
        raise EvidenceValidationError("certification bundle archive is missing or symlinked")
    actual = _archive_sha256(archive)
    if actual != expected_sha256.lower():
        raise EvidenceValidationError("certification bundle archive digest mismatch")
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    seen: set[str] = set()
    try:
        with zipfile.ZipFile(archive) as package:
            for info in package.infolist():
                relative = _safe_relative(info.filename, "certification bundle archive member")
                key = relative.as_posix()
                if key in seen:
                    raise EvidenceValidationError("certification bundle archive contains duplicate members")
                seen.add(key)
                mode = (info.external_attr >> 16) & 0o170000
                if mode == stat.S_IFLNK:
                    raise EvidenceValidationError("certification bundle archive contains a symlink")
                target = safe_relative_path(destination, relative, label="certification bundle archive destination")
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True, mode=0o700)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                target.write_bytes(package.read(info))
                target.chmod(0o600)
    except (OSError, zipfile.BadZipFile) as exc:
        raise EvidenceValidationError("certification bundle archive is unreadable") from exc
    manifests = [item for item in destination.rglob("certification-bundle.json") if not item.is_symlink() and item.is_file()]
    if len(manifests) != 1:
        raise EvidenceValidationError("certification bundle archive must contain one manifest")
    return manifests[0]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Materialize an authorized private K-Slide certification bundle")
    parser.add_argument("--bundle-root", type=Path)
    parser.add_argument("--archive", type=Path, help="Verified private certification bundle ZIP")
    parser.add_argument("--archive-sha256", help="Authoritative SHA-256 for --archive")
    parser.add_argument("--manifest", type=Path, default=None)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--subject-sha", required=True)
    args = parser.parse_args(argv)
    manifest = args.manifest
    try:
        if args.archive:
            if not args.archive_sha256 or len(args.archive_sha256) != 64 or set(args.archive_sha256.lower()) - set("0123456789abcdef"):
                raise EvidenceValidationError("--archive requires a valid archive SHA-256")
            with tempfile.TemporaryDirectory(prefix="k-slide-certification-bundle-") as directory:
                extracted = _extract_archive(args.archive.expanduser(), Path(directory), args.archive_sha256)
                result = materialize(bundle_root=extracted.parent, manifest_path=extracted, output_root=args.output_root, subject_git_sha=args.subject_sha)
        else:
            if args.bundle_root is None:
                raise EvidenceValidationError("--bundle-root or --archive is required")
            manifest = manifest or args.bundle_root / "certification-bundle.json"
            result = materialize(bundle_root=args.bundle_root, manifest_path=manifest, output_root=args.output_root, subject_git_sha=args.subject_sha)
    except (EvidenceValidationError, OSError, UnicodeError, ValueError) as exc:
        print(json.dumps({"status": "BLOCKED", "reason": str(exc)}, ensure_ascii=False))
        return 2
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
