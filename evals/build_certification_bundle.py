"""Build a private certification bundle from explicitly named inputs.

This command is intended for an approved private preparation environment.  It
does not scan ``.k-slide-*`` directories and never includes source documents
implicitly.  The resulting directory can be zipped by that private producer
and published through its approved private transport.  Its manifest records
the public K-Slide target subject separately from the producer revision.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from k_slide.certification import EvidenceValidationError, load_candidate_spec, safe_path_under, sha256_file, validate_ocr_asset_manifest
from k_slide.io import atomic_write_json


def _target_subject(*, target_subject_git_sha: str | None, subject_git_sha: str | None) -> str:
    target = target_subject_git_sha if target_subject_git_sha is not None else subject_git_sha
    if target is None or len(target) != 40 or set(target.lower()) - set("0123456789abcdef"):
        raise EvidenceValidationError("bundle target subject SHA is invalid")
    return target.lower()


def build(*, output: Path, target_subject_git_sha: str | None = None, candidate_profile: Path, production_dependency_lock: Path, termbase_overlay: Path | None = None, ocr_asset_manifest: Path | None = None, subject_git_sha: str | None = None) -> dict[str, Any]:
    target_subject = _target_subject(target_subject_git_sha=target_subject_git_sha, subject_git_sha=subject_git_sha)
    output = output.expanduser().absolute()
    if output.is_symlink():
        raise EvidenceValidationError("bundle output directory may not be symlinked")
    if output.exists() and any(output.iterdir()):
        raise EvidenceValidationError("bundle output directory must be empty")
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    candidate_profile = candidate_profile.expanduser()
    candidate = load_candidate_spec(candidate_profile, root=candidate_profile.parent.parent, require_identity=True, strict=True)
    if candidate.get("subject_git_sha") not in {None, "", "UNSET", target_subject}:
        raise EvidenceValidationError("candidate subject does not match the bundle subject")
    if candidate.get("ocr_provider") == "paddle" and ocr_asset_manifest is None:
        raise EvidenceValidationError("Paddle certification bundle requires the candidate-bound OCR asset manifest")
    if candidate.get("ocr_provider") != "paddle" and ocr_asset_manifest is not None:
        raise EvidenceValidationError("OCR assets may only be bundled for a Paddle candidate")
    entries: list[dict[str, str]] = []

    def copy_named(role: str, source: Path, target: Path) -> None:
        source = source.expanduser()
        if source.is_symlink() or not source.is_file():
            raise EvidenceValidationError(f"bundle source is missing or symlinked: {role}")
        destination = output / target
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        destination.write_bytes(source.read_bytes())
        destination.chmod(0o600)
        entries.append({"role": role, "path": target.as_posix(), "target": target.as_posix(), "sha256": sha256_file(destination)})

    copy_named("candidate_profile", candidate_profile, Path(".k-slide-config/production-candidate.json"))
    copy_named("production_dependency_lock", production_dependency_lock, Path(".k-slide-config/production-requirements.lock"))
    if termbase_overlay is not None:
        copy_named("termbase_overlay", termbase_overlay, Path(".k-slide-config/termbase.local.json"))
    if ocr_asset_manifest is not None:
        manifest_source = ocr_asset_manifest.expanduser()
        identity = validate_ocr_asset_manifest(manifest_source)
        declared_manifest = str(candidate.get("ocr_asset_manifest") or "")
        if declared_manifest != "ocr/manifest.json":
            raise EvidenceValidationError("candidate OCR manifest must use the portable target ocr/manifest.json")
        declared_hash = str(candidate.get("ocr_asset_manifest_sha256") or "").lower()
        if declared_hash not in {"", "unset"} and declared_hash != identity["sha256"]:
            raise EvidenceValidationError("candidate OCR asset manifest hash does not match the supplied asset tree")
        copy_named("ocr_asset_manifest", manifest_source, Path("ocr/manifest.json"))
        asset_root = manifest_source.parent
        for relative in identity["files"]:
            source = safe_path_under(asset_root, relative, label=f"bundle OCR asset {relative}", require_file=True)
            copy_named("ocr_asset", source, Path("ocr") / relative)
    manifest = {"schema_version": "1.1", "target_subject_git_sha": target_subject, "files": entries}
    atomic_write_json(output / "certification-bundle.json", manifest, mode=0o600)
    return {"status": "PASS", "target_subject_git_sha": target_subject, "file_count": len(entries)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build an explicit private K-Slide certification bundle")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target-subject-sha", "--subject-sha", dest="target_subject_sha", required=True)
    parser.add_argument("--candidate-profile", type=Path, required=True)
    parser.add_argument("--production-dependency-lock", type=Path, required=True)
    parser.add_argument("--termbase-overlay", type=Path)
    parser.add_argument("--ocr-asset-manifest", type=Path)
    args = parser.parse_args(argv)
    try:
        result = build(output=args.output, target_subject_git_sha=args.target_subject_sha, candidate_profile=args.candidate_profile, production_dependency_lock=args.production_dependency_lock, termbase_overlay=args.termbase_overlay, ocr_asset_manifest=args.ocr_asset_manifest)
    except (EvidenceValidationError, OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "BLOCKED", "reason": str(exc)}, ensure_ascii=False))
        return 2
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
