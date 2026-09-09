"""Offline release metadata, SBOM, and certification-manifest generation."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from k_slide import __version__
from k_slide.production import ReleaseState
from k_slide.redaction import redact_value
from k_slide.runtime import discover_runtime

from .certification import load_model_policy
from .scenarios import DATASET_VERSION, split_manifest


def _sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _git_sha(root: Path) -> str | None:
    try:
        result = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def _packages() -> list[dict[str, str]]:
    names = ("Pillow", "PyMuPDF", "python-pptx", "paddlepaddle", "paddleocr", "setuptools")
    values: list[dict[str, str]] = []
    for name in names:
        try:
            version = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            continue
        values.append({"name": name, "version": version})
    return values


def build_sbom(root: Path) -> dict[str, Any]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:k-slide-{_git_sha(root) or 'unknown'}",
        "metadata": {"timestamp": datetime.now(timezone.utc).isoformat(), "component": {"type": "application", "name": "k-slide", "version": __version__}},
        "components": [{"type": "library", "name": item["name"], "version": item["version"]} for item in _packages()],
        "notes": ["OCR model asset hashes are recorded in the heavy image manifest when that image is built.", "This local SBOM does not claim an unexecuted heavy image or model-asset result."],
    }


def build_release_manifest(root: Path, *, state: str = ReleaseState.DEVELOPMENT.value, model: str | None = None, ocr_asset_manifest: Path | None = None, validation_result: Path | None = None, held_out_result: Path | None = None) -> dict[str, Any]:
    runtime = discover_runtime()
    policy = load_model_policy(root)
    split = split_manifest()
    return {
        "schema_version": "1.0",
        "release_state": state,
        "version": __version__,
        "git_sha": _git_sha(root),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runtime": {"opencode_version": runtime.opencode_version, "model": model or runtime.reported_model_id, "provider": runtime.provider},
        "model_policy": {"target_family": policy.target_family, "target_size": policy.target_size, "target_variant": policy.target_variant, "approved_model_ids": list(policy.approved_model_ids), "approved_aliases": list(policy.approved_aliases)},
        "ocr": {"provider": "paddle", "asset_manifest": str(ocr_asset_manifest) if ocr_asset_manifest else None, "asset_manifest_sha256": _sha256(ocr_asset_manifest) if ocr_asset_manifest else None},
        "schemas": {"translation_patch": "1.0", "evidence_ir": "1.0", "slide_ir": "1.0"},
        "dataset": {"version": DATASET_VERSION, "corpus_fingerprint": split["corpus_fingerprint"], "held_out_fingerprint": split["held_out_fingerprint"]},
        "validation_result_sha256": _sha256(validation_result) if validation_result else None,
        "held_out_result_sha256": _sha256(held_out_result) if held_out_result else None,
        "attestations": {"internal_bilingual": "UNSET", "zero_korean_comprehension": "UNSET", "security_scan": "UNSET", "heavy_runtime": "UNSET", "model_data_policy": "UNSET"},
        "constraints_file": "constraints-production.txt",
    }


def _certification_blockers(manifest: dict[str, Any]) -> list[str]:
    blockers: list[str] = []
    if manifest.get("release_state") != ReleaseState.PRODUCTION_CERTIFIED.value:
        blockers.append("release_state is not PRODUCTION_CERTIFIED")
    runtime = manifest.get("runtime", {})
    if runtime.get("model") != "google/gemma-4-31b-it" and not str(runtime.get("model", "")).startswith("approved:"):
        blockers.append("approved Gemma model identity is not recorded")
    ocr = manifest.get("ocr", {})
    if not ocr.get("asset_manifest_sha256"):
        blockers.append("offline OCR asset manifest hash is missing")
    if not manifest.get("validation_result_sha256"):
        blockers.append("validation result hash is missing")
    if not manifest.get("held_out_result_sha256"):
        blockers.append("held-out result hash is missing")
    attestations = manifest.get("attestations", {})
    for name in ("internal_bilingual", "zero_korean_comprehension", "security_scan", "heavy_runtime", "model_data_policy"):
        if not attestations.get(name) or attestations[name] == "UNSET":
            blockers.append(f"{name} attestation is missing")
    return blockers


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate offline K-Slide release metadata")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sbom", type=Path)
    parser.add_argument("--state", choices=[item.value for item in ReleaseState], default=ReleaseState.DEVELOPMENT.value)
    parser.add_argument("--model")
    parser.add_argument("--ocr-asset-manifest", type=Path)
    parser.add_argument("--validation-result", type=Path)
    parser.add_argument("--held-out-result", type=Path)
    parser.add_argument("--require-certified", action="store_true")
    args = parser.parse_args(argv)
    manifest = build_release_manifest(args.root, state=args.state, model=args.model, ocr_asset_manifest=args.ocr_asset_manifest, validation_result=args.validation_result, held_out_result=args.held_out_result)
    if args.require_certified:
        blockers = _certification_blockers(manifest)
        if blockers:
            print(json.dumps({"status": "BLOCKED", "reasons": blockers, "manifest": redact_value(manifest)}, ensure_ascii=False, indent=2))
            return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.sbom:
        args.sbom.parent.mkdir(parents=True, exist_ok=True)
        args.sbom.write_text(json.dumps(build_sbom(args.root), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "PASS", "release_state": manifest["release_state"], "manifest": str(args.output), "sbom": str(args.sbom) if args.sbom else None}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
