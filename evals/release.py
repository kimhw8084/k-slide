"""Evidence-derived release metadata and certification manifest generation."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from k_slide import __version__
from k_slide.certification import (
    EvidenceValidationError,
    build_deployment_factors,
    certification_fingerprint,
    deployment_fingerprint,
    evidence_hashes,
    load_evidence,
    sha256_file,
)
from k_slide.model_policy import load_model_policy
from k_slide.production import ReleaseState
from k_slide.runtime import discover_runtime

from .scenarios import DATASET_VERSION, split_manifest


REQUESTABLE_STATES = tuple(item.value for item in ReleaseState if item != ReleaseState.CERTIFICATION_STALE)


def _sha256(path: Path | None) -> str | None:
    if path is None or not path.is_file() or path.is_symlink():
        return None
    return sha256_file(path)


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
    """Build a development inventory; it is explicitly not a certified SBOM."""

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:k-slide-{_git_sha(root) or 'unknown'}",
        "metadata": {"timestamp": datetime.now(timezone.utc).isoformat(), "component": {"type": "application", "name": "k-slide", "version": __version__}},
        "components": [{"type": "library", "name": item["name"], "version": item["version"]} for item in _packages()],
        "complete": False,
        "notes": ["Development inventory only; this does not claim an executed production environment/image SBOM.", "OCR model asset hashes are separately validated from the heavy image manifest."],
    }


def build_production_sbom(root: Path, output: Path) -> dict[str, Any]:
    """Generate a real environment SBOM with the pinned CycloneDX tool.

    The tool is intentionally an approved release-environment dependency rather
    than a development dependency.  A missing generator is a release blocker,
    never a reason to fall back to the lightweight development inventory.
    """

    executable = shutil.which("cyclonedx-py")
    if not executable:
        raise RuntimeError("cyclonedx-py is unavailable; production SBOM was not generated")
    output.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run([executable, "environment", "--of", "JSON", "--output-file", str(output)], cwd=root, capture_output=True, text=True, timeout=120, check=False)
    if result.returncode != 0 or not output.is_file():
        raise RuntimeError((result.stderr or result.stdout or "cyclonedx-py failed").strip())
    try:
        value = json.loads(output.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("production SBOM is not valid JSON") from exc
    if not isinstance(value, dict) or value.get("bomFormat") != "CycloneDX" or not value.get("components"):
        raise RuntimeError("production SBOM is incomplete")
    return value


def _raw_profile(root: Path) -> dict[str, Any]:
    path = root / ".k-slide-config" / "production-profile.json"
    if not path.is_file():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _evidence_arguments(args: argparse.Namespace) -> dict[str, Path]:
    names = {
        "runtime": "runtime_evidence",
        "heavy_runtime": "heavy_runtime_evidence",
        "model_validation": "validation_evidence",
        "model_high_risk_stability": "high_risk_evidence",
        "model_held_out": "held_out_evidence",
        "internal_bilingual": "internal_bilingual_attestation",
        "zero_korean_comprehension": "zero_korean_attestation",
        "security": "security_attestation",
        "reliability": "reliability_attestation",
        "model_data_policy": "model_data_policy_attestation",
        "pilot_canary": "pilot_attestation",
        "governance": "governance_attestation",
    }
    result: dict[str, Path] = {}
    for evidence_type, argument in names.items():
        value = getattr(args, argument, None)
        if value:
            result[evidence_type] = Path(value)
    return result


def _load_records(paths: dict[str, Path], *, subject_sha: str, deployment_fp: str, repository_root: Path | None = None) -> tuple[dict[str, dict[str, Any]], list[str]]:
    records: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    for evidence_type, path in paths.items():
        try:
                records[evidence_type] = load_evidence(path, expected_type=evidence_type, subject_git_sha=subject_sha, deployment_fingerprint=deployment_fp, repository_root=repository_root or path.parent)
        except EvidenceValidationError as exc:
            errors.append(f"{evidence_type}: {exc}")
    return records, errors


def _champion(root: Path, *, records: dict[str, dict[str, Any]], policy: Any, deployment_fp: str) -> tuple[dict[str, Any] | None, str | None, list[str]]:
    path = root / "evals" / "champion.json"
    blockers: list[str] = []
    if not path.is_file():
        return None, None, ["champion.json is missing"]
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None, None, ["champion.json is malformed"]
    if not isinstance(value, dict) or value.get("status") in {None, "UNSET"} or value.get("model") in {None, "UNSET"}:
        return None, None, ["champion.json is UNSET"]
    if not policy.approved(requested=value.get("model"), effective=value.get("effective_model", value.get("model"))):
        blockers.append("champion model is not approved by ModelPolicy")
    if value.get("deployment_fingerprint") != deployment_fp:
        blockers.append("champion deployment fingerprint does not match candidate")
    config_hash = str(value.get("config_hash") or "")
    if not config_hash:
        blockers.append("champion config_hash is missing")
    for evidence_type in ("model_validation", "model_high_risk_stability", "model_held_out"):
        record = records.get(evidence_type)
        if record and record["payload"].get("configuration_hash") != config_hash:
            blockers.append(f"champion config hash does not match {evidence_type} evidence")
    return value, _sha256(path), blockers


def _state_requirements(state: str) -> tuple[str, ...]:
    return {
        ReleaseState.DEVELOPMENT.value: (),
        ReleaseState.RUNTIME_READY.value: ("runtime",),
        ReleaseState.GEMMA_EVAL_READY.value: ("runtime", "heavy_runtime"),
        ReleaseState.SYNTHETIC_PRODUCTION_CANDIDATE.value: ("runtime", "heavy_runtime", "model_validation", "model_high_risk_stability", "model_held_out"),
        ReleaseState.INTERNAL_VALIDATED.value: ("runtime", "heavy_runtime", "model_validation", "model_high_risk_stability", "model_held_out", "internal_bilingual", "zero_korean_comprehension", "model_data_policy"),
        ReleaseState.PILOT_APPROVED.value: ("runtime", "heavy_runtime", "model_validation", "model_high_risk_stability", "model_held_out", "internal_bilingual", "zero_korean_comprehension", "model_data_policy", "security", "reliability", "governance"),
        ReleaseState.PRODUCTION_CERTIFIED.value: ("runtime", "heavy_runtime", "model_validation", "model_high_risk_stability", "model_held_out", "internal_bilingual", "zero_korean_comprehension", "model_data_policy", "security", "reliability", "governance", "pilot_canary"),
        ReleaseState.CERTIFICATION_STALE.value: (),
    }[state]


def _state_specific_blockers(state: str, records: dict[str, dict[str, Any]], *, root: Path, policy: Any, deployment_fp: str) -> list[str]:
    blockers = [f"missing validated {item} evidence" for item in _state_requirements(state) if item not in records]
    heavy = records.get("heavy_runtime")
    if state in {ReleaseState.SYNTHETIC_PRODUCTION_CANDIDATE.value, ReleaseState.INTERNAL_VALIDATED.value, ReleaseState.PILOT_APPROVED.value, ReleaseState.PRODUCTION_CERTIFIED.value} and heavy and heavy["payload"].get("full_engine_pass") is not True:
        blockers.append("full heavy engine evidence is required beyond GEMMA_EVAL_READY")
    if state in {ReleaseState.SYNTHETIC_PRODUCTION_CANDIDATE.value, ReleaseState.INTERNAL_VALIDATED.value, ReleaseState.PILOT_APPROVED.value, ReleaseState.PRODUCTION_CERTIFIED.value}:
        champion, _, champion_blockers = _champion(root, records=records, policy=policy, deployment_fp=deployment_fp)
        if champion is None or champion_blockers:
            blockers.extend(champion_blockers or ["champion evidence is missing"])
    if state == ReleaseState.PRODUCTION_CERTIFIED.value:
        sbom = root / ".k-slide-config" / "production-sbom.json"
        if not sbom.is_file():
            blockers.append("production SBOM is missing; development inventory is not sufficient")
        else:
            try:
                parsed = json.loads(sbom.read_text(encoding="utf-8"))
                if parsed.get("bomFormat") != "CycloneDX" or not parsed.get("components") or parsed.get("complete") is False or not isinstance(parsed.get("metadata"), dict):
                    blockers.append("production SBOM is incomplete")
            except (OSError, UnicodeError, json.JSONDecodeError, AttributeError):
                blockers.append("production SBOM is malformed")
        profile = _raw_profile(root)
        if not profile or profile.get("release_state") != ReleaseState.PRODUCTION_CERTIFIED.value:
            blockers.append("certified production profile is missing")
    return sorted(set(blockers))


def derive_release_state(requested_state: str, *, records: dict[str, dict[str, Any]], root: Path, policy: Any, deployment_fp: str) -> tuple[str, list[str]]:
    """Return the highest state supported up to the requested maximum."""

    ordered = list(REQUESTABLE_STATES)
    if requested_state not in ordered:
        return ReleaseState.DEVELOPMENT.value, [f"release state is not requestable: {requested_state}"]
    available = ReleaseState.DEVELOPMENT.value
    for state in ordered[1:]:
        blockers = _state_specific_blockers(state, records, root=root, policy=policy, deployment_fp=deployment_fp)
        if blockers:
            break
        available = state
    requested_blockers = _state_specific_blockers(requested_state, records, root=root, policy=policy, deployment_fp=deployment_fp)
    if ordered.index(requested_state) > ordered.index(available):
        return available, sorted(set(requested_blockers + [f"requested {requested_state} exceeds evidence-derived maximum {available}"]))
    return requested_state, requested_blockers


def build_release_manifest(root: Path, *, state: str = ReleaseState.DEVELOPMENT.value, requested_state: str | None = None, model: str | None = None, ocr_asset_manifest: Path | None = None, validation_result: Path | None = None, held_out_result: Path | None = None, evidence_paths: dict[str, Path] | None = None, subject_sha: str | None = None) -> dict[str, Any]:
    root = root.expanduser().resolve()
    runtime = discover_runtime()
    policy = load_model_policy(root)
    split = split_manifest()
    subject = subject_sha or _git_sha(root) or "UNSET"
    profile = _raw_profile(root)
    runtime_values = runtime.as_dict()
    if model:
        runtime_values["reported_model_id"] = model
    factors = build_deployment_factors(root, subject_git_sha=subject, runtime=runtime_values, profile=profile, model_policy=policy, corpus={"version": DATASET_VERSION, "corpus_fingerprint": split["corpus_fingerprint"], "held_out_fingerprint": split["held_out_fingerprint"]})
    deployment_fp = deployment_fingerprint(factors)
    records, evidence_errors = _load_records(evidence_paths or {}, subject_sha=subject, deployment_fp=deployment_fp, repository_root=root)
    requested = requested_state or state
    derived, blockers = derive_release_state(requested, records=records, root=root, policy=policy, deployment_fp=deployment_fp)
    if evidence_errors:
        blockers.extend(evidence_errors)
    champion, champion_hash, champion_blockers = _champion(root, records=records, policy=policy, deployment_fp=deployment_fp) if derived in {ReleaseState.SYNTHETIC_PRODUCTION_CANDIDATE.value, ReleaseState.INTERNAL_VALIDATED.value, ReleaseState.PILOT_APPROVED.value, ReleaseState.PRODUCTION_CERTIFIED.value} else (None, None, [])
    blockers.extend(champion_blockers)
    hashes = evidence_hashes(records.values())
    envelope_hashes = {str(item["evidence_type"]): str(item.get("envelope_sha256") or item["sha256"]) for item in records.values()}
    cert_fp = "UNSET" if derived == ReleaseState.DEVELOPMENT.value else certification_fingerprint(deployment=deployment_fp, evidence_hashes=hashes, release_state=derived, champion_hash=champion_hash)
    manifest_ocr_asset = ocr_asset_manifest
    if manifest_ocr_asset is None and profile.get("ocr_asset_manifest") and not str(profile["ocr_asset_manifest"]).startswith("UNSET"):
        manifest_ocr_asset = Path(str(profile["ocr_asset_manifest"]))
    def safe_relative(path: Path | None) -> str | None:
        if path is None:
            return None
        candidate = path.expanduser().resolve()
        try:
            return candidate.relative_to(root).as_posix()
        except ValueError:
            return candidate.name
    manifest: dict[str, Any] = {
        "schema_version": "1.0",
        "release_state": derived,
        "version": __version__,
        "subject_git_sha": subject,
        "report_generated_from_sha": _git_sha(root) or "UNSET",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "deployment_fingerprint": deployment_fp,
        "certification_fingerprint": cert_fp,
        "runtime": {"opencode_version": runtime.opencode_version, "model": model or runtime.reported_model_id, "provider": runtime.provider, "vision_support": runtime.vision_support},
        "model_policy": policy.as_dict(),
        "ocr": {"provider": "paddle", "asset_manifest": safe_relative(manifest_ocr_asset), "asset_manifest_sha256": _sha256(manifest_ocr_asset)},
        "schemas": {"translation_patch": "1.0", "evidence_ir": "1.0", "slide_ir": "1.0"},
        "dataset": {"version": DATASET_VERSION, "corpus_fingerprint": split["corpus_fingerprint"], "held_out_fingerprint": split["held_out_fingerprint"]},
        "evidence_hashes": hashes,
        "evidence_envelope_hashes": envelope_hashes,
        "evidence_paths": {key: safe_relative(value) for key, value in (evidence_paths or {}).items()},
        "champion_hash": champion_hash,
        "constraints_file": "constraints-production.txt",
        "constraints_sha256": _sha256(root / "constraints-production.txt"),
        "attestations": {
            "internal_bilingual": records.get("internal_bilingual", {}).get("payload", {}).get("attestation_id", "UNSET"),
            "zero_korean_comprehension": records.get("zero_korean_comprehension", {}).get("payload", {}).get("attestation_id", "UNSET"),
            "security": records.get("security", {}).get("payload", {}).get("attestation_id", "UNSET"),
            "heavy_runtime": records.get("heavy_runtime", {}).get("payload", {}).get("attestation_id", "UNSET"),
            "model_data_policy": records.get("model_data_policy", {}).get("payload", {}).get("attestation_id", "UNSET"),
        },
    }
    if blockers:
        manifest["blocking_reasons"] = sorted(set(blockers))
    return manifest


def _write_development_sbom(root: Path, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(build_sbom(root), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate evidence-derived K-Slide release metadata")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sbom", type=Path)
    parser.add_argument("--generate-production-sbom", action="store_true", help="Generate the required production environment SBOM with cyclonedx-py")
    parser.add_argument("--requested-state", choices=REQUESTABLE_STATES, default=None)
    parser.add_argument("--state", choices=REQUESTABLE_STATES, default=None, help="Deprecated alias for --requested-state")
    parser.add_argument("--subject-sha")
    parser.add_argument("--model")
    parser.add_argument("--ocr-asset-manifest", type=Path)
    parser.add_argument("--validation-result", type=Path, help="Deprecated raw-result metadata; use --validation-evidence")
    parser.add_argument("--held-out-result", type=Path, help="Deprecated raw-result metadata; use --held-out-evidence")
    for option, destination in (("runtime", "runtime_evidence"), ("heavy-runtime", "heavy_runtime_evidence"), ("validation", "validation_evidence"), ("high-risk", "high_risk_evidence"), ("held-out", "held_out_evidence"), ("internal-bilingual", "internal_bilingual_attestation"), ("zero-korean", "zero_korean_attestation"), ("security", "security_attestation"), ("reliability", "reliability_attestation"), ("model-data-policy", "model_data_policy_attestation"), ("pilot", "pilot_attestation"), ("governance", "governance_attestation")):
        suffix = "evidence" if option in {"runtime", "heavy-runtime", "validation", "high-risk", "held-out"} else "attestation"
        parser.add_argument(f"--{option}-{suffix}", type=Path, dest=destination)
    parser.add_argument("--require-certified", action="store_true", help="Require the requested state to be evidence-backed; never promotes by itself")
    args = parser.parse_args(argv)
    root = args.root.expanduser().resolve()
    requested = args.requested_state or args.state or ReleaseState.DEVELOPMENT.value
    subject = args.subject_sha or _git_sha(root) or "UNSET"
    if args.generate_production_sbom:
        try:
            build_production_sbom(root, root / ".k-slide-config" / "production-sbom.json")
        except RuntimeError as exc:
            print(json.dumps({"status": "BLOCKED", "reasons": [str(exc)]}, ensure_ascii=False, indent=2))
            return 2
    runtime = discover_runtime()
    policy = load_model_policy(root)
    profile = _raw_profile(root)
    split = split_manifest()
    runtime_values = runtime.as_dict()
    if args.model:
        runtime_values["reported_model_id"] = args.model
    factors = build_deployment_factors(root, subject_git_sha=subject, runtime=runtime_values, profile=profile, model_policy=policy, corpus={"version": DATASET_VERSION, "corpus_fingerprint": split["corpus_fingerprint"], "held_out_fingerprint": split["held_out_fingerprint"]})
    deployment_fp = deployment_fingerprint(factors)
    paths = _evidence_arguments(args)
    records, evidence_errors = _load_records(paths, subject_sha=subject, deployment_fp=deployment_fp, repository_root=root)
    derived, blockers = derive_release_state(requested, records=records, root=root, policy=policy, deployment_fp=deployment_fp)
    blockers.extend(evidence_errors)
    if args.validation_result and "model_validation" not in paths:
        blockers.append("raw --validation-result is not certification evidence; provide --validation-evidence envelope")
    if args.held_out_result and "model_held_out" not in paths:
        blockers.append("raw --held-out-result is not certification evidence; provide --held-out-evidence envelope")
    if args.require_certified and requested != ReleaseState.PRODUCTION_CERTIFIED.value:
        blockers.append("--require-certified requires requested state PRODUCTION_CERTIFIED")
    if requested != ReleaseState.DEVELOPMENT.value and derived != requested:
        blockers.append(f"requested {requested} is not evidence-supported; maximum derived state is {derived}")
    if blockers:
        print(json.dumps({"status": "BLOCKED", "requested_state": requested, "derived_state": derived, "reasons": sorted(set(blockers))}, ensure_ascii=False, indent=2))
        return 2
    manifest = build_release_manifest(root, requested_state=requested, model=args.model, ocr_asset_manifest=args.ocr_asset_manifest, evidence_paths=paths, subject_sha=subject)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.sbom:
        _write_development_sbom(root, args.sbom)
    print(json.dumps({"status": "PASS", "release_state": manifest["release_state"], "manifest": str(args.output), "sbom": str(args.sbom) if args.sbom else None}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
