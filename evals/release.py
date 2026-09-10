"""Evidence-derived release metadata and certification manifest generation."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from k_slide import __version__
from k_slide.certification import (
    CANDIDATE_INPUT_FIELDS,
    EvidenceValidationError,
    candidate_deployment_fingerprint,
    canonical_candidate_factors,
    canonical_corpus_identity,
    dependency_inventory_hash,
    certification_fingerprint,
    candidate_completeness,
    evidence_hashes,
    load_evidence,
    load_candidate_spec,
    load_dependency_lock,
    load_dependency_inventory,
    repository_schema_versions,
    resolve_candidate_spec,
    sha256_file,
    validate_cyclonedx_1_5,
)
from k_slide.model_policy import load_model_policy
from k_slide.production import ReleaseState
from k_slide.runtime import discover_runtime
from k_slide.io import atomic_write_json
from k_slide.errors import KSlideError

from .scenarios import DATASET_VERSION, split_manifest


REQUESTABLE_STATES = tuple(item.value for item in ReleaseState if item != ReleaseState.CERTIFICATION_STALE)


def _sha256(path: Path | None) -> str | None:
    if path is None or not path.is_file() or path.is_symlink():
        return None
    return sha256_file(path)


def _evidence_source_path(record: dict[str, Any] | None, role: str) -> Path | None:
    if not isinstance(record, dict) or not isinstance(record.get("path"), str) or not isinstance(record.get("sources"), list):
        return None
    envelope = Path(record["path"]).expanduser().resolve()
    for descriptor in record["sources"]:
        if not isinstance(descriptor, dict) or descriptor.get("role") != role or not isinstance(descriptor.get("path"), str):
            continue
        relative = Path(descriptor["path"])
        if relative.is_absolute() or ".." in relative.parts:
            return None
        path = (envelope.parent / relative).resolve()
        try:
            path.relative_to(envelope.parent)
        except ValueError:
            return None
        return path
    return None


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

    subject = _git_sha(root) or "unknown"
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, 'k-slide-development:' + subject)}",
        "version": 1,
        "metadata": {"timestamp": datetime.now(timezone.utc).isoformat(), "component": {"type": "application", "name": "k-slide", "version": __version__, "properties": [{"name": "k-slide:completeness", "value": "development"}]}},
        "components": [{"type": "library", "name": item["name"], "version": item["version"]} for item in _packages()],
    }


def build_production_sbom(root: Path, output: Path, *, inventory_path: Path | None = None) -> dict[str, Any]:
    """Generate a CycloneDX 1.5 SBOM from the frozen production inventory.

    The inventory is produced by the production interpreter and independently
    checked against the exact lock and audit result by the security adapter.
    This function only serializes that already-resolved subject; it never
    substitutes the ambient scanner environment or a development package list.
    """

    if inventory_path is None:
        candidates = (root / ".k-slide-config" / "production-dependency-inventory.json", root / "production-dependency-inventory.json")
        inventory_path = next((path for path in candidates if path.is_file() and not path.is_symlink()), None)
    if inventory_path is None:
        raise RuntimeError("exact resolved production dependency inventory is required")
    inventory = load_dependency_inventory(inventory_path.expanduser())
    inventory_sha = dependency_inventory_hash(inventory)
    value = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, f'k-slide-production:{inventory_sha}')}",
        "version": 1,
        "metadata": {"component": {"type": "application", "name": "k-slide", "version": __version__, "properties": [{"name": "k-slide:dependency-set-sha256", "value": inventory_sha}]}},
        "components": [{"type": "library", "name": item["name"], "version": item["version"]} for item in inventory["packages"]],
    }
    validate_cyclonedx_1_5(value)
    output.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(output, value, mode=0o600)
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


def _candidate_spec_for_release(root: Path, *, candidate_profile: Path | None, subject_sha: str | None, model: str | None, policy: Any, corpus: dict[str, Any], require_identity: bool = False) -> tuple[dict[str, Any], str]:
    """Resolve one candidate input object; certified output fields are ignored."""

    source_path = candidate_profile
    if source_path is None:
        local = root / ".k-slide-config" / "production-candidate.json"
        repository_candidate = root / "evals" / "production-candidate.yaml"
        source_path = local if local.is_file() else (repository_candidate if repository_candidate.is_file() else None)
    if source_path is not None:
        candidate = load_candidate_spec(source_path, root=root, require_identity=False, strict=True)
    else:
        candidate = _raw_profile(root)
    candidate = dict(candidate)
    git_subject = _git_sha(root)
    declared_subject = str(candidate.get("subject_git_sha") or "")
    subject = subject_sha or (git_subject if git_subject and git_subject != "UNSET" else (declared_subject or "UNSET"))
    if declared_subject and declared_subject.upper() != "UNSET" and declared_subject != subject:
        raise EvidenceValidationError("candidate subject_git_sha does not match release subject")
    candidate["subject_git_sha"] = subject
    if model:
        declared_model = str(candidate.get("requested_model") or "")
        if declared_model and declared_model.upper() != "UNSET" and declared_model != model:
            raise EvidenceValidationError("candidate requested_model does not match release model")
        candidate["requested_model"] = model
    candidate.setdefault("kslide_version", __version__)
    candidate.setdefault("effective_model", "UNSET")
    candidate.setdefault("ocr_provider", "none")
    candidate = resolve_candidate_spec(candidate, root=root, subject_git_sha=subject, model_policy=policy, corpus=corpus, require_sources=require_identity)
    if candidate.get("behavior_configuration") is None:
        candidate["behavior_configuration"] = {}
    if require_identity:
        for field in ("subject_git_sha", "requested_model"):
            if not str(candidate.get(field) or "") or str(candidate[field]).upper() == "UNSET":
                raise EvidenceValidationError(f"candidate profile must declare {field} after release binding")
    return candidate, subject


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


def _adopt_proven_effective_model(candidate: dict[str, Any], paths: dict[str, Path]) -> dict[str, Any]:
    """Use finalized model evidence to complete provisional candidate inputs."""

    specs: list[dict[str, Any]] = []
    for evidence_type in ("model_validation", "model_high_risk_stability", "model_held_out"):
        path = paths.get(evidence_type)
        if path is None or not path.is_file():
            continue
        try:
            envelope = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        if isinstance(envelope, dict) and isinstance(envelope.get("candidate_spec"), dict):
            specs.append(envelope["candidate_spec"])
    if not specs:
        return candidate
    if any(item != specs[0] for item in specs[1:]):
        raise EvidenceValidationError("model evidence final candidate specifications disagree")
    effective = str(specs[0].get("effective_model") or "")
    if not effective or effective.upper() == "UNSET":
        raise EvidenceValidationError("model evidence does not prove one effective model identity")
    result = dict(candidate)
    for key, value in specs[0].items():
        existing = result.get(key)
        if existing is not None and str(existing).upper() != "UNSET" and existing != value:
            raise EvidenceValidationError(f"model evidence final candidate input disagrees: {key}")
        result[key] = value
    return result


def _load_records(paths: dict[str, Path], *, subject_sha: str, deployment_fp: str, repository_root: Path | None = None, candidate_spec: dict[str, Any] | None = None, require_candidate_binding: bool = False) -> tuple[dict[str, dict[str, Any]], list[str]]:
    records: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    for evidence_type, path in paths.items():
        try:
            records[evidence_type] = load_evidence(path, expected_type=evidence_type, subject_git_sha=subject_sha, deployment_fingerprint=deployment_fp, repository_root=repository_root or path.parent, candidate_spec=candidate_spec, require_candidate_spec=require_candidate_binding)
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
    config_hash = str(value.get("behavior_configuration_hash") or value.get("config_hash") or "")
    if not config_hash:
        blockers.append("champion config_hash is missing")
    for evidence_type in ("model_validation", "model_high_risk_stability", "model_held_out"):
        record = records.get(evidence_type)
        if record and record["payload"].get("behavior_configuration_hash", record["payload"].get("configuration_hash")) != config_hash:
            blockers.append(f"champion config hash does not match {evidence_type} evidence")
    model_records = [records.get(item) for item in ("model_validation", "model_high_risk_stability", "model_held_out") if records.get(item)]
    behavior_hashes = {record["payload"].get("behavior_configuration_hash", record["payload"].get("configuration_hash")) for record in model_records}
    if len(behavior_hashes) > 1:
        blockers.append("model evidence behavior configuration hashes disagree")
    format_plans = {tuple(record["payload"].get("formats", ())) for record in model_records}
    if len(format_plans) > 1:
        blockers.append("model evidence format plans disagree")
    effective_ids = {record["payload"].get("effective_model") for record in model_records if record["payload"].get("effective_model")}
    champion_effective = policy.canonical_effective(requested=value.get("model"), effective=value.get("effective_model", value.get("model")))
    if len(effective_ids) > 1 or (effective_ids and champion_effective not in effective_ids):
        blockers.append("model evidence effective identities disagree")
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


def _state_specific_blockers(state: str, records: dict[str, dict[str, Any]], *, root: Path, policy: Any, deployment_fp: str, candidate_spec: dict[str, Any] | None = None) -> list[str]:
    blockers = [f"missing validated {item} evidence" for item in _state_requirements(state) if item not in records]
    if state != ReleaseState.DEVELOPMENT.value and candidate_spec is None:
        blockers.append("candidate deployment specification is missing")
    elif candidate_spec is not None:
        blockers.extend(f"candidate field is unresolved: {field}" for field in candidate_completeness(candidate_spec, state))
    heavy = records.get("heavy_runtime")
    if state in {ReleaseState.SYNTHETIC_PRODUCTION_CANDIDATE.value, ReleaseState.INTERNAL_VALIDATED.value, ReleaseState.PILOT_APPROVED.value, ReleaseState.PRODUCTION_CERTIFIED.value} and heavy and heavy["payload"].get("full_engine_pass") is not True:
        blockers.append("full heavy engine evidence is required beyond GEMMA_EVAL_READY")
    if state in {ReleaseState.SYNTHETIC_PRODUCTION_CANDIDATE.value, ReleaseState.INTERNAL_VALIDATED.value, ReleaseState.PILOT_APPROVED.value, ReleaseState.PRODUCTION_CERTIFIED.value}:
        champion, _, champion_blockers = _champion(root, records=records, policy=policy, deployment_fp=deployment_fp)
        if champion is None or champion_blockers:
            blockers.extend(champion_blockers or ["champion evidence is missing"])
    if state == ReleaseState.PRODUCTION_CERTIFIED.value:
        security_record = records.get("security")
        sbom = _evidence_source_path(security_record, "production_sbom")
        lock = _evidence_source_path(security_record, "production_lock")
        inventory = _evidence_source_path(security_record, "dependency_inventory")
        if sbom is None or not sbom.is_file():
            blockers.append("production SBOM is missing; development inventory is not sufficient")
        else:
            try:
                parsed = json.loads(sbom.read_text(encoding="utf-8"))
                validate_cyclonedx_1_5(parsed)
            except (OSError, UnicodeError, json.JSONDecodeError, EvidenceValidationError, AttributeError):
                blockers.append("production SBOM is malformed")
        security = records.get("security", {}).get("payload", {}) if isinstance(records.get("security"), dict) else {}
        try:
            sbom_hash = sha256_file(sbom) if sbom is not None else None
        except EvidenceValidationError:
            sbom_hash = None
        if not security.get("resolved_dependency_set_sha256"):
            blockers.append("security evidence has no resolved dependency-set identity")
        if not security.get("resolved_dependency_lock_sha256") or lock is None or not lock.is_file():
            blockers.append("security evidence has no portable resolved dependency lock")
        else:
            try:
                if sha256_file(lock) != security.get("resolved_dependency_lock_sha256") or dependency_inventory_hash(load_dependency_lock(lock)) != security.get("resolved_dependency_set_sha256"):
                    blockers.append("security evidence lock does not match the resolved dependency set")
            except (EvidenceValidationError, OSError):
                blockers.append("security evidence dependency lock is malformed")
        if inventory is None or not inventory.is_file():
            blockers.append("security evidence has no portable dependency inventory")
        if not security.get("production_sbom_sha256") or security.get("production_sbom_sha256") != sbom_hash:
            blockers.append("security evidence is not bound to the staged production SBOM")
        if candidate_spec is not None and security.get("resolved_dependency_set_sha256") != candidate_spec.get("resolved_dependency_set_sha256"):
            blockers.append("security evidence dependency set does not match candidate")
        heavy_payload = records.get("heavy_runtime", {}).get("payload", {}) if isinstance(records.get("heavy_runtime"), dict) else {}
        expected_dependency = candidate_spec.get("resolved_dependency_set_sha256") if candidate_spec is not None else None
        for field in ("resolved_dependency_set_sha256", "built_image_dependency_set_sha256"):
            if heavy_payload.get(field) != expected_dependency or heavy_payload.get(field) != security.get("resolved_dependency_set_sha256"):
                blockers.append(f"heavy evidence {field} does not match the security and candidate dependency subject")
        if heavy_payload.get("resolved_dependency_lock_sha256") != security.get("resolved_dependency_lock_sha256"):
            blockers.append("heavy evidence lock does not match the security dependency subject")
        # The candidate profile describes deployment inputs.  A certified
        # profile is materialized/bound after this evidence-derived state is
        # generated; requiring it here would make certification circular.
    return sorted(set(blockers))


def derive_release_state(requested_state: str, *, records: dict[str, dict[str, Any]], root: Path, policy: Any, deployment_fp: str, candidate_spec: dict[str, Any] | None = None) -> tuple[str, list[str]]:
    """Return the highest state supported up to the requested maximum."""

    ordered = list(REQUESTABLE_STATES)
    if requested_state not in ordered:
        return ReleaseState.DEVELOPMENT.value, [f"release state is not requestable: {requested_state}"]
    available = ReleaseState.DEVELOPMENT.value
    for state in ordered[1:]:
        blockers = _state_specific_blockers(state, records, root=root, policy=policy, deployment_fp=deployment_fp, candidate_spec=candidate_spec)
        if blockers:
            break
        available = state
    requested_blockers = _state_specific_blockers(requested_state, records, root=root, policy=policy, deployment_fp=deployment_fp, candidate_spec=candidate_spec)
    if ordered.index(requested_state) > ordered.index(available):
        return available, sorted(set(requested_blockers + [f"requested {requested_state} exceeds evidence-derived maximum {available}"]))
    return requested_state, requested_blockers


def build_release_manifest(root: Path, *, state: str = ReleaseState.DEVELOPMENT.value, requested_state: str | None = None, model: str | None = None, ocr_asset_manifest: Path | None = None, validation_result: Path | None = None, held_out_result: Path | None = None, evidence_paths: dict[str, Path] | None = None, subject_sha: str | None = None, candidate_profile: Path | None = None) -> dict[str, Any]:
    root = root.expanduser().resolve()
    runtime = discover_runtime(root)
    policy = load_model_policy(root)
    split = split_manifest()
    corpus = canonical_corpus_identity({"version": DATASET_VERSION, "corpus_fingerprint": split["corpus_fingerprint"], "held_out_fingerprint": split["held_out_fingerprint"]})
    evidence_paths = evidence_paths or {}
    requested = requested_state or state
    candidate, subject = _candidate_spec_for_release(root, candidate_profile=candidate_profile, subject_sha=subject_sha, model=model, policy=policy, corpus=corpus, require_identity=requested != ReleaseState.DEVELOPMENT.value)
    if requested == ReleaseState.DEVELOPMENT.value:
        candidate = _adopt_proven_effective_model(candidate, evidence_paths)
    completeness_blockers = candidate_completeness(candidate, requested)
    if completeness_blockers:
        raise EvidenceValidationError("candidate is incomplete for " + requested + ": " + ", ".join(completeness_blockers))
    def release_relative(path: Path, label: str) -> str:
        resolved = path.expanduser().resolve()
        try:
            return resolved.relative_to(root).as_posix()
        except ValueError as exc:
            raise EvidenceValidationError(f"release {label} must be staged beneath the release root") from exc

    # Validate portability before opening any evidence.  A manifest must never
    # disclose or depend on a private absolute evidence path.
    for evidence_type, evidence_path in evidence_paths.items():
        release_relative(evidence_path, f"evidence {evidence_type}")
    deployment_fp = candidate_deployment_fingerprint(candidate)
    records, evidence_errors = _load_records(
        evidence_paths,
        subject_sha=subject,
        deployment_fp=deployment_fp,
        repository_root=root,
        candidate_spec=candidate,
        require_candidate_binding=requested != ReleaseState.DEVELOPMENT.value or candidate_profile is not None,
    )
    derived, blockers = derive_release_state(requested, records=records, root=root, policy=policy, deployment_fp=deployment_fp, candidate_spec=candidate)
    if evidence_errors:
        blockers.extend(evidence_errors)
    champion, champion_hash, champion_blockers = _champion(root, records=records, policy=policy, deployment_fp=deployment_fp) if derived in {ReleaseState.SYNTHETIC_PRODUCTION_CANDIDATE.value, ReleaseState.INTERNAL_VALIDATED.value, ReleaseState.PILOT_APPROVED.value, ReleaseState.PRODUCTION_CERTIFIED.value} else (None, None, [])
    blockers.extend(champion_blockers)
    hashes = evidence_hashes(records.values())
    envelope_hashes = {str(item["evidence_type"]): str(item.get("envelope_sha256") or item["sha256"]) for item in records.values()}
    cert_fp = "UNSET" if derived == ReleaseState.DEVELOPMENT.value else certification_fingerprint(deployment=deployment_fp, evidence_hashes=hashes, release_state=derived, champion_hash=champion_hash)
    manifest_ocr_asset = ocr_asset_manifest
    if manifest_ocr_asset is not None:
        manifest_ocr_asset = manifest_ocr_asset.expanduser()
        if not manifest_ocr_asset.is_absolute():
            manifest_ocr_asset = root / manifest_ocr_asset
    if manifest_ocr_asset is not None and candidate.get("ocr_asset_manifest") and not str(candidate["ocr_asset_manifest"]).startswith("UNSET"):
        declared_asset = Path(str(candidate["ocr_asset_manifest"])).expanduser()
        if not declared_asset.is_absolute():
            declared_asset = root / declared_asset
        if manifest_ocr_asset.expanduser().resolve() != declared_asset.resolve():
            raise EvidenceValidationError("release OCR asset manifest does not match candidate specification")
    if manifest_ocr_asset is None and candidate.get("ocr_asset_manifest") and not str(candidate["ocr_asset_manifest"]).startswith("UNSET"):
        manifest_ocr_asset = Path(str(candidate["ocr_asset_manifest"]))
        if not manifest_ocr_asset.is_absolute():
            manifest_ocr_asset = root / manifest_ocr_asset
    def safe_relative(path: Path | None, label: str) -> str | None:
        if path is None:
            return None
        return release_relative(path, label)
    manifest: dict[str, Any] = {
        "schema_version": "1.0",
        "release_state": derived,
        "version": __version__,
        "subject_git_sha": subject,
        "report_generated_from_sha": _git_sha(root) or "UNSET",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "deployment_fingerprint": deployment_fp,
        "certification_fingerprint": cert_fp,
        "candidate_spec": canonical_candidate_factors(candidate),
        "runtime_provenance": {"opencode_version": runtime.opencode_version, "model": runtime.reported_model_id, "provider": runtime.provider, "vision_support": runtime.vision_support},
        "runtime": {"opencode_version": candidate.get("opencode_version"), "model": candidate.get("effective_model"), "provider": candidate.get("provider"), "vision_support": candidate.get("vision_settings")},
        "model_policy": policy.as_dict(),
        "ocr": {"provider": candidate.get("ocr_provider"), "asset_manifest": safe_relative(manifest_ocr_asset, "OCR asset manifest"), "asset_manifest_sha256": candidate.get("ocr_asset_manifest_sha256") or _sha256(manifest_ocr_asset)},
        "schemas": candidate.get("schema_versions") or repository_schema_versions(),
        "dataset": {"version": DATASET_VERSION, "corpus_fingerprint": split["corpus_fingerprint"], "held_out_fingerprint": split["held_out_fingerprint"]},
        "evidence_hashes": hashes,
        "evidence_envelope_hashes": envelope_hashes,
        "evidence_paths": {key: safe_relative(value, f"evidence {key}") for key, value in evidence_paths.items()},
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
    if derived == ReleaseState.PRODUCTION_CERTIFIED.value:
        security_payload = records.get("security", {}).get("payload", {}) if isinstance(records.get("security"), dict) else {}
        security_record = records.get("security")
        production_sbom = _evidence_source_path(security_record, "production_sbom")
        production_inventory = _evidence_source_path(security_record, "dependency_inventory")
        production_lock = _evidence_source_path(security_record, "production_lock")
        manifest["production_dependencies"] = {
            "constraints_sha256": candidate.get("constraints_sha256"),
            "inventory_sha256": security_payload.get("resolved_dependency_set_sha256") or candidate.get("resolved_dependency_set_sha256"),
            "inventory": safe_relative(production_inventory, "production dependency inventory"),
            "lock": safe_relative(production_lock, "production dependency lock"),
            "lock_sha256": security_payload.get("resolved_dependency_lock_sha256"),
            "heavy_inventory_sha256": records.get("heavy_runtime", {}).get("payload", {}).get("built_image_dependency_set_sha256"),
            "heavy_lock_sha256": records.get("heavy_runtime", {}).get("payload", {}).get("resolved_dependency_lock_sha256"),
            "sbom": safe_relative(production_sbom, "production SBOM"),
            "sbom_sha256": security_payload.get("production_sbom_sha256") or _sha256(production_sbom),
            "pip_audit_version": security_payload.get("pip_audit_version"),
            "semgrep_version": security_payload.get("semgrep_version"),
            "semgrep_ruleset_identity": security_payload.get("semgrep_ruleset_identity"),
            "semgrep_ruleset_sha256": security_payload.get("semgrep_ruleset_sha256"),
        }
    if blockers:
        manifest["blocking_reasons"] = sorted(set(blockers))
    return manifest


def _certified_profile_mapping(root: Path, *, candidate_spec: dict[str, Any], manifest: dict[str, Any], manifest_path: Path, manifest_sha256: str) -> dict[str, Any]:
    """Build and structurally validate the post-derivation profile in memory."""

    if manifest.get("release_state") != ReleaseState.PRODUCTION_CERTIFIED.value:
        raise EvidenceValidationError("certified profile requires PRODUCTION_CERTIFIED manifest")
    manifest_path = manifest_path.expanduser().resolve()
    candidate = dict(candidate_spec)
    finalized = manifest.get("candidate_spec")
    if not isinstance(finalized, dict):
        raise EvidenceValidationError("release manifest has no finalized candidate specification")
    candidate.update(finalized)
    missing = candidate_completeness(candidate, ReleaseState.PRODUCTION_CERTIFIED.value)
    if missing:
        raise EvidenceValidationError("finalized candidate is incomplete: " + ", ".join(missing))
    dataset = manifest.get("dataset")
    if isinstance(dataset, dict):
        candidate["corpus_identity"] = canonical_corpus_identity(dataset)
    attestations = manifest.get("attestations")
    model_data_attestation = attestations.get("model_data_policy") if isinstance(attestations, dict) else None
    if not model_data_attestation or model_data_attestation == "UNSET":
        raise EvidenceValidationError("release manifest has no model-data-policy attestation")
    def relative_or_absolute(path: Path) -> str:
        try:
            return path.relative_to(root.expanduser().resolve()).as_posix()
        except ValueError:
            return str(path)
    profile: dict[str, Any] = {key: value for key, value in candidate.items() if key in CANDIDATE_INPUT_FIELDS and key not in {"candidate_spec_version", "ocr_asset_manifest_sha256", "constraints_sha256"}}
    if candidate.get("ocr_asset_manifest"):
        profile["ocr_asset_manifest"] = candidate["ocr_asset_manifest"]
    profile.update({
        "schema_version": "1.0",
        "release_state": ReleaseState.PRODUCTION_CERTIFIED.value,
        "subject_git_sha": manifest.get("subject_git_sha"),
        "deployment_fingerprint": manifest.get("deployment_fingerprint"),
        "certification_fingerprint": manifest.get("certification_fingerprint"),
        "release_manifest": relative_or_absolute(manifest_path),
        "release_manifest_sha256": manifest_sha256,
        "model_data_attestation": model_data_attestation,
        "candidate_spec": canonical_candidate_factors(candidate),
    })
    # ProductionProfile.from_mapping is the final schema check before write.
    from k_slide.production import ProductionProfile

    parsed = ProductionProfile.from_mapping(profile)
    if parsed.deployment_fingerprint != candidate_deployment_fingerprint(candidate):
        raise EvidenceValidationError("certified profile deployment does not match finalized candidate specification")
    return profile


def materialize_certified_profile(root: Path, *, candidate_spec: dict[str, Any], manifest: dict[str, Any], manifest_path: Path, output: Path) -> Path:
    """Write the post-derivation production profile without hash recursion."""

    manifest_path = manifest_path.expanduser().resolve()
    profile = _certified_profile_mapping(root, candidate_spec=candidate_spec, manifest=manifest, manifest_path=manifest_path, manifest_sha256=sha256_file(manifest_path))
    output = output.expanduser()
    output.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(output, profile, mode=0o600)
    return output


def _write_development_sbom(root: Path, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(path, build_sbom(root), mode=0o600)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate evidence-derived K-Slide release metadata")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--candidate-profile", type=Path, help="Explicit candidate deployment specification")
    parser.add_argument("--resolved-candidate-output", type=Path, help="Persist centrally resolved candidate inputs for subsequent evidence producers")
    parser.add_argument("--certified-profile-output", type=Path, help="Materialize the certified production profile after the final manifest is written")
    parser.add_argument("--sbom", type=Path)
    parser.add_argument("--generate-production-sbom", action="store_true", help="Generate the required CycloneDX 1.5 SBOM from the resolved production inventory")
    parser.add_argument("--production-dependency-inventory", type=Path, help="Exact resolved production dependency inventory used for the production SBOM")
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
    try:
        split = split_manifest()
        policy = load_model_policy(root)
        candidate, subject = _candidate_spec_for_release(
            root,
            candidate_profile=args.candidate_profile,
            subject_sha=args.subject_sha,
            model=args.model,
            policy=policy,
            corpus=canonical_corpus_identity({"version": DATASET_VERSION, "corpus_fingerprint": split["corpus_fingerprint"], "held_out_fingerprint": split["held_out_fingerprint"]}),
            require_identity=requested != ReleaseState.DEVELOPMENT.value,
        )
    except (EvidenceValidationError, OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(json.dumps({"status": "BLOCKED", "requested_state": requested, "derived_state": ReleaseState.DEVELOPMENT.value, "reasons": [str(exc)]}, ensure_ascii=False, indent=2))
        return 2
    if requested != ReleaseState.DEVELOPMENT.value and args.candidate_profile is None and not (root / ".k-slide-config" / "production-candidate.json").is_file():
        print(json.dumps({"status": "BLOCKED", "requested_state": requested, "derived_state": ReleaseState.DEVELOPMENT.value, "reasons": ["certification-quality release requires --candidate-profile"]}, ensure_ascii=False, indent=2))
        return 2
    if args.resolved_candidate_output:
        try:
            resolved_output = args.resolved_candidate_output.expanduser()
            resolved_output.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_json(resolved_output, candidate, mode=0o600)
        except (OSError, TypeError, ValueError) as exc:
            print(json.dumps({"status": "BLOCKED", "requested_state": requested, "derived_state": ReleaseState.DEVELOPMENT.value, "reasons": [f"resolved candidate could not be persisted: {exc}"]}, ensure_ascii=False, indent=2))
            return 2
    completeness_blockers = candidate_completeness(candidate, requested)
    if completeness_blockers:
        print(json.dumps({"status": "BLOCKED", "requested_state": requested, "derived_state": ReleaseState.DEVELOPMENT.value, "reasons": ["candidate is incomplete for " + requested + ": " + ", ".join(completeness_blockers)]}, ensure_ascii=False, indent=2))
        return 2
    if args.generate_production_sbom:
        try:
            inventory_path = args.production_dependency_inventory
            if inventory_path is not None and not inventory_path.expanduser().is_absolute():
                inventory_path = root / inventory_path
            build_production_sbom(root, root / ".k-slide-config" / "production-sbom.json", inventory_path=inventory_path)
        except (EvidenceValidationError, OSError, RuntimeError) as exc:
            print(json.dumps({"status": "BLOCKED", "reasons": [str(exc)]}, ensure_ascii=False, indent=2))
            return 2
    paths = _evidence_arguments(args)
    # A certifying candidate is frozen before any evidence is loaded.  Model
    # evidence may only prove the already-declared effective identity; it may
    # not opportunistically rewrite this candidate during release.
    deployment_fp = candidate_deployment_fingerprint(candidate)
    records, evidence_errors = _load_records(paths, subject_sha=subject, deployment_fp=deployment_fp, repository_root=root, candidate_spec=candidate, require_candidate_binding=requested != ReleaseState.DEVELOPMENT.value or args.candidate_profile is not None)
    derived, blockers = derive_release_state(requested, records=records, root=root, policy=policy, deployment_fp=deployment_fp, candidate_spec=candidate)
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
    if derived == ReleaseState.PRODUCTION_CERTIFIED.value and args.certified_profile_output is None:
        print(json.dumps({"status": "BLOCKED", "requested_state": requested, "derived_state": derived, "reasons": ["PRODUCTION_CERTIFIED requires --certified-profile-output"]}, ensure_ascii=False, indent=2))
        return 2
    if derived == ReleaseState.PRODUCTION_CERTIFIED.value:
        try:
            args.output.expanduser().resolve().relative_to(root)
        except ValueError:
            print(json.dumps({"status": "BLOCKED", "requested_state": requested, "derived_state": derived, "reasons": ["PRODUCTION_CERTIFIED manifest must be staged beneath the release root"]}, ensure_ascii=False, indent=2))
            return 2
        try:
            args.certified_profile_output.expanduser().resolve().relative_to(root)
        except ValueError:
            print(json.dumps({"status": "BLOCKED", "requested_state": requested, "derived_state": derived, "reasons": ["PRODUCTION_CERTIFIED profile must be staged beneath the release root"]}, ensure_ascii=False, indent=2))
            return 2
    try:
        manifest = build_release_manifest(root, requested_state=requested, model=args.model, ocr_asset_manifest=args.ocr_asset_manifest, evidence_paths=paths, subject_sha=subject, candidate_profile=args.candidate_profile)
        if manifest["release_state"] == ReleaseState.PRODUCTION_CERTIFIED.value:
            # Validate the generated profile shape before writing the manifest.
            # Its real manifest hash is filled only after the manifest is
            # atomically written, so a fixed-width placeholder is sufficient
            # for this preflight structural check.
            _certified_profile_mapping(root, candidate_spec=candidate, manifest=manifest, manifest_path=args.output, manifest_sha256="0" * 64)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_json(args.output, manifest, mode=0o600)
    except (EvidenceValidationError, KSlideError, OSError, TypeError, ValueError) as exc:
        print(json.dumps({"status": "BLOCKED", "requested_state": requested, "derived_state": ReleaseState.DEVELOPMENT.value, "reasons": [str(exc)]}, ensure_ascii=False, indent=2))
        return 2
    if manifest["release_state"] == ReleaseState.PRODUCTION_CERTIFIED.value:
        try:
            materialize_certified_profile(root, candidate_spec=candidate, manifest=manifest, manifest_path=args.output, output=args.certified_profile_output)
        except (EvidenceValidationError, KSlideError, OSError, ValueError) as exc:
            # The manifest is only valid together with its materialized
            # certified profile.  Do not leave a seemingly usable partial
            # certification after a post-write filesystem failure.
            try:
                args.output.unlink(missing_ok=True)
                if args.certified_profile_output:
                    args.certified_profile_output.unlink(missing_ok=True)
            except OSError:
                pass
            print(json.dumps({"status": "BLOCKED", "requested_state": requested, "derived_state": manifest["release_state"], "reasons": [str(exc)]}, ensure_ascii=False, indent=2))
            return 2
    if args.sbom:
        _write_development_sbom(root, args.sbom)
    print(json.dumps({"status": "PASS", "release_state": manifest["release_state"], "manifest": str(args.output), "sbom": str(args.sbom) if args.sbom else None}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
