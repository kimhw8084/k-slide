"""Fail-closed production deployment profile and doctor checks."""

from __future__ import annotations

import importlib.metadata
import importlib.util
import json
import os
import shutil
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from .certification import (
    CANDIDATE_INPUT_FIELDS,
    EvidenceValidationError,
    NOT_APPLICABLE_VALUE,
    NOT_EXPOSED_VALUE,
    canonical_corpus_identity,
    candidate_completeness,
    certification_fingerprint,
    candidate_deployment_fingerprint,
    load_candidate_spec,
    load_evidence,
    resolve_candidate_spec,
    sha256_file,
)
from .errors import ErrorCode, KSlideError
from .model_policy import load_model_policy
from .ocr.policy import OCRProviderPolicy, create_ocr_provider
from .runtime import RuntimeMetadata


class ReleaseState(str, Enum):
    DEVELOPMENT = "DEVELOPMENT"
    RUNTIME_READY = "RUNTIME_READY"
    GEMMA_EVAL_READY = "GEMMA_EVAL_READY"
    SYNTHETIC_PRODUCTION_CANDIDATE = "SYNTHETIC_PRODUCTION_CANDIDATE"
    INTERNAL_VALIDATED = "INTERNAL_VALIDATED"
    PILOT_APPROVED = "PILOT_APPROVED"
    PRODUCTION_CERTIFIED = "PRODUCTION_CERTIFIED"
    CERTIFICATION_STALE = "CERTIFICATION_STALE"


@dataclass(frozen=True)
class ProductionProfile:
    schema_version: str
    release_state: str
    opencode_version: str
    requested_model: str
    effective_model: str
    ocr_provider: str
    ocr_asset_manifest: str
    python_version: str
    paddle_version: str
    paddleocr_version: str
    libreoffice_version: str
    retention_days: int
    tenant_isolation: str
    network_egress: str
    subject_git_sha: str
    deployment_fingerprint: str
    certification_fingerprint: str
    release_manifest: str
    release_manifest_sha256: str
    model_data_attestation: str
    behavior_configuration: dict[str, Any] | None = None
    candidate_spec: dict[str, Any] | None = None

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> "ProductionProfile":
        required = ("release_state", "opencode_version", "requested_model", "effective_model", "ocr_provider", "ocr_asset_manifest", "python_version", "paddle_version", "paddleocr_version", "libreoffice_version", "retention_days", "tenant_isolation", "network_egress", "subject_git_sha", "deployment_fingerprint", "certification_fingerprint", "release_manifest", "release_manifest_sha256", "model_data_attestation")
        missing = [key for key in required if key not in value]
        if missing:
            raise KSlideError(ErrorCode.PRODUCTION_PROFILE_INVALID, "Production profile is missing required fields.", {"fields": missing})
        if "resource_limits" in value:
            raise KSlideError(ErrorCode.PRODUCTION_PROFILE_INVALID, "resource_limits is not a runtime-enforced production field; use production-slo.yaml for measured SLOs.")
        retention_days = value["retention_days"]
        if isinstance(retention_days, bool) or not isinstance(retention_days, int) or retention_days <= 0:
            raise KSlideError(ErrorCode.PRODUCTION_PROFILE_INVALID, "Production profile retention_days must be a positive integer.")
        return cls(
            schema_version=str(value.get("schema_version", "1.0")),
            release_state=str(value["release_state"]),
            opencode_version=str(value["opencode_version"]),
            requested_model=str(value["requested_model"]),
            effective_model=str(value["effective_model"]),
            ocr_provider=str(value["ocr_provider"]),
            ocr_asset_manifest=str(value["ocr_asset_manifest"]),
            python_version=str(value["python_version"]),
            paddle_version=str(value["paddle_version"]),
            paddleocr_version=str(value["paddleocr_version"]),
            libreoffice_version=str(value["libreoffice_version"]),
            retention_days=retention_days,
            tenant_isolation=str(value["tenant_isolation"]),
            network_egress=str(value["network_egress"]),
            subject_git_sha=str(value["subject_git_sha"]),
            deployment_fingerprint=str(value["deployment_fingerprint"]),
            certification_fingerprint=str(value["certification_fingerprint"]),
            release_manifest=str(value["release_manifest"]),
            release_manifest_sha256=str(value["release_manifest_sha256"]),
            model_data_attestation=str(value["model_data_attestation"]),
            behavior_configuration=value.get("behavior_configuration") if isinstance(value.get("behavior_configuration"), dict) else None,
            candidate_spec={**(value.get("candidate_spec") if isinstance(value.get("candidate_spec"), dict) else {}), **{key: value[key] for key in CANDIDATE_INPUT_FIELDS if key in value}},
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "release_state": self.release_state,
            "opencode_version": self.opencode_version,
            "requested_model": self.requested_model,
            "effective_model": self.effective_model,
            "ocr_provider": self.ocr_provider,
            "ocr_asset_manifest": self.ocr_asset_manifest,
            "python_version": self.python_version,
            "paddle_version": self.paddle_version,
            "paddleocr_version": self.paddleocr_version,
            "libreoffice_version": self.libreoffice_version,
            "retention_days": self.retention_days,
            "tenant_isolation": self.tenant_isolation,
            "network_egress": self.network_egress,
            "subject_git_sha": self.subject_git_sha,
            "deployment_fingerprint": self.deployment_fingerprint,
            "certification_fingerprint": self.certification_fingerprint,
            "release_manifest": self.release_manifest,
            "release_manifest_sha256": self.release_manifest_sha256,
            "model_data_attestation": self.model_data_attestation,
            **({"behavior_configuration": self.behavior_configuration} if self.behavior_configuration is not None else {}),
            **({"candidate_spec": self.candidate_spec} if self.candidate_spec is not None else {}),
        }


def load_production_profile(root: Path) -> ProductionProfile:
    path = root.expanduser().resolve() / ".k-slide-config" / "production-profile.json"
    if not path.is_file():
        raise KSlideError(ErrorCode.PRODUCTION_PROFILE_INVALID, "Production profile is missing.", {"path": str(path)})
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise KSlideError(ErrorCode.PRODUCTION_PROFILE_INVALID, "Production profile is unreadable or malformed.", {"path": str(path)}) from exc
    if not isinstance(value, dict):
        raise KSlideError(ErrorCode.PRODUCTION_PROFILE_INVALID, "Production profile must be a JSON object.")
    return ProductionProfile.from_mapping(value)


def _check(label: str, passed: bool, detail: str) -> dict[str, str]:
    return {"label": label, "status": "PASS" if passed else "FAIL", "detail": detail}


def _asset_manifest_status(path: Path) -> tuple[bool, str]:
    if path.is_symlink():
        return False, "asset manifest is symlinked"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return False, f"manifest unreadable: {exc}"
    if not isinstance(value, dict) or value.get("provider") != "paddle":
        return False, "manifest is not a Paddle asset manifest"
    files = value.get("files")
    if not isinstance(files, list) or not files:
        return False, "manifest has no materialized asset files"
    root = path.parent.resolve()
    for item in files:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            return False, "manifest contains an invalid asset entry"
        candidate = Path(item["path"]).expanduser()
        if not candidate.is_absolute():
            candidate = root / candidate
        try:
            candidate.resolve().relative_to(root)
        except ValueError:
            return False, "manifest references an asset outside its local root"
        if candidate.is_symlink():
            return False, "manifest references a symlinked asset"
        if not candidate.is_file():
            return False, f"asset is missing: {candidate.name}"
        expected_hash = item.get("sha256")
        if not isinstance(expected_hash, str) or len(expected_hash) != 64:
            return False, f"asset hash is missing: {candidate.name}"
        try:
            actual_hash = sha256_file(candidate)
        except EvidenceValidationError as exc:
            return False, str(exc)
        if actual_hash != expected_hash.lower():
            return False, f"asset hash mismatch: {candidate.name}"
    return True, f"{len(files)} local assets"


def _resolve_path(root: Path, raw: str) -> Path:
    candidate = Path(raw).expanduser()
    return candidate if candidate.is_absolute() else root.expanduser().resolve() / candidate


def _version_from_command(command: str) -> str | None:
    binary = shutil.which(command)
    if not binary:
        return None
    try:
        import subprocess
        result = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (result.stdout or result.stderr).strip().splitlines()
    return text[0] if result.returncode == 0 and text else None


def _manifest_and_fingerprint_status(root: Path, profile: ProductionProfile, runtime: RuntimeMetadata) -> list[dict[str, str]]:
    checks: list[dict[str, str]] = []
    certification_match = False
    manifest_path = _resolve_path(root, profile.release_manifest)
    try:
        manifest_hash = sha256_file(manifest_path)
        checks.append(_check("Release manifest hash", manifest_hash == profile.release_manifest_sha256, f"expected={profile.release_manifest_sha256}; actual={manifest_hash}"))
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(manifest, dict):
            raise ValueError("release manifest must be an object")
        checks.append(_check("Release manifest state", manifest.get("release_state") == ReleaseState.PRODUCTION_CERTIFIED.value, str(manifest.get("release_state"))))
        checks.append(_check("Release manifest subject", manifest.get("subject_git_sha") == profile.subject_git_sha, str(manifest.get("subject_git_sha"))))
        checks.append(_check("Release manifest deployment", manifest.get("deployment_fingerprint") == profile.deployment_fingerprint, str(manifest.get("deployment_fingerprint"))))
        asset_manifest = _resolve_path(root, profile.ocr_asset_manifest)
        expected_asset_hash = sha256_file(asset_manifest)
        checks.append(_check("Release manifest OCR asset hash", manifest.get("ocr", {}).get("asset_manifest_sha256") == expected_asset_hash, f"expected={expected_asset_hash}"))
        attestations = manifest.get("attestations", {})
        checks.append(_check("Model-data attestation binding", isinstance(attestations, dict) and attestations.get("model_data_policy") == profile.model_data_attestation, profile.model_data_attestation))
        evidence_hashes = manifest.get("evidence_hashes")
        if not isinstance(evidence_hashes, dict) or not evidence_hashes:
            raise ValueError("release manifest has no evidence hashes")
        for evidence_type, expected_hash in evidence_hashes.items():
            evidence_path = manifest.get("evidence_paths", {}).get(evidence_type) if isinstance(manifest.get("evidence_paths"), dict) else None
            if not evidence_path:
                checks.append(_check(f"Evidence {evidence_type}", False, "path is missing"))
                continue
            try:
                record = load_evidence(_resolve_path(root, str(evidence_path)), expected_type=str(evidence_type), subject_git_sha=profile.subject_git_sha, deployment_fingerprint=profile.deployment_fingerprint, repository_root=root, candidate_spec=profile.candidate_spec)
                checks.append(_check(f"Evidence {evidence_type}", record.get("evidence_identity") == expected_hash, f"identity={record.get('evidence_identity')}"))
                expected_envelope = manifest.get("evidence_envelope_hashes", {}).get(evidence_type) if isinstance(manifest.get("evidence_envelope_hashes"), dict) else None
                if expected_envelope:
                    checks.append(_check(f"Evidence {evidence_type} envelope hash", record.get("envelope_sha256") == expected_envelope, f"sha256={record.get('envelope_sha256')}"))
            except (EvidenceValidationError, OSError, ValueError) as exc:
                checks.append(_check(f"Evidence {evidence_type}", False, str(exc)))
        expected_certification = certification_fingerprint(
            deployment=profile.deployment_fingerprint,
            evidence_hashes={str(key): str(value) for key, value in evidence_hashes.items()},
            release_state=ReleaseState.PRODUCTION_CERTIFIED.value,
            champion_hash=manifest.get("champion_hash"),
        )
        certification_match = expected_certification == profile.certification_fingerprint == manifest.get("certification_fingerprint")
        checks.append(_check("Certification fingerprint", certification_match, f"expected={expected_certification}; profile={profile.certification_fingerprint}"))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, EvidenceValidationError) as exc:
        checks.append(_check("Release manifest", False, str(exc)))
    from .model_policy import ModelPolicy

    candidate_policy = (profile.candidate_spec or {}).get("model_policy")
    policy = ModelPolicy.from_mapping(candidate_policy) if isinstance(candidate_policy, dict) else load_model_policy(root)
    try:
        from evals.scenarios import split_manifest

        corpus = canonical_corpus_identity(split_manifest())
    except ImportError:
        corpus = canonical_corpus_identity(None)
    candidate = dict(profile.candidate_spec or {})
    profile_values = profile.as_dict()
    for field in CANDIDATE_INPUT_FIELDS:
        if field in profile_values and field != "candidate_spec":
            candidate[field] = profile_values[field]
    candidate["subject_git_sha"] = profile.subject_git_sha
    candidate["requested_model"] = profile.requested_model
    candidate["effective_model"] = profile.effective_model
    candidate["opencode_version"] = profile.opencode_version
    candidate["ocr_provider"] = profile.ocr_provider
    candidate["model_policy"] = policy.as_dict()
    if not candidate.get("corpus_identity"):
        candidate["corpus_identity"] = corpus
    expected_deployment = candidate_deployment_fingerprint(candidate)
    deployment_match = expected_deployment == profile.deployment_fingerprint
    checks.append(_check("Deployment fingerprint", deployment_match, f"expected={expected_deployment}; profile={profile.deployment_fingerprint}"))
    candidate_sources = [root / ".k-slide-config" / "production-candidate.json", root / "evals" / "production-candidate.yaml"]
    candidate_source = next((path for path in candidate_sources if path.is_file()), None)
    candidate_source_match = True
    if candidate_source is not None:
        try:
            source_candidate = load_candidate_spec(candidate_source, root=root, require_identity=False, strict=True)
            source_candidate = resolve_candidate_spec(source_candidate, root=root, subject_git_sha=profile.subject_git_sha, model_policy=policy, corpus=corpus, require_sources=True)
            source_missing = candidate_completeness(source_candidate, ReleaseState.PRODUCTION_CERTIFIED.value)
            if candidate_source == root / "evals" / "production-candidate.yaml" and source_missing:
                # The tracked public template is deliberately a development
                # input and must not stale a separately materialized private
                # certified profile.
                checks.append(_check("Candidate source identity", True, "tracked DEVELOPMENT template is incomplete and non-authoritative"))
            else:
                for field in CANDIDATE_INPUT_FIELDS:
                    current = source_candidate.get(field)
                    unresolved = current is None or current == {} or (isinstance(current, str) and current.upper() == "UNSET")
                    if unresolved and field in candidate:
                        source_candidate[field] = candidate[field]
                source_candidate["subject_git_sha"] = profile.subject_git_sha
                source_candidate["requested_model"] = profile.requested_model
                source_candidate["effective_model"] = profile.effective_model
                source_candidate["opencode_version"] = profile.opencode_version
                source_candidate["ocr_provider"] = profile.ocr_provider
                source_candidate["model_policy"] = policy.as_dict()
                source_match = candidate_deployment_fingerprint(source_candidate) == profile.deployment_fingerprint
                candidate_source_match = source_match
                checks.append(_check("Candidate source identity", source_match, str(candidate_source)))
        except (EvidenceValidationError, OSError, UnicodeError, ValueError, TypeError) as exc:
            candidate_source_match = False
            checks.append(_check("Candidate source identity", False, str(exc)))
    checks.append(_check("Certification freshness", deployment_match and certification_match and candidate_source_match, "current" if deployment_match and certification_match and candidate_source_match else "CERTIFICATION_STALE"))
    return checks


def _runtime_identity_checks(profile: ProductionProfile, runtime: RuntimeMetadata) -> list[dict[str, str]]:
    candidate = profile.candidate_spec or {}
    checks: list[dict[str, str]] = []

    def compare(label: str, field: str, actual: Any, *, optional: bool = False) -> None:
        expected = candidate.get(field)
        if expected in (None, "", "UNSET"):
            checks.append(_check(label, False, f"candidate {field} is unresolved"))
            return
        if optional and expected in {NOT_EXPOSED_VALUE, NOT_APPLICABLE_VALUE}:
            exposed = actual not in (None, "", {})
            checks.append(_check(label, not exposed, "not exposed by current runtime" if not exposed else f"runtime exposes {actual!r}"))
            return
        if actual in (None, "", {}):
            checks.append(_check(label, False, f"expected={expected!r}; actual=unavailable"))
            return
        checks.append(_check(label, actual == expected, f"expected={expected!r}; actual={actual!r}"))

    compare("Provider identity", "provider", runtime.provider)
    compare("Provider backend identity", "provider_backend", runtime.provider_backend, optional=True)
    compare("Provider revision identity", "model_revision", getattr(runtime, "model_revision", None), optional=True)
    compare("Provider quantization/dtype identity", "quantization_or_dtype", runtime.quantization_or_dtype, optional=True)
    compare("Context configuration identity", "context_configuration", runtime.context_configuration)
    compare("Image preprocessing identity", "image_preprocessing_settings", runtime.image_preprocessing_settings)
    return checks


def _vision_evidence_status(root: Path, profile: ProductionProfile) -> tuple[bool, str]:
    """Find candidate-bound multimodal proof in the finalized model evidence."""

    manifest_path = _resolve_path(root, profile.release_manifest)
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False, "release manifest is unavailable"
    evidence_paths = manifest.get("evidence_paths") if isinstance(manifest, dict) else None
    if not isinstance(evidence_paths, dict):
        return False, "release manifest has no evidence paths"
    for evidence_type in ("model_validation", "model_high_risk_stability", "model_held_out"):
        raw_path = evidence_paths.get(evidence_type)
        if not raw_path:
            continue
        try:
            record = load_evidence(
                _resolve_path(root, str(raw_path)),
                expected_type=evidence_type,
                subject_git_sha=profile.subject_git_sha,
                deployment_fingerprint=profile.deployment_fingerprint,
                repository_root=root,
                candidate_spec=profile.candidate_spec,
                require_candidate_spec=True,
            )
        except (EvidenceValidationError, OSError, ValueError):
            continue
        payload = record.get("payload", {})
        if (
            payload.get("vision_input_proven") is True
            and payload.get("target_model_approved") is True
            and payload.get("quality_metrics_authoritative") is True
            and payload.get("effective_model") == profile.effective_model
        ):
            return True, f"candidate-bound multimodal proof from {evidence_type}"
    return False, "no candidate-bound authoritative multimodal proof"


def _installed_build_status(root: Path, profile: ProductionProfile) -> tuple[bool, str]:
    path = root.expanduser().resolve() / ".k-slide-install.json"
    if path.is_symlink() or not path.is_file():
        return False, "installed build manifest is missing"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False, "installed build manifest is unreadable"
    if not isinstance(value, dict) or value.get("source_git_sha") != profile.subject_git_sha:
        return False, f"installed build subject mismatch: {value.get('source_git_sha') if isinstance(value, dict) else 'invalid'}"
    return True, str(value.get("source_git_sha"))


def production_checks(root: Path, runtime: RuntimeMetadata) -> list[dict[str, str]]:
    """Return fail-closed production checks without changing run state."""

    checks: list[dict[str, str]] = []
    try:
        profile = load_production_profile(root)
    except KSlideError as exc:
        return [_check("Production profile", False, exc.message)]
    checks.append(_check("Production profile schema", profile.schema_version == "1.0", profile.schema_version))
    checks.append(_check("Release state", profile.release_state == ReleaseState.PRODUCTION_CERTIFIED.value, profile.release_state))
    candidate_missing = candidate_completeness(profile.candidate_spec or {}, ReleaseState.PRODUCTION_CERTIFIED.value)
    checks.append(_check("Candidate completeness", not candidate_missing, "complete" if not candidate_missing else "unresolved=" + ",".join(candidate_missing)))
    expected_kslide = (profile.candidate_spec or {}).get("kslide_version")
    checks.append(_check("K-Slide version", runtime.kslide_version == expected_kslide, f"expected={expected_kslide}; actual={runtime.kslide_version}"))
    checks.append(_check("OpenCode version", runtime.opencode_version == profile.opencode_version, f"expected={profile.opencode_version}; actual={runtime.opencode_version or 'unknown'}"))
    from .model_policy import ModelPolicy

    candidate_policy = (profile.candidate_spec or {}).get("model_policy")
    policy = ModelPolicy.from_mapping(candidate_policy) if isinstance(candidate_policy, dict) else load_model_policy(root)
    checks.append(_check("Requested/effective model policy", policy.approved(requested=profile.requested_model, effective=profile.effective_model), f"requested={profile.requested_model}; effective={profile.effective_model}"))
    checks.append(_check("Runtime model match", runtime.reported_model_id == profile.effective_model, runtime.reported_model_id or "unknown"))
    checks.extend(_runtime_identity_checks(profile, runtime))
    installed_ok, installed_detail = _installed_build_status(root, profile)
    checks.append(_check("Installed build identity", installed_ok, installed_detail))
    vision_evidence_ok, vision_evidence_detail = _vision_evidence_status(root, profile)
    vision_runtime_ok = runtime.vision_support is not False
    vision_identity_ok = runtime.reported_model_id == profile.effective_model
    checks.append(_check("Vision capability", vision_identity_ok and vision_runtime_ok and vision_evidence_ok, vision_evidence_detail if vision_evidence_ok else "not proven: " + vision_evidence_detail))
    checks.append(_check("OCR policy", profile.ocr_provider == "paddle", profile.ocr_provider))
    asset_manifest = Path(profile.ocr_asset_manifest).expanduser()
    if not asset_manifest.is_absolute():
        asset_manifest = root.expanduser().resolve() / asset_manifest
    manifest_ok, manifest_detail = _asset_manifest_status(asset_manifest) if asset_manifest.is_file() else (False, "manifest is missing")
    checks.append(_check("OCR asset manifest", manifest_ok, manifest_detail))
    checks.append(_check("Retention policy", profile.retention_days > 0, str(profile.retention_days)))
    checks.append(_check("Tenant isolation", profile.tenant_isolation == "workspace_per_session", profile.tenant_isolation))
    checks.append(_check("Network egress", profile.network_egress == "approved_inference_only", profile.network_egress))
    checks.append(_check("Model data attestation", bool(profile.model_data_attestation and profile.model_data_attestation != "UNSET"), profile.model_data_attestation or "missing"))
    run_root = root.expanduser().resolve() / ".k-slide-runs"
    mode_ok = run_root.is_dir() and (run_root.stat().st_mode & 0o077) == 0
    checks.append(_check("Run directory permissions", mode_ok, oct(run_root.stat().st_mode & 0o777) if run_root.exists() else "missing"))
    checks.append(_check("LibreOffice", bool(shutil.which("libreoffice") or shutil.which("soffice")), "binary discovered" if (shutil.which("libreoffice") or shutil.which("soffice")) else "not discovered"))
    checks.append(_check("Paddle runtime", importlib.util.find_spec("paddle") is not None and importlib.util.find_spec("paddleocr") is not None, "packages discovered" if importlib.util.find_spec("paddle") and importlib.util.find_spec("paddleocr") else "packages missing"))
    try:
        actual_python = os.sys.version.split()[0]
        checks.append(_check("Python version", actual_python == profile.python_version or actual_python.startswith(profile.python_version + "."), f"expected={profile.python_version}; actual={actual_python}"))
        checks.append(_check("Paddle version", importlib.metadata.version("paddlepaddle") == profile.paddle_version, f"expected={profile.paddle_version}"))
        checks.append(_check("PaddleOCR version", importlib.metadata.version("paddleocr") == profile.paddleocr_version, f"expected={profile.paddleocr_version}"))
    except importlib.metadata.PackageNotFoundError as exc:
        checks.append(_check("Pinned OCR dependency versions", False, str(exc)))
    office_version = _version_from_command("libreoffice") or _version_from_command("soffice")
    checks.append(_check("LibreOffice version", bool(office_version and profile.libreoffice_version != "UNSET" and profile.libreoffice_version in office_version), f"expected={profile.libreoffice_version}; actual={office_version or 'missing'}"))
    try:
        selection = create_ocr_provider(OCRProviderPolicy.PADDLE)
        checks.append(_check("Paddle provider initialization", selection.effective == "paddle", selection.version))
    except KSlideError as exc:
        checks.append(_check("Paddle provider initialization", False, f"{exc.code.value}: {exc.message}"))
    except Exception as exc:
        checks.append(_check("Paddle provider initialization", False, str(exc)))
    checks.append(_check("Offline OCR mode", os.environ.get("KSLIDE_PADDLE_REQUIRE_LOCAL_ASSETS", "0").lower() in {"1", "true", "yes"}, "local assets required" if os.environ.get("KSLIDE_PADDLE_REQUIRE_LOCAL_ASSETS", "0").lower() in {"1", "true", "yes"} else "offline asset enforcement disabled"))
    checks.extend(_manifest_and_fingerprint_status(root, profile, runtime))
    return checks
