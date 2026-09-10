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
    EvidenceValidationError,
    build_deployment_factors,
    canonical_corpus_identity,
    certification_fingerprint,
    deployment_fingerprint,
    load_evidence,
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
                record = load_evidence(_resolve_path(root, str(evidence_path)), expected_type=str(evidence_type), subject_git_sha=profile.subject_git_sha, deployment_fingerprint=profile.deployment_fingerprint, repository_root=root)
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
    policy = load_model_policy(root)
    try:
        from evals.scenarios import split_manifest

        corpus = canonical_corpus_identity(split_manifest())
    except ImportError:
        corpus = canonical_corpus_identity(None)
    factors = build_deployment_factors(root, subject_git_sha=profile.subject_git_sha, runtime=runtime, profile=profile.as_dict(), model_policy=policy, corpus=corpus)
    expected_deployment = deployment_fingerprint(factors)
    deployment_match = expected_deployment == profile.deployment_fingerprint
    checks.append(_check("Deployment fingerprint", deployment_match, f"expected={expected_deployment}; profile={profile.deployment_fingerprint}"))
    checks.append(_check("Certification freshness", deployment_match and certification_match, "current" if deployment_match and certification_match else "CERTIFICATION_STALE"))
    return checks


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
    checks.append(_check("OpenCode version", runtime.opencode_version == profile.opencode_version, f"expected={profile.opencode_version}; actual={runtime.opencode_version or 'unknown'}"))
    policy = load_model_policy(root)
    checks.append(_check("Requested/effective model policy", policy.approved(requested=profile.requested_model, effective=profile.effective_model), f"requested={profile.requested_model}; effective={profile.effective_model}"))
    checks.append(_check("Runtime model match", runtime.reported_model_id in {profile.requested_model, profile.effective_model}, runtime.reported_model_id or "unknown"))
    installed_ok, installed_detail = _installed_build_status(root, profile)
    checks.append(_check("Installed build identity", installed_ok, installed_detail))
    checks.append(_check("Vision capability", runtime.vision_support is True, "proven" if runtime.vision_support is True else "not proven"))
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
        checks.append(_check("Python version", os.sys.version.split()[0] == profile.python_version, f"expected={profile.python_version}; actual={os.sys.version.split()[0]}"))
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
