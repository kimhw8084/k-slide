"""Fail-closed production deployment profile and doctor checks."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from .errors import ErrorCode, KSlideError
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
    retention_days: int
    tenant_isolation: str
    network_egress: str
    certification_fingerprint: str
    model_data_attestation: str

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> "ProductionProfile":
        required = ("release_state", "opencode_version", "requested_model", "effective_model", "ocr_provider", "ocr_asset_manifest", "retention_days", "tenant_isolation", "network_egress", "certification_fingerprint", "model_data_attestation")
        missing = [key for key in required if key not in value]
        if missing:
            raise KSlideError(ErrorCode.PRODUCTION_PROFILE_INVALID, "Production profile is missing required fields.", {"fields": missing})
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
            retention_days=retention_days,
            tenant_isolation=str(value["tenant_isolation"]),
            network_egress=str(value["network_egress"]),
            certification_fingerprint=str(value["certification_fingerprint"]),
            model_data_attestation=str(value["model_data_attestation"]),
        )


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
        if not candidate.is_file():
            return False, f"asset is missing: {candidate.name}"
    return True, f"{len(files)} local assets"


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
    checks.append(_check("Requested model", profile.requested_model == "google/gemma-4-31b-it" or profile.requested_model.startswith("approved:"), profile.requested_model))
    checks.append(_check("Effective model identity", profile.effective_model == "google/gemma-4-31b-it" or profile.effective_model.startswith("approved:"), profile.effective_model))
    checks.append(_check("Runtime model match", runtime.reported_model_id in {profile.requested_model, profile.effective_model}, runtime.reported_model_id or "unknown"))
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
        selection = create_ocr_provider(OCRProviderPolicy.PADDLE)
        checks.append(_check("Paddle provider initialization", selection.effective == "paddle", selection.version))
    except KSlideError as exc:
        checks.append(_check("Paddle provider initialization", False, f"{exc.code.value}: {exc.message}"))
    except Exception as exc:
        checks.append(_check("Paddle provider initialization", False, str(exc)))
    checks.append(_check("Offline OCR mode", os.environ.get("KSLIDE_PADDLE_REQUIRE_LOCAL_ASSETS", "0").lower() in {"1", "true", "yes"}, "local assets required" if os.environ.get("KSLIDE_PADDLE_REQUIRE_LOCAL_ASSETS", "0").lower() in {"1", "true", "yes"} else "offline asset enforcement disabled"))
    checks.append(_check("Certification fingerprint", bool(profile.certification_fingerprint and profile.certification_fingerprint != "UNSET"), profile.certification_fingerprint or "missing"))
    return checks
