"""Evidence-bound release certification primitives.

This module is intentionally dependency-free.  It is imported by the runtime
doctor as well as the evaluation/release tooling so a production state cannot
be created by changing a label or by supplying an unbound attestation string.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Iterable


EVIDENCE_SCHEMA_VERSION = "2.0"
EVIDENCE_TYPES = (
    "runtime",
    "heavy_runtime",
    "model_validation",
    "model_high_risk_stability",
    "model_held_out",
    "internal_bilingual",
    "zero_korean_comprehension",
    "security",
    "reliability",
    "model_data_policy",
    "pilot_canary",
    "governance",
)
MACHINE_EVIDENCE_TYPES = {
    "runtime",
    "heavy_runtime",
    "model_validation",
    "model_high_risk_stability",
    "model_held_out",
    "security",
    "reliability",
    "governance",
}
_HEX64 = set("0123456789abcdef")


class EvidenceValidationError(ValueError):
    """Raised when evidence is missing, malformed, stale, or insufficient."""


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise EvidenceValidationError(f"file is missing or symlinked: {path.name}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _require_hex(value: Any, label: str) -> str:
    text = str(value or "")
    if len(text) != 64 or set(text.lower()) - _HEX64:
        raise EvidenceValidationError(f"{label} must be a SHA-256 hex digest")
    return text.lower()


def _is_true(value: Any) -> bool:
    return value is True


def _positive_int(value: Any, minimum: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= minimum


def validate_evidence_payload(evidence_type: str, payload: dict[str, Any]) -> None:
    """Validate substantive pass criteria for one evidence class."""

    if not isinstance(payload, dict) or not payload:
        raise EvidenceValidationError(f"{evidence_type} evidence has no payload")
    requirements: dict[str, tuple[str, ...]] = {
        "runtime": ("runtime_pass", "required_media_compliance", "run_complete", "simple_pass", "three_slide_pass", "five_slide_pass"),
        "heavy_runtime": ("heavy_pass", "networkless_pass", "representative_engine_pass", "full_engine_pass", "unexpected_capability_blocks"),
        "model_validation": ("split", "target_model_approved", "quality_metrics_authoritative", "critical_failure_count", "repetitions", "configuration_hash", "required_media_compliance"),
        "model_high_risk_stability": ("target_model_approved", "worst_critical_frequency", "repetitions", "configuration_hash", "required_group_coverage"),
        "model_held_out": ("split", "target_model_approved", "quality_metrics_authoritative", "critical_failure_count", "configuration_hash", "corpus_fingerprint", "held_out_fingerprint"),
        "internal_bilingual": ("attestation_id", "artifact_count", "work_unit_count", "critical_business_meaning_errors", "critical_numeric_date_unit_errors", "critical_modality_escalations", "critical_table_mapping_errors", "critical_trend_reversals", "unsupported_critical_executive_claims", "overall_noncritical_semantic_fidelity", "locked_terminology"),
        "zero_korean_comprehension": ("attestation_id", "users", "answers", "critical_question_accuracy", "overall_comprehension", "critical_misunderstanding"),
        "security": ("dependency_audit_pass", "secret_scan_pass", "static_scan_pass", "unresolved_high_findings", "unresolved_critical_findings", "secret_findings"),
        "reliability": ("timeout_recovery_pass", "resume_pass", "fifty_slide_pass", "concurrency_pass", "slo_pass", "concurrent_runs"),
        "model_data_policy": ("attestation_id", "approved_for_internal_artifacts"),
        "pilot_canary": ("attestation_id", "users", "artifacts", "critical_confirmed_errors", "cross_user_exposure", "security_incidents", "silent_incomplete_output"),
        "governance": ("codeowners_pass", "branch_protection_pass", "required_ci_pass", "review_required"),
    }
    missing = [key for key in requirements.get(evidence_type, ()) if key not in payload]
    if missing:
        raise EvidenceValidationError(f"{evidence_type} evidence is missing payload fields: {', '.join(missing)}")
    if evidence_type == "runtime":
        if not all(_is_true(payload[key]) for key in ("runtime_pass", "required_media_compliance", "run_complete")):
            raise EvidenceValidationError("runtime evidence does not prove the complete OpenCode lifecycle")
    elif evidence_type == "heavy_runtime":
        if not all(_is_true(payload[key]) for key in ("heavy_pass", "networkless_pass", "representative_engine_pass")):
            raise EvidenceValidationError("heavy runtime evidence does not prove required offline capabilities")
    elif evidence_type == "model_validation":
        if payload["split"] != "validation" or not _is_true(payload["target_model_approved"]) or not _is_true(payload["quality_metrics_authoritative"]):
            raise EvidenceValidationError("validation evidence is not authoritative target-model evidence")
        if payload["critical_failure_count"] != 0 or not _positive_int(payload["repetitions"], 3):
            raise EvidenceValidationError("validation evidence fails critical/repetition gates")
    elif evidence_type == "model_high_risk_stability":
        if not _is_true(payload["target_model_approved"]) or payload["worst_critical_frequency"] != 0 or not _positive_int(payload["repetitions"], 5):
            raise EvidenceValidationError("high-risk stability evidence fails target, critical-frequency, or repetition gates")
    elif evidence_type == "model_held_out":
        if payload["split"] != "held_out" or not _is_true(payload["target_model_approved"]) or not _is_true(payload["quality_metrics_authoritative"]):
            raise EvidenceValidationError("held-out evidence is not authoritative target-model evidence")
        if payload["critical_failure_count"] != 0:
            raise EvidenceValidationError("held-out evidence fails critical gate")
    elif evidence_type == "internal_bilingual":
        if not str(payload["attestation_id"]) or payload["attestation_id"] == "UNSET" or not _positive_int(payload["artifact_count"], 50) or not _positive_int(payload["work_unit_count"], 200):
            raise EvidenceValidationError("internal bilingual sample/attestation is insufficient")
        critical = ("critical_business_meaning_errors", "critical_numeric_date_unit_errors", "critical_modality_escalations", "critical_table_mapping_errors", "critical_trend_reversals", "unsupported_critical_executive_claims")
        if any(payload[key] != 0 for key in critical) or float(payload["overall_noncritical_semantic_fidelity"]) < 0.98 or float(payload["locked_terminology"]) < 0.995:
            raise EvidenceValidationError("internal bilingual quality gates failed")
    elif evidence_type == "zero_korean_comprehension":
        if not str(payload["attestation_id"]) or payload["attestation_id"] == "UNSET" or not _positive_int(payload["users"], 10) or not _positive_int(payload["answers"], 100):
            raise EvidenceValidationError("zero-Korean study sample/attestation is insufficient")
        if float(payload["critical_question_accuracy"]) != 1.0 or float(payload["overall_comprehension"]) < 0.95 or payload["critical_misunderstanding"] != 0:
            raise EvidenceValidationError("zero-Korean comprehension gates failed")
    elif evidence_type == "security":
        if not all(_is_true(payload[key]) for key in ("dependency_audit_pass", "secret_scan_pass", "static_scan_pass")) or any(payload[key] != 0 for key in ("unresolved_high_findings", "unresolved_critical_findings", "secret_findings")):
            raise EvidenceValidationError("security evidence has failed or unresolved findings")
    elif evidence_type == "reliability":
        if not all(_is_true(payload[key]) for key in ("timeout_recovery_pass", "resume_pass", "fifty_slide_pass", "concurrency_pass", "slo_pass")) or not _positive_int(payload["concurrent_runs"], 5):
            raise EvidenceValidationError("reliability evidence fails recovery, load, or SLO gates")
    elif evidence_type == "model_data_policy":
        if not str(payload["attestation_id"]) or payload["attestation_id"] == "UNSET" or not _is_true(payload["approved_for_internal_artifacts"]):
            raise EvidenceValidationError("model-data policy approval is missing")
    elif evidence_type == "pilot_canary":
        if not str(payload["attestation_id"]) or payload["attestation_id"] == "UNSET" or not _positive_int(payload["users"], 5) or not _positive_int(payload["artifacts"], 50):
            raise EvidenceValidationError("pilot sample/attestation is insufficient")
        if any(payload[key] != 0 for key in ("critical_confirmed_errors", "cross_user_exposure", "security_incidents", "silent_incomplete_output")):
            raise EvidenceValidationError("pilot safety gate failed")
    elif evidence_type == "governance" and not all(_is_true(payload[key]) for key in ("codeowners_pass", "branch_protection_pass", "required_ci_pass", "review_required")):
        raise EvidenceValidationError("repository governance evidence is incomplete")


def load_evidence(path: Path, *, expected_type: str | None = None, subject_git_sha: str | None = None, deployment_fingerprint: str | None = None, repository_root: Path | None = None) -> dict[str, Any]:
    """Load and validate one immutable evidence envelope."""

    path = path.expanduser()
    if path.is_symlink() or not path.is_file():
        raise EvidenceValidationError(f"evidence file is missing or symlinked: {path.name}")
    path = path.resolve()
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceValidationError(f"evidence file is unreadable or malformed: {path.name}") from exc
    if not isinstance(value, dict):
        raise EvidenceValidationError("evidence envelope must be an object")
    if value.get("schema_version") != EVIDENCE_SCHEMA_VERSION:
        raise EvidenceValidationError("unsupported evidence schema version")
    evidence_type = value.get("evidence_type")
    if evidence_type not in EVIDENCE_TYPES:
        raise EvidenceValidationError("unknown evidence type")
    if expected_type and evidence_type != expected_type:
        raise EvidenceValidationError(f"expected {expected_type} evidence, found {evidence_type}")
    if value.get("status") != "PASS":
        raise EvidenceValidationError(f"evidence status is not PASS: {value.get('status')}")
    if subject_git_sha and value.get("subject_git_sha") != subject_git_sha:
        raise EvidenceValidationError("evidence subject_git_sha does not match candidate")
    evidence_fp = value.get("deployment_fingerprint")
    _require_hex(evidence_fp, "deployment_fingerprint")
    if deployment_fingerprint and evidence_fp != deployment_fingerprint:
        raise EvidenceValidationError("evidence deployment_fingerprint does not match candidate")
    if not str(value.get("generated_at") or ""):
        raise EvidenceValidationError("evidence generated_at is missing")
    payload = value.get("payload")
    if evidence_type in MACHINE_EVIDENCE_TYPES:
        from .evidence_adapters import AdapterError, verify_machine_envelope

        try:
            verified = verify_machine_envelope(path, value, subject_git_sha=subject_git_sha, deployment_fingerprint=deployment_fingerprint, root=repository_root)
        except AdapterError as exc:
            raise EvidenceValidationError(str(exc)) from exc
        if payload != verified["payload"]:
            raise EvidenceValidationError("machine evidence payload is not the adapter-derived payload")
        validate_evidence_payload(str(evidence_type), payload)
        identity = evidence_identity(value, sources=verified["sources"])
        return {**value, "path": str(path), "sha256": sha256_file(path), "envelope_sha256": sha256_file(path), "evidence_identity": identity}
    validate_evidence_payload(str(evidence_type), payload)
    physical = sha256_file(path)
    return {**value, "path": str(path), "sha256": physical, "envelope_sha256": physical, "evidence_identity": evidence_identity(value)}


def write_evidence(path: Path, *, evidence_type: str, subject_git_sha: str, deployment_fingerprint: str, payload: dict[str, Any], generated_at: str, attestation_id: str | None = None) -> Path:
    """Write a source-free envelope after validating its substantive payload."""

    if evidence_type not in EVIDENCE_TYPES:
        raise EvidenceValidationError("unknown evidence type")
    if evidence_type in MACHINE_EVIDENCE_TYPES:
        raise EvidenceValidationError("machine evidence must be derived from source results by evidence_adapters")
    validate_evidence_payload(evidence_type, payload)
    envelope: dict[str, Any] = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "evidence_type": evidence_type,
        "status": "PASS",
        "subject_git_sha": subject_git_sha,
        "deployment_fingerprint": _require_hex(deployment_fingerprint, "deployment_fingerprint"),
        "generated_at": generated_at,
        "payload": payload,
    }
    if attestation_id is not None:
        envelope["attestation_id"] = attestation_id
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(envelope, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return path


def _tree_hash(root: Path) -> str | None:
    if not root.is_dir():
        return None
    entries: list[dict[str, str]] = []
    for path in sorted(item for item in root.rglob("*") if item.is_file() and not item.is_symlink()):
        entries.append({"path": path.relative_to(root).as_posix(), "sha256": sha256_file(path)})
    return sha256_bytes(canonical_bytes(entries))


def _git_sha(root: Path) -> str | None:
    try:
        result = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def _manifest_hash(profile: dict[str, Any], root: Path) -> str | None:
    raw = profile.get("ocr_asset_manifest")
    if not raw or str(raw).startswith("UNSET"):
        return None
    path = Path(str(raw)).expanduser()
    if not path.is_absolute():
        path = root / path
    try:
        return sha256_file(path)
    except EvidenceValidationError:
        return None


def build_deployment_factors(root: Path, *, subject_git_sha: str | None = None, runtime: Any | None = None, profile: dict[str, Any] | None = None, model_policy: Any | None = None, corpus: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build stable, path/timestamp-free material deployment identity."""

    root = root.expanduser().resolve()
    profile = dict(profile or {})
    runtime_dict = runtime.as_dict() if hasattr(runtime, "as_dict") else dict(runtime or {})
    runtime_material = {key: runtime_dict.get(key) for key in ("opencode_version", "provider", "reported_model_id", "model_family", "model_size", "instruction_tuned_status", "vision_support", "thinking_support", "provider_backend", "quantization_or_dtype", "context_configuration", "image_preprocessing_settings")}
    profile_material = {key: value for key, value in profile.items() if key not in {"certification_fingerprint", "deployment_fingerprint", "subject_git_sha", "release_manifest", "release_manifest_sha256", "generated_at"}}
    from . import __version__

    factors: dict[str, Any] = {
        "kslide_version": profile.get("kslide_version") or __version__,
        "subject_git_sha": subject_git_sha or _git_sha(root) or "UNSET",
        "runtime": runtime_material,
        "profile": profile_material,
        "ocr_asset_manifest_sha256": _manifest_hash(profile, root),
        "constraints_sha256": None,
        "prompt_tree_sha256": _tree_hash(root / "prompts"),
        "termbase_tree_sha256": _tree_hash(root / "termbase"),
        "model_policy": model_policy.as_dict() if hasattr(model_policy, "as_dict") else model_policy,
        "schemas": {"evidence_ir": "1.0", "translation_patch": "1.0", "slide_ir": "1.0"},
        "corpus": corpus or {},
    }
    constraints = root / "constraints-production.txt"
    if constraints.is_file():
        factors["constraints_sha256"] = sha256_file(constraints)
    return factors


def deployment_fingerprint(factors: dict[str, Any]) -> str:
    return sha256_bytes(canonical_bytes(factors))


def certification_fingerprint(*, deployment: str, evidence_hashes: dict[str, str], release_state: str, champion_hash: str | None = None) -> str:
    return sha256_bytes(canonical_bytes({"deployment_fingerprint": deployment, "evidence_hashes": dict(sorted(evidence_hashes.items())), "release_state": release_state, "champion_hash": champion_hash}))


def evidence_hashes(records: Iterable[dict[str, Any]]) -> dict[str, str]:
    return {str(item["evidence_type"]): str(item.get("evidence_identity") or item["sha256"]) for item in records}


def evidence_identity(envelope: dict[str, Any], *, sources: list[dict[str, str]] | None = None) -> str:
    """Stable evidence identity excluding packaging metadata such as timestamps."""

    identity = {
        "schema_version": envelope.get("schema_version"),
        "evidence_type": envelope.get("evidence_type"),
        "adapter_version": envelope.get("adapter_version"),
        "subject_git_sha": envelope.get("subject_git_sha"),
        "deployment_fingerprint": envelope.get("deployment_fingerprint"),
        "sources": sorted(
            [{"role": item.get("role"), "sha256": item.get("sha256")} for item in (sources if sources is not None else envelope.get("sources", []))],
            key=lambda item: item.get("role", ""),
        ),
        "payload": envelope.get("payload"),
    }
    return sha256_bytes(canonical_bytes(identity))
