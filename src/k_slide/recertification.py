"""Closed champion promotion and scoped evidence recertification contracts.

The dependency registry below mirrors the evidence producer contracts: runtime,
model-run, heavy-runtime, security, and governance evidence inspect or exercise
the exact repository subject. Model-data policy evidence is an attestation over
explicit candidate policy fields and has no repository-code input; it can cross
a subject transition only when its deterministic dependency projection is
unchanged. The registry is repository-owned so callers cannot narrow impact.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .certification import (
    CANDIDATE_INPUT_FIELDS,
    EVIDENCE_TYPES,
    EvidenceValidationError,
    canonical_bytes,
    canonical_candidate_factors,
    candidate_completeness,
    candidate_deployment_fingerprint,
    load_evidence,
    sha256_bytes,
    validate_evidence_payload,
    validate_model_evidence_corpus_binding,
    _governed_termbase_identity_resolved,
)


CHAMPION_PROMOTION_CONTRACT_VERSION = "1.0"
CHAMPION_PROMOTION_RECERTIFICATION_VERSION = "1.1"
CHANGE_IMPACT_POLICY_VERSION = "1.1"
RECERTIFICATION_CONTRACT_VERSION = "1.0"
CHAMPION_PROMOTION_STATES = frozenset({"PROMOTED", "FROZEN_PROMOTED"})
MODEL_PROMOTION_EVIDENCE = (
    "model_validation",
    "model_high_risk_stability",
    "model_held_out",
)
_MODEL_PURPOSES = {
    "model_validation": ("private_representative", "private_evaluation"),
    "model_high_risk_stability": ("frozen_high_risk", "comparison"),
    "model_held_out": ("sealed_held_out", "promotion"),
}
_HEX = frozenset("0123456789abcdef")


def _identity(value: dict[str, Any], identity_field: str) -> str:
    body = {key: item for key, item in value.items() if key != identity_field}
    return sha256_bytes(canonical_bytes(body))


def _require_identity(raw: Any, label: str) -> str:
    if not isinstance(raw, str) or len(raw) != 64 or set(raw) - _HEX:
        raise EvidenceValidationError(f"{label} must be a lowercase SHA-256 identity")
    return raw


def champion_promotion_identity(record: dict[str, Any]) -> str:
    """Return the deterministic identity of a promotion record."""

    if not isinstance(record, dict):
        raise EvidenceValidationError("champion promotion record must be an object")
    return _identity(record, "promotion_identity")


def _load_promotion_evidence(
    evidence_type: str,
    supplied: dict[str, Any],
    *,
    candidate_spec: dict[str, Any],
    root: Path | None,
) -> dict[str, Any]:
    if not isinstance(supplied, dict) or supplied.get("evidence_type") != evidence_type:
        raise EvidenceValidationError(f"promotion is missing validated {evidence_type} evidence")
    raw_path = supplied.get("path")
    if not isinstance(raw_path, str) or not raw_path:
        raise EvidenceValidationError(f"promotion {evidence_type} evidence has no re-verifiable envelope path")
    try:
        record = load_evidence(
            Path(raw_path),
            expected_type=evidence_type,
            subject_git_sha=str(candidate_spec.get("subject_git_sha") or ""),
            deployment_fingerprint=candidate_deployment_fingerprint(candidate_spec),
            repository_root=root,
            candidate_spec=candidate_spec,
            require_candidate_spec=True,
        )
    except (OSError, ValueError, TypeError) as exc:
        if isinstance(exc, EvidenceValidationError):
            raise
        raise EvidenceValidationError(f"promotion {evidence_type} evidence could not be revalidated") from exc
    if supplied.get("evidence_identity") != record.get("evidence_identity"):
        raise EvidenceValidationError(f"promotion {evidence_type} evidence identity changed")
    if supplied.get("envelope_sha256", supplied.get("sha256")) != record.get("envelope_sha256"):
        raise EvidenceValidationError(f"promotion {evidence_type} evidence envelope hash changed")
    return record


def _promotion_evidence_details(
    candidate_spec: dict[str, Any],
    records: dict[str, dict[str, Any]],
    *,
    policy: Any,
    root: Path | None,
    recertification: dict[str, Any] | None = None,
    prior_records: dict[str, dict[str, Any]] | None = None,
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], str, str]:
    candidate = canonical_candidate_factors(candidate_spec)
    deployment = candidate_deployment_fingerprint(candidate_spec)
    subject = str(candidate_spec.get("subject_git_sha") or "")
    requested = str(candidate_spec.get("requested_model") or "")
    effective = str(candidate_spec.get("effective_model") or "")
    if not subject or subject.upper() == "UNSET" or not requested or requested.upper() == "UNSET" or not effective or effective.upper() == "UNSET":
        raise EvidenceValidationError("promotion candidate subject and requested/effective models must be resolved")
    if not policy.approved(requested=requested, effective=effective):
        raise EvidenceValidationError("promotion candidate model is not approved by ModelPolicy")
    unresolved = candidate_completeness(candidate_spec, "SYNTHETIC_PRODUCTION_CANDIDATE")
    if unresolved:
        raise EvidenceValidationError("promotion candidate is incomplete: " + ", ".join(unresolved))
    for field in ("provider_backend", "model_revision", "quantization_or_dtype"):
        value = candidate_spec.get(field)
        if value is None or (isinstance(value, str) and value.strip().upper() in {"", "UNSET", "NOT_YET_CONFIGURED"}):
            raise EvidenceValidationError(f"promotion candidate {field} must be resolved or explicitly unavailable")
    route = candidate_spec.get("inference_route_identity")
    endpoint = candidate_spec.get("inference_endpoint_identity")
    if not isinstance(route, str) or not route.strip() or route.strip().upper() in {"UNSET", "NOT_YET_CONFIGURED"}:
        raise EvidenceValidationError("promotion candidate inference route identity is unresolved")
    _require_identity(endpoint, "promotion candidate inference endpoint identity")
    for field in ("constraints_sha256", "resolved_dependency_set_sha256"):
        _require_identity(candidate_spec.get(field), f"promotion candidate {field}")
    termbase = candidate_spec.get("termbase_identity")
    if not _governed_termbase_identity_resolved(termbase):
        raise EvidenceValidationError("promotion candidate termbase governance identity is unresolved")
    if candidate_spec.get("termbase_hash") != termbase.get("hash") or candidate_spec.get("termbase_version") != termbase.get("version"):
        raise EvidenceValidationError("promotion candidate termbase version or hash is inconsistent")

    details: dict[str, dict[str, Any]] = {}
    behavior_hashes: set[str] = set()
    formats: set[tuple[str, ...]] = set()
    behavior_configuration = candidate_spec.get("behavior_configuration")
    if not isinstance(behavior_configuration, dict):
        raise EvidenceValidationError("promotion candidate behavior configuration is missing")
    try:
        from evals.experiments import behavior_configuration_hash

        candidate_behavior_hash = behavior_configuration_hash(behavior_configuration, strict=True)
    except (ImportError, TypeError, ValueError) as exc:
        raise EvidenceValidationError("promotion candidate behavior configuration cannot be canonicalized") from exc
    canonical_effective = policy.canonical_effective(requested=requested, effective=effective)
    prior_records = prior_records or {}
    old_candidate: dict[str, Any] | None = None
    exemption_by_type: dict[str, dict[str, Any]] = {}
    recertification_identity: str | None = None
    if recertification is not None:
        validate_recertification_record(
            recertification,
            candidate_spec,
            prior_records,
            root=root,
            expected_prior_release_manifest_sha256=str(recertification.get("prior_release_manifest_sha256") or ""),
        )
        old_candidate_value = recertification.get("old_candidate_spec")
        if not isinstance(old_candidate_value, dict):
            raise EvidenceValidationError("promotion recertification has no exact old candidate")
        old_candidate = old_candidate_value
        exemptions = recertification.get("exemptions")
        if not isinstance(exemptions, list):
            raise EvidenceValidationError("promotion recertification exemptions are malformed")
        exemption_by_type = {
            str(item["evidence_type"]): item
            for item in exemptions
            if isinstance(item, dict) and isinstance(item.get("evidence_type"), str)
        }
        recertification_identity = str(recertification.get("recertification_identity") or "")
    elif prior_records:
        raise EvidenceValidationError("promotion prior evidence requires a recertification bridge")
    for evidence_type in MODEL_PROMOTION_EVIDENCE:
        exemption = exemption_by_type.get(evidence_type)
        carried = exemption is not None
        if carried:
            assert old_candidate is not None
            record = _validate_old_evidence(
                evidence_type,
                prior_records.get(evidence_type),
                old_candidate=old_candidate,
                root=root,
            )
            supplied = records.get(evidence_type)
            if supplied is not None and (
                supplied.get("evidence_identity") != record.get("evidence_identity")
                or supplied.get("envelope_sha256") != record.get("envelope_sha256")
                or supplied.get("path") != record.get("path")
            ):
                raise EvidenceValidationError(f"promotion carried {evidence_type} evidence differs from the recertified envelope")
        else:
            record = _load_promotion_evidence(
                evidence_type,
                records.get(evidence_type),
                candidate_spec=candidate_spec,
                root=root,
            )
        payload = record.get("payload")
        if not isinstance(payload, dict):
            raise EvidenceValidationError(f"promotion {evidence_type} payload is missing")
        validate_evidence_payload(evidence_type, payload)
        validate_model_evidence_corpus_binding(evidence_type, payload, candidate_spec)
        if carried:
            assert old_candidate is not None and exemption is not None and recertification_identity is not None
            old_factors = canonical_candidate_factors(old_candidate)
            if record.get("subject_git_sha") != old_candidate.get("subject_git_sha") or record.get("deployment_fingerprint") != candidate_deployment_fingerprint(old_candidate):
                raise EvidenceValidationError(f"promotion carried {evidence_type} evidence is not bound to the exact old candidate")
            if not isinstance(record.get("candidate_spec"), dict) or canonical_candidate_factors(record["candidate_spec"]) != old_factors:
                raise EvidenceValidationError(f"promotion carried {evidence_type} evidence does not bind the exact old candidate")
        else:
            if record.get("subject_git_sha") != subject or record.get("deployment_fingerprint") != deployment:
                raise EvidenceValidationError(f"promotion {evidence_type} evidence is cross-candidate")
            if not isinstance(record.get("candidate_spec"), dict) or canonical_candidate_factors(record["candidate_spec"]) != candidate:
                raise EvidenceValidationError(f"promotion {evidence_type} evidence does not bind the exact candidate")
        if payload.get("requested_model") != requested or payload.get("effective_model") != canonical_effective:
            raise EvidenceValidationError(f"promotion {evidence_type} evidence model does not match the candidate")
        if payload.get("target_model_approved") is not True or payload.get("quality_metrics_authoritative") is not True:
            raise EvidenceValidationError(f"promotion {evidence_type} evidence is not authoritative target-model evidence")
        if payload.get("hard_gate_pass") is not True or payload.get("critical_failure_count") != 0 or payload.get("hard_gate_failure_count") != 0:
            raise EvidenceValidationError(f"promotion {evidence_type} evidence fails a hard gate")
        behavior_hash = payload.get("behavior_configuration_hash")
        if not isinstance(behavior_hash, str) or len(behavior_hash) != 64 or set(behavior_hash) - _HEX:
            raise EvidenceValidationError(f"promotion {evidence_type} behavior configuration identity is invalid")
        if payload.get("configuration_hash") != behavior_hash:
            raise EvidenceValidationError(f"promotion {evidence_type} configuration identities disagree")
        behavior_hashes.add(behavior_hash)
        formats.add(tuple(payload.get("formats", ())))
        expected_role, expected_purpose = _MODEL_PURPOSES[evidence_type]
        corpus = payload.get("corpus_set_identity")
        if not isinstance(corpus, dict) or corpus.get("role") != expected_role or payload.get("evaluation_purpose") != expected_purpose:
            raise EvidenceValidationError(f"promotion {evidence_type} corpus role or purpose is ineligible")
        evidence_identity = _require_identity(record.get("evidence_identity"), f"promotion {evidence_type} evidence identity")
        envelope_hash = _require_identity(record.get("envelope_sha256"), f"promotion {evidence_type} envelope hash")
        evidence_detail = {
            "evidence_identity": evidence_identity,
            "envelope_sha256": envelope_hash,
            "subject_git_sha": str(record.get("subject_git_sha") or ""),
            "deployment_fingerprint": str(record.get("deployment_fingerprint") or ""),
            "requested_model": requested,
            "effective_model": canonical_effective,
            "behavior_configuration_hash": behavior_hash,
            "corpus_set_identity": corpus,
            "evaluation_purpose": expected_purpose,
        }
        if carried:
            assert old_candidate is not None and exemption is not None and recertification_identity is not None
            evidence_detail["carry_forward"] = {
                "exemption_identity": exemption["exemption_identity"],
                "old_candidate_identity": {
                    "subject_git_sha": old_candidate["subject_git_sha"],
                    "deployment_fingerprint": candidate_deployment_fingerprint(old_candidate),
                    "candidate_factors_sha256": sha256_bytes(canonical_bytes(canonical_candidate_factors(old_candidate))),
                },
                "new_candidate_identity": {
                    "subject_git_sha": candidate_spec["subject_git_sha"],
                    "deployment_fingerprint": deployment,
                    "candidate_factors_sha256": sha256_bytes(canonical_bytes(candidate)),
                },
                "recertification_identity": recertification_identity,
            }
        details[evidence_type] = evidence_detail
    if len(behavior_hashes) != 1:
        raise EvidenceValidationError("promotion model evidence behavior configuration identities disagree")
    if behavior_hashes != {candidate_behavior_hash}:
        raise EvidenceValidationError("promotion model evidence behavior configuration does not match the candidate")
    if len(formats) != 1:
        raise EvidenceValidationError("promotion model evidence format plans disagree")
    carried_details = {
        evidence_type: {
            "evidence_identity": details[evidence_type]["evidence_identity"],
            "envelope_sha256": details[evidence_type]["envelope_sha256"],
            **details[evidence_type]["carry_forward"],
        }
        for evidence_type in MODEL_PROMOTION_EVIDENCE
        if "carry_forward" in details[evidence_type]
    }
    return details, carried_details, canonical_effective, next(iter(behavior_hashes))


def build_champion_promotion(
    candidate_spec: dict[str, Any],
    records: dict[str, dict[str, Any]],
    *,
    policy: Any,
    root: Path | None = None,
    state: str = "PROMOTED",
    recertification: dict[str, Any] | None = None,
    prior_records: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a closed promotion record from exact candidate-bound evidence."""

    if state not in CHAMPION_PROMOTION_STATES:
        raise EvidenceValidationError("champion promotion state is not in the closed state set")
    details, carried_details, effective, behavior_hash = _promotion_evidence_details(
        candidate_spec,
        records,
        policy=policy,
        root=root,
        recertification=recertification,
        prior_records=prior_records,
    )
    factors = canonical_candidate_factors(candidate_spec)
    deployment = candidate_deployment_fingerprint(candidate_spec)
    record: dict[str, Any] = {
        "contract_version": CHAMPION_PROMOTION_RECERTIFICATION_VERSION if carried_details else CHAMPION_PROMOTION_CONTRACT_VERSION,
        "state": state,
        "candidate_subject_git_sha": candidate_spec["subject_git_sha"],
        "candidate_deployment_fingerprint": deployment,
        "candidate_factors_sha256": sha256_bytes(canonical_bytes(factors)),
        "requested_model": candidate_spec["requested_model"],
        "effective_model": effective,
        "model_policy_sha256": sha256_bytes(canonical_bytes(factors.get("model_policy"))),
        "corpus_identity_sha256": sha256_bytes(canonical_bytes(factors.get("corpus_identity"))),
        "behavior_configuration_hash": behavior_hash,
        "evidence": details,
    }
    if carried_details:
        record["recertification_identity"] = recertification["recertification_identity"] if recertification else None
        record["carried_model_evidence"] = carried_details
    record["promotion_identity"] = champion_promotion_identity(record)
    return record


def validate_champion_promotion(
    record: dict[str, Any],
    candidate_spec: dict[str, Any],
    records: dict[str, dict[str, Any]],
    *,
    policy: Any,
    root: Path | None = None,
    recertification: dict[str, Any] | None = None,
    prior_records: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Independently revalidate a serialized promotion record."""

    base_keys = {
        "contract_version", "state", "candidate_subject_git_sha",
        "candidate_deployment_fingerprint", "candidate_factors_sha256",
        "requested_model", "effective_model", "model_policy_sha256",
        "corpus_identity_sha256", "behavior_configuration_hash", "evidence",
        "promotion_identity",
    }
    if not isinstance(record, dict) or not base_keys <= set(record):
        raise EvidenceValidationError("champion promotion record does not match the closed contract")
    version = record.get("contract_version")
    if version == CHAMPION_PROMOTION_CONTRACT_VERSION:
        if set(record) != base_keys:
            raise EvidenceValidationError("champion promotion record does not match the closed contract")
    elif version == CHAMPION_PROMOTION_RECERTIFICATION_VERSION:
        if set(record) != base_keys | {"recertification_identity", "carried_model_evidence"}:
            raise EvidenceValidationError("recertified champion promotion record does not match the closed contract")
    else:
        raise EvidenceValidationError("champion promotion version or state is unsupported")
    if record.get("state") not in CHAMPION_PROMOTION_STATES:
        raise EvidenceValidationError("champion promotion version or state is unsupported")
    actual_identity = champion_promotion_identity(record)
    if record.get("promotion_identity") != actual_identity:
        raise EvidenceValidationError("champion promotion identity does not match its content")
    details, carried_details, effective, behavior_hash = _promotion_evidence_details(
        candidate_spec,
        records,
        policy=policy,
        root=root,
        recertification=recertification,
        prior_records=prior_records,
    )
    if version == CHAMPION_PROMOTION_RECERTIFICATION_VERSION:
        if not carried_details or not isinstance(recertification, dict):
            raise EvidenceValidationError("recertified champion promotion has no carried model evidence bridge")
        if record.get("recertification_identity") != recertification.get("recertification_identity") or record.get("carried_model_evidence") != carried_details:
            raise EvidenceValidationError("champion promotion recertification provenance is stale or inconsistent")
    elif carried_details:
        raise EvidenceValidationError("champion promotion contract 1.0 cannot authorize carried model evidence")
    factors = canonical_candidate_factors(candidate_spec)
    expected = {
        "candidate_subject_git_sha": candidate_spec.get("subject_git_sha"),
        "candidate_deployment_fingerprint": candidate_deployment_fingerprint(candidate_spec),
        "candidate_factors_sha256": sha256_bytes(canonical_bytes(factors)),
        "requested_model": candidate_spec.get("requested_model"),
        "effective_model": effective,
        "model_policy_sha256": sha256_bytes(canonical_bytes(factors.get("model_policy"))),
        "corpus_identity_sha256": sha256_bytes(canonical_bytes(factors.get("corpus_identity"))),
        "behavior_configuration_hash": behavior_hash,
        "evidence": details,
    }
    for key, value in expected.items():
        if record.get(key) != value:
            raise EvidenceValidationError(f"champion promotion {key} is stale or inconsistent")
    return {**record}


def champion_document_from_promotion(record: dict[str, Any], *, reason: str = "") -> dict[str, Any]:
    """Create the strict editable champion summary around a validated record."""

    if record.get("state") not in CHAMPION_PROMOTION_STATES:
        raise EvidenceValidationError("champion promotion state is not in the closed state set")
    return {
        "schema_version": "1.0",
        "status": record["state"],
        "reason": reason,
        "model": record["requested_model"],
        "effective_model": record["effective_model"],
        "deployment_fingerprint": record["candidate_deployment_fingerprint"],
        "behavior_configuration_hash": record["behavior_configuration_hash"],
        "promotion_contract": record,
    }


# Producer-owned dependency dimensions. Each candidate field is explicitly
# mapped to the evidence classes whose producers consume that factor.
_MODEL_EXECUTION = frozenset({
    "subject_git_sha", "candidate_spec_version", "kslide_version", "opencode_version", "requested_model",
    "effective_model", "provider", "provider_backend", "model_revision",
    "quantization_or_dtype", "vision_settings", "context_configuration",
    "image_preprocessing_settings", "prompt_identity", "prompt_version",
    "prompt_hash", "generation_settings", "ocr_provider",
    "ocr_asset_manifest_sha256", "normalization_behavior", "repair_policy",
    "python_version", "paddle_version", "paddleocr_version", "libreoffice_version",
    "termbase_identity", "termbase_version", "termbase_hash", "model_policy",
    "inference_route_identity", "inference_endpoint_identity", "inference_data_use_policy",
    "egress_policy_version", "egress_policy_hash", "egress_policy_identity",
    "schema_versions", "network_egress", "resolved_dependency_set_sha256", "runtime_artifact_identity",
    "runtime_artifact_manifest_sha256", "runtime_sbom_sha256",
    "opencode_bootstrap_identity", "opencode_models_identity", "behavior_configuration",
})
_DEPLOYMENT_EXECUTION = _MODEL_EXECUTION | frozenset({
    "tenant_isolation", "constraints_sha256",
})
_HEAVY_RUNTIME = frozenset({
    "subject_git_sha", "candidate_spec_version", "kslide_version", "opencode_version",
    "ocr_provider", "ocr_asset_manifest_sha256", "python_version", "paddle_version",
    "paddleocr_version", "libreoffice_version", "schema_versions", "constraints_sha256",
    "resolved_dependency_set_sha256", "runtime_artifact_identity",
    "runtime_artifact_manifest_sha256", "runtime_sbom_sha256", "opencode_bootstrap_identity",
})
_SECURITY = frozenset({
    "subject_git_sha", "candidate_spec_version", "kslide_version", "opencode_version",
    "python_version", "schema_versions", "constraints_sha256",
    "resolved_dependency_set_sha256", "runtime_artifact_identity",
    "runtime_artifact_manifest_sha256", "runtime_sbom_sha256",
    "opencode_bootstrap_identity", "opencode_models_identity",
})
_MODEL_POLICY_ATTESTATION = frozenset({
    "candidate_spec_version", "requested_model", "effective_model", "provider", "model_policy", "retention_policy",
    "inference_route_identity", "inference_endpoint_identity", "inference_data_use_policy",
    "egress_policy_version", "egress_policy_hash", "egress_policy_identity",
    "network_egress",
})

EVIDENCE_DEPENDENCY_FIELDS: dict[str, frozenset[str]] = {
    "runtime": _DEPLOYMENT_EXECUTION,
    "heavy_runtime": _HEAVY_RUNTIME,
    "model_validation": _MODEL_EXECUTION | {"corpus_identity"},
    "model_high_risk_stability": _MODEL_EXECUTION | {"corpus_identity"},
    "model_held_out": _MODEL_EXECUTION | {"corpus_identity"},
    "internal_bilingual": _DEPLOYMENT_EXECUTION | {"corpus_identity"},
    "zero_korean_comprehension": _DEPLOYMENT_EXECUTION | {"corpus_identity"},
    "security": _SECURITY,
    "reliability": _DEPLOYMENT_EXECUTION,
    "model_data_policy": _MODEL_POLICY_ATTESTATION,
    "pilot_canary": _DEPLOYMENT_EXECUTION | {"corpus_identity"},
    "governance": frozenset({"subject_git_sha", "candidate_spec_version"}),
}
EVIDENCE_DEPENDENCY_FIELDS["pilot_canary"] = EVIDENCE_DEPENDENCY_FIELDS["pilot_canary"] | {"retention_policy"}


def change_impact_policy_identity() -> str:
    dimensions = {
        evidence_type: sorted(fields)
        for evidence_type, fields in sorted(EVIDENCE_DEPENDENCY_FIELDS.items())
    }
    return sha256_bytes(canonical_bytes({
        "version": CHANGE_IMPACT_POLICY_VERSION,
        "evidence_types": list(EVIDENCE_TYPES),
        "candidate_dimensions": list(CANDIDATE_INPUT_FIELDS),
        "dependencies": dimensions,
    }))


def _candidate_factors_for_impact(candidate_spec: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(candidate_spec, dict):
        raise EvidenceValidationError("recertification candidate must be an object")
    # Strict normalization rejects caller-invented dimensions. A repository
    # field added without a dependency entry is handled below as fail-closed.
    from .certification import _normalize_candidate_mapping

    normalized = _normalize_candidate_mapping(candidate_spec, strict=True)
    return canonical_candidate_factors(normalized)


def candidate_change_impact(old_candidate: dict[str, Any], new_candidate: dict[str, Any]) -> dict[str, Any]:
    """Compare exact canonical factors and apply the closed dependency policy."""

    old_factors = _candidate_factors_for_impact(old_candidate)
    new_factors = _candidate_factors_for_impact(new_candidate)
    all_dimensions = sorted(set(old_factors) | set(new_factors))
    changed = [key for key in all_dimensions if old_factors.get(key) != new_factors.get(key)]
    mapped = set().union(*EVIDENCE_DEPENDENCY_FIELDS.values())
    unknown = sorted(set(changed) - mapped)
    affected: dict[str, list[str]] = {}
    for evidence_type in EVIDENCE_TYPES:
        relevant = sorted(set(changed) & EVIDENCE_DEPENDENCY_FIELDS[evidence_type])
        if unknown:
            relevant = sorted(set(relevant) | set(unknown))
        if relevant:
            affected[evidence_type] = relevant
    old_deployment = candidate_deployment_fingerprint(old_candidate)
    new_deployment = candidate_deployment_fingerprint(new_candidate)
    champion_affected = old_deployment != new_deployment
    return {
        "policy_version": CHANGE_IMPACT_POLICY_VERSION,
        "policy_identity": change_impact_policy_identity(),
        "old_subject_git_sha": old_candidate.get("subject_git_sha"),
        "old_deployment_fingerprint": old_deployment,
        "new_subject_git_sha": new_candidate.get("subject_git_sha"),
        "new_deployment_fingerprint": new_deployment,
        "changed_dimensions": changed,
        "unknown_dimensions": unknown,
        "affected_evidence": affected,
        "champion_affected": champion_affected,
    }


def dependency_projection_identity(candidate_spec: dict[str, Any], evidence_type: str) -> str:
    if evidence_type not in EVIDENCE_DEPENDENCY_FIELDS:
        raise EvidenceValidationError("unknown evidence type has no dependency projection")
    factors = _candidate_factors_for_impact(candidate_spec)
    fields = EVIDENCE_DEPENDENCY_FIELDS[evidence_type]
    unmapped = sorted(set(factors) - set().union(*EVIDENCE_DEPENDENCY_FIELDS.values()))
    projection = {
        "policy_version": CHANGE_IMPACT_POLICY_VERSION,
        "policy_identity": change_impact_policy_identity(),
        "evidence_type": evidence_type,
        "factors": {key: factors[key] for key in sorted(fields) if key in factors},
        "unmapped_dimensions": {key: factors[key] for key in unmapped},
    }
    return sha256_bytes(canonical_bytes(projection))


def _validate_old_evidence(
    evidence_type: str,
    record: dict[str, Any],
    *,
    old_candidate: dict[str, Any],
    root: Path | None,
) -> dict[str, Any]:
    if not isinstance(record, dict) or record.get("evidence_type") != evidence_type:
        raise EvidenceValidationError(f"recertification prior {evidence_type} evidence is missing")
    path = record.get("path")
    if not isinstance(path, str) or not path:
        raise EvidenceValidationError(f"recertification prior {evidence_type} evidence path is missing")
    try:
        validated = load_evidence(
            Path(path),
            expected_type=evidence_type,
            subject_git_sha=str(old_candidate.get("subject_git_sha") or ""),
            deployment_fingerprint=candidate_deployment_fingerprint(old_candidate),
            repository_root=root,
            candidate_spec=old_candidate,
            require_candidate_spec=True,
        )
    except (OSError, ValueError, TypeError) as exc:
        if isinstance(exc, EvidenceValidationError):
            raise
        raise EvidenceValidationError(f"recertification prior {evidence_type} evidence is invalid") from exc
    if record.get("evidence_identity") != validated.get("evidence_identity") or record.get("envelope_sha256", record.get("sha256")) != validated.get("envelope_sha256"):
        raise EvidenceValidationError(f"recertification prior {evidence_type} evidence identity or hash changed")
    return validated


def _make_exemption(
    evidence_type: str,
    evidence: dict[str, Any],
    *,
    impact: dict[str, Any],
    old_candidate: dict[str, Any],
    new_candidate: dict[str, Any],
) -> dict[str, Any]:
    if evidence_type in impact["affected_evidence"]:
        raise EvidenceValidationError(f"recertification cannot exempt affected {evidence_type} evidence")
    return {
        "contract_version": RECERTIFICATION_CONTRACT_VERSION,
        "evidence_type": evidence_type,
        "outcome": "CARRY_FORWARD",
        "rationale_code": "DEPENDENCY_PROJECTION_UNCHANGED",
        "impact_policy_version": impact["policy_version"],
        "impact_policy_identity": impact["policy_identity"],
        "old_subject_git_sha": impact["old_subject_git_sha"],
        "old_deployment_fingerprint": impact["old_deployment_fingerprint"],
        "new_subject_git_sha": impact["new_subject_git_sha"],
        "new_deployment_fingerprint": impact["new_deployment_fingerprint"],
        "changed_dimensions": impact["changed_dimensions"],
        "evidence_identity": evidence["evidence_identity"],
        "envelope_sha256": evidence["envelope_sha256"],
        "old_dependency_projection_identity": dependency_projection_identity(old_candidate, evidence_type),
        "new_dependency_projection_identity": dependency_projection_identity(new_candidate, evidence_type),
    }


def build_recertification_record(
    old_candidate: dict[str, Any],
    new_candidate: dict[str, Any],
    prior_records: dict[str, dict[str, Any]],
    evidence_types: list[str] | tuple[str, ...],
    *,
    root: Path | None = None,
    prior_release_manifest_sha256: str,
) -> dict[str, Any]:
    """Build an immutable bridge for explicitly selected unaffected evidence."""

    prior_release_manifest_sha256 = _require_identity(prior_release_manifest_sha256, "prior release manifest hash")
    impact = candidate_change_impact(old_candidate, new_candidate)
    if not impact["champion_affected"]:
        raise EvidenceValidationError("scoped recertification requires a distinct new candidate identity")
    if impact["unknown_dimensions"]:
        raise EvidenceValidationError("recertification has unknown or unmapped changed candidate dimensions")
    requested = list(evidence_types)
    if len(set(requested)) != len(requested):
        raise EvidenceValidationError("recertification evidence types must be unique")
    exemptions: list[dict[str, Any]] = []
    for evidence_type in sorted(requested):
        if evidence_type not in EVIDENCE_TYPES:
            raise EvidenceValidationError("recertification evidence type is unknown")
        prior = _validate_old_evidence(evidence_type, prior_records.get(evidence_type), old_candidate=old_candidate, root=root)
        payload = prior.get("payload")
        if isinstance(payload, dict):
            validate_evidence_payload(evidence_type, payload)
        exemption = _make_exemption(evidence_type, prior, impact=impact, old_candidate=old_candidate, new_candidate=new_candidate)
        exemption["exemption_identity"] = _identity(exemption, "exemption_identity")
        exemptions.append(exemption)
    old_factors = canonical_candidate_factors(old_candidate)
    new_factors = canonical_candidate_factors(new_candidate)
    result: dict[str, Any] = {
        "contract_version": RECERTIFICATION_CONTRACT_VERSION,
        "impact_policy_version": impact["policy_version"],
        "impact_policy_identity": impact["policy_identity"],
        "prior_release_manifest_sha256": prior_release_manifest_sha256,
        "prior_certification_status": "STALE_FOR_NEW_CANDIDATE" if impact["champion_affected"] else "UNCHANGED_CANDIDATE",
        "old_subject_git_sha": impact["old_subject_git_sha"],
        "old_deployment_fingerprint": impact["old_deployment_fingerprint"],
        "old_candidate_spec": old_factors,
        "new_subject_git_sha": impact["new_subject_git_sha"],
        "new_deployment_fingerprint": impact["new_deployment_fingerprint"],
        "new_candidate_spec": new_factors,
        "changed_dimensions": impact["changed_dimensions"],
        "unknown_dimensions": impact["unknown_dimensions"],
        "affected_evidence": impact["affected_evidence"],
        "champion_affected": impact["champion_affected"],
        "exemptions": exemptions,
    }
    result["recertification_identity"] = _identity(result, "recertification_identity")
    return result


def validate_recertification_record(
    record: dict[str, Any],
    new_candidate: dict[str, Any],
    prior_records: dict[str, dict[str, Any]],
    *,
    root: Path | None = None,
    expected_prior_release_manifest_sha256: str | None = None,
) -> dict[str, Any]:
    """Recompute every impact, evidence, projection, and content identity."""

    expected_keys = {
        "contract_version", "impact_policy_version", "impact_policy_identity",
        "prior_release_manifest_sha256", "prior_certification_status",
        "old_subject_git_sha", "old_deployment_fingerprint", "old_candidate_spec",
        "new_subject_git_sha", "new_deployment_fingerprint", "new_candidate_spec",
        "changed_dimensions", "unknown_dimensions", "affected_evidence",
        "champion_affected", "exemptions", "recertification_identity",
    }
    if not isinstance(record, dict) or set(record) != expected_keys:
        raise EvidenceValidationError("recertification record does not match the closed contract")
    if record.get("contract_version") != RECERTIFICATION_CONTRACT_VERSION:
        raise EvidenceValidationError("recertification contract version is unsupported")
    if expected_prior_release_manifest_sha256 is not None and record.get("prior_release_manifest_sha256") != expected_prior_release_manifest_sha256:
        raise EvidenceValidationError("recertification prior manifest identity changed")
    old_candidate = record.get("old_candidate_spec")
    if not isinstance(old_candidate, dict) or canonical_candidate_factors(old_candidate) != old_candidate:
        raise EvidenceValidationError("recertification old candidate specification is not canonical")
    new_factors = canonical_candidate_factors(new_candidate)
    if record.get("new_candidate_spec") != new_factors:
        raise EvidenceValidationError("recertification is bound to another new candidate")
    impact = candidate_change_impact(old_candidate, new_candidate)
    if not impact["champion_affected"]:
        raise EvidenceValidationError("scoped recertification must bind a distinct new candidate identity")
    if impact["unknown_dimensions"]:
        raise EvidenceValidationError("recertification contains unknown or unmapped changed dimensions")
    expected_impact = {
        "impact_policy_version": impact["policy_version"],
        "impact_policy_identity": impact["policy_identity"],
        "old_subject_git_sha": impact["old_subject_git_sha"],
        "old_deployment_fingerprint": impact["old_deployment_fingerprint"],
        "new_subject_git_sha": impact["new_subject_git_sha"],
        "new_deployment_fingerprint": impact["new_deployment_fingerprint"],
        "changed_dimensions": impact["changed_dimensions"],
        "unknown_dimensions": impact["unknown_dimensions"],
        "affected_evidence": impact["affected_evidence"],
        "champion_affected": impact["champion_affected"],
        "prior_certification_status": "STALE_FOR_NEW_CANDIDATE" if impact["champion_affected"] else "UNCHANGED_CANDIDATE",
    }
    for key, expected in expected_impact.items():
        if record.get(key) != expected:
            raise EvidenceValidationError(f"recertification {key} was edited or is stale")
    exemptions = record.get("exemptions")
    if not isinstance(exemptions, list):
        raise EvidenceValidationError("recertification exemptions must be a list")
    seen: set[str] = set()
    for exemption in exemptions:
        exemption_keys = {
            "contract_version", "evidence_type", "outcome", "rationale_code",
            "impact_policy_version", "impact_policy_identity", "old_subject_git_sha",
            "old_deployment_fingerprint", "new_subject_git_sha", "new_deployment_fingerprint",
            "changed_dimensions", "evidence_identity", "envelope_sha256",
            "old_dependency_projection_identity", "new_dependency_projection_identity",
            "exemption_identity",
        }
        if not isinstance(exemption, dict) or set(exemption) != exemption_keys:
            raise EvidenceValidationError("recertification exemption does not match the closed contract")
        evidence_type = exemption.get("evidence_type")
        if not isinstance(evidence_type, str) or evidence_type not in EVIDENCE_TYPES or evidence_type in seen:
            raise EvidenceValidationError("recertification exemption evidence type is unknown or duplicated")
        seen.add(evidence_type)
        if exemption.get("contract_version") != RECERTIFICATION_CONTRACT_VERSION or exemption.get("outcome") != "CARRY_FORWARD" or exemption.get("rationale_code") != "DEPENDENCY_PROJECTION_UNCHANGED":
            raise EvidenceValidationError("recertification exemption outcome or rationale is unsupported")
        expected_exemption = _make_exemption(
            evidence_type,
            _validate_old_evidence(evidence_type, prior_records.get(evidence_type), old_candidate=old_candidate, root=root),
            impact=impact,
            old_candidate=old_candidate,
            new_candidate=new_candidate,
        )
        if exemption.get("exemption_identity") != _identity(exemption, "exemption_identity"):
            raise EvidenceValidationError("recertification exemption identity does not match its content")
        expected_exemption["exemption_identity"] = _identity(expected_exemption, "exemption_identity")
        if exemption != expected_exemption:
            raise EvidenceValidationError(f"recertification {evidence_type} exemption is affected, stale, or misbound")
    if record.get("recertification_identity") != _identity(record, "recertification_identity"):
        raise EvidenceValidationError("recertification identity does not match its content")
    return {**record}


def recertification_exemption_identities(record: dict[str, Any] | None) -> dict[str, str]:
    if record is None:
        return {}
    exemptions = record.get("exemptions")
    if not isinstance(exemptions, list):
        raise EvidenceValidationError("recertification exemptions are malformed")
    return {
        str(item["evidence_type"]): str(item["exemption_identity"])
        for item in exemptions
        if isinstance(item, dict)
    }
