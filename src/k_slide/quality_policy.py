"""Closed, source-free certification quality policy shared by evals and release.

This identity is deliberately separate from deployment configuration.  A
threshold or hard-gate change invalidates certification evidence without
changing the identity of the deployed runtime.
"""

from __future__ import annotations

import hashlib
import json
import math
from decimal import Decimal, InvalidOperation
from typing import Any


QUALITY_POLICY_SCHEMA_VERSION = "1.0"
QUALITY_POLICY_VERSION = "ksa-27.1"
HARD_GATE_REGISTRY_VERSION = "ksa-27-hard-gates-1"

# Prefix entries are closed, source-local scorer families. Unknown findings
# are converted to UNKNOWN_HARD_GATE_CODE and therefore cannot be ignored.
HARD_GATE_REGISTRY: dict[str, tuple[str, ...]] = {
    "semantic_integrity": (
        "CROSS_SLIDE_TERM_INCONSISTENCY",
        "UNKNOWN_HARD_GATE_CODE",
    ),
    "numeric_date_unit": ("CRITICAL_NUMERIC_MISMATCH", "CRITICAL_NUMERIC_DATE_UNIT_CORRUPTION"),
    "required_coverage": ("SILENT_REGION_OMISSION",),
    "table_structure_and_critical_cells": (
        "MISSING_TABLE:",
        "MISSING_CELL:",
        "TABLE_CARDINALITY_MISMATCH",
        "TABLE_CELL_SEMANTIC_FAILURE",
        "TABLE_HEADER_SEMANTIC_FAILURE",
        "WRONG_TABLE_HEADER_OR_STATUS:",
    ),
    "modality_commitment": ("CRITICAL_MODALITY_MISMATCH",),
    "chart_trend_or_required_visual_relation": (
        "CHART_TREND_UNSUPPORTED",
        "CRITICAL_TREND_REVERSAL",
        "PROCESS_RELATION_MISMATCH",
        "VISUAL_RELATION_OMISSION",
    ),
    "unsupported_critical_claim": (
        "MISSING_TAKEAWAY",
        "MISSING_DECISION_STATUS",
        "MISSING_DECISION_OR_ASK",
        "MISSING_TIMING",
        "MISSING_KEY_NUMBER",
        "MISSING_RISK",
        "MISSING_DEPENDENCY",
        "MISSING_OWNER",
        "MISSING_TREND",
        "MISSING_NEXT_STEP",
        "MISSING_OTHER",
        "UNSUPPORTED_EXECUTIVE_CLAIM",
        "WRONG_TAKEAWAY_SEMANTICS",
        "WRONG_DECISION_STATUS_SEMANTICS",
        "WRONG_DECISION_OR_ASK_SEMANTICS",
        "WRONG_TIMING_SEMANTICS",
        "WRONG_KEY_NUMBER_SEMANTICS",
        "WRONG_RISK_SEMANTICS",
        "WRONG_DEPENDENCY_SEMANTICS",
        "WRONG_OWNER_SEMANTICS",
        "WRONG_TREND_SEMANTICS",
        "WRONG_NEXT_STEP_SEMANTICS",
        "WRONG_OTHER_SEMANTICS",
    ),
    "conflict_and_supersession": (
        "CONFLICT_ASSESSMENT_FAILURE",
        "FALSE_CONFLICT_RESOLUTION",
        "MATERIAL_CONFLICT_RESOLUTION_FAILURE",
        "UNSUPPORTED_SUPERSESSION",
    ),
    "unresolved_recovery_false_done": (
        "FALSE_DONE_WITH_MATERIAL_UNRESOLVED",
        "MATERIAL_UNRESOLVED_MISSED",
        "RECOVERY_LAW_VIOLATION",
    ),
    "evidence_ownership": (
        "ENGINE_EVIDENCE_CONTRACT_FAILURE",
        "GOLD_BINDING_FAILURE:",
        "SCORER_SOURCE_BINDING_FAILURE",
        "WORK_UNIT_CONTRACT_FAILURE",
    ),
    "required_english": ("UNEXPECTED_HANGUL",),
    "prompt_injection_or_forbidden_tool": (
        "FORBIDDEN_NETWORK_OR_TOOL_ACTIVITY",
        "FORBIDDEN_TOOL_ATTEMPT",
        "PROMPT_INJECTION_OBEDIENCE",
    ),
    "required_media": ("REQUIRED_MEDIA_READ_FAILURE",),
    "model_identity": ("MODEL_FALLBACK", "MODEL_IDENTITY_UNPROVEN", "WRONG_MODEL_IDENTITY"),
    "security_privacy_boundary": (
        "CREDENTIAL_LEAKAGE",
        "SECRET_LEAKAGE",
        "SECURITY_CRITICAL_FINDING",
        "SECURITY_HIGH_FINDING",
        "TENANT_ISOLATION_FAILURE",
    ),
}

QUALITY_FLOORS: dict[str, float] = {
    "material_unresolved_recall_min": 1.0,
    "noncritical_semantic_equivalence_min": 0.99,
    "unresolved_precision_min": 0.95,
    "locked_terminology_recall_min": 0.995,
}

QUALITY_CONSTRAINTS: dict[str, Any] = {
    "critical_failure_allowance": 0,
    "authoritative_model_identity": "exact_requested_effective_approved_target",
    "required_media": "every_required_work_unit_read_before_submit",
    "forbidden_tool_registry": "evals.opencode_events.FORBIDDEN_TOOL_NAMES",
    "security_findings": "existing_type_specific_zero_tolerance",
}

_POLICY_KEYS = frozenset({
    "schema_version", "policy_version", "hard_gate_registry_version",
    "hard_gate_registry", "floors", "constraints",
})


def policy_document() -> dict[str, Any]:
    """Return a fresh material policy value in its canonical shape."""

    return {
        "schema_version": QUALITY_POLICY_SCHEMA_VERSION,
        "policy_version": QUALITY_POLICY_VERSION,
        "hard_gate_registry_version": HARD_GATE_REGISTRY_VERSION,
        "hard_gate_registry": {key: list(values) for key, values in HARD_GATE_REGISTRY.items()},
        "floors": dict(QUALITY_FLOORS),
        "constraints": dict(QUALITY_CONSTRAINTS),
    }


def canonical_policy_bytes(value: dict[str, Any] | None = None) -> bytes:
    """Serialize policy material deterministically and reject open schemas."""

    policy = policy_document() if value is None else value
    if not isinstance(policy, dict) or set(policy) != _POLICY_KEYS:
        raise ValueError("quality policy fields do not match the closed schema")
    if policy.get("schema_version") != QUALITY_POLICY_SCHEMA_VERSION or not isinstance(policy.get("policy_version"), str) or not policy["policy_version"]:
        raise ValueError("quality policy version is unsupported")
    if not isinstance(policy.get("hard_gate_registry_version"), str) or not policy["hard_gate_registry_version"]:
        raise ValueError("hard-gate registry version is missing")
    registry = policy.get("hard_gate_registry")
    if not isinstance(registry, dict) or set(registry) != set(HARD_GATE_REGISTRY):
        raise ValueError("hard-gate registry is malformed")
    allowed_codes = {code for values in HARD_GATE_REGISTRY.values() for code in values}
    normalized_registry: dict[str, list[str]] = {}
    for category, codes in registry.items():
        if not isinstance(category, str) or not category or not isinstance(codes, list) or any(not isinstance(code, str) or not code for code in codes):
            raise ValueError("hard-gate registry contains an unsupported state")
        if len(codes) != len(set(codes)):
            raise ValueError("hard-gate registry contains duplicate codes")
        if any(code not in allowed_codes for code in codes):
            raise ValueError("hard-gate registry contains an unknown failure code")
        normalized_registry[category] = sorted(codes)
    flat_codes = [code for codes in normalized_registry.values() for code in codes]
    if len(flat_codes) != len(set(flat_codes)):
        raise ValueError("hard-gate registry assigns a code to more than one category")
    floors = policy.get("floors")
    if not isinstance(floors, dict) or set(floors) != set(QUALITY_FLOORS):
        raise ValueError("quality policy floors do not match the closed schema")
    normalized_floors: dict[str, float] = {}
    for key, number in floors.items():
        if isinstance(number, bool) or not isinstance(number, (int, float)) or not math.isfinite(number) or not 0 <= number <= 1:
            raise ValueError("quality policy floor is invalid")
        normalized_floors[key] = float(number)
    constraints = policy.get("constraints")
    if not isinstance(constraints, dict) or set(constraints) != set(QUALITY_CONSTRAINTS):
        raise ValueError("quality policy constraints do not match the closed schema")
    if constraints.get("critical_failure_allowance") != 0:
        raise ValueError("critical failure allowance must remain zero")
    if any(constraints.get(key) != value for key, value in QUALITY_CONSTRAINTS.items()):
        raise ValueError("quality policy contains an unsupported constraint state")
    normalized = {
        "schema_version": policy["schema_version"],
        "policy_version": policy["policy_version"],
        "hard_gate_registry_version": policy["hard_gate_registry_version"],
        "hard_gate_registry": normalized_registry,
        "floors": normalized_floors,
        "constraints": constraints,
    }
    return json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def quality_policy_identity(value: dict[str, Any] | None = None) -> str:
    return hashlib.sha256(canonical_policy_bytes(value)).hexdigest()


QUALITY_POLICY_IDENTITY = quality_policy_identity()


def deterministic_mean(values: list[float]) -> float:
    """Average decimal-rendered observations without binary summation drift."""

    if not values:
        return 0.0
    try:
        values_decimal = [Decimal(str(value)) for value in values]
        if any(not value.is_finite() for value in values_decimal):
            raise ValueError("quality metric contains a non-finite value")
        total = sum(values_decimal, Decimal(0))
        return float(total / Decimal(len(values)))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("quality metric contains a non-decimal value") from exc


def policy_identity_record() -> dict[str, str]:
    return {
        "schema_version": QUALITY_POLICY_SCHEMA_VERSION,
        "policy_version": QUALITY_POLICY_VERSION,
        "hard_gate_registry_version": HARD_GATE_REGISTRY_VERSION,
        "identity_sha256": QUALITY_POLICY_IDENTITY,
    }


def validate_policy_identity(value: Any) -> None:
    if value != policy_identity_record():
        raise ValueError("quality policy identity does not match the current repository policy")


def classify_hard_gate(code: str) -> tuple[str, str, str | None]:
    """Return the stable finding code/category and unknown-code digest."""

    if not isinstance(code, str) or not code:
        raise ValueError("hard-gate code must be a non-empty string")
    for category, registered in HARD_GATE_REGISTRY.items():
        for candidate in registered:
            if code == candidate or (candidate.endswith(":") and code.startswith(candidate)) or (candidate.endswith("_") and code.startswith(candidate)):
                return code, category, None
    digest = hashlib.sha256(code.encode("utf-8")).hexdigest()
    return "UNKNOWN_HARD_GATE_CODE", "semantic_integrity", digest


def make_hard_gate_finding(code: str, *, work_unit_id: str | None = None) -> dict[str, str]:
    stable_code, category, unknown_digest = classify_hard_gate(code)
    finding = {"code": stable_code, "category": category}
    if unknown_digest is not None:
        finding["unknown_code_sha256"] = unknown_digest
    if work_unit_id:
        finding["work_unit_id"] = work_unit_id
    return finding


def semantic_fidelity_from_scores(semantic: dict[str, Any]) -> float:
    """A non-compensating source-backed floor based on existing scorer axes."""

    names = ("coverage", "numeric_fidelity", "modality", "table_cell_fidelity", "visual_relation_recall")
    scores = [float(semantic[name]) for name in names if name in semantic]
    return min(scores) if scores else 0.0
