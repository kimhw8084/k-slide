"""Shared certification policy, status semantics, and reproducibility fingerprints."""

from __future__ import annotations

import hashlib
import json
from enum import Enum
from pathlib import Path
from typing import Any, Iterable

from k_slide.model_policy import ModelPolicy, load_model_policy


class EvaluationState(str, Enum):
    NOT_MEASURED = "NOT_MEASURED"
    CAPABILITY_BLOCKED = "CAPABILITY_BLOCKED"
    PROTOCOL_SMOKE_ONLY = "PROTOCOL_SMOKE_ONLY"
    MEASURED = "MEASURED"
    CERTIFICATION_FAIL = "CERTIFICATION_FAIL"
    PRODUCTION_CANDIDATE = "PRODUCTION_CANDIDATE"
    PRODUCTION_CERTIFIED = "PRODUCTION_CERTIFIED"


# These keys intentionally match Scenario.category values exactly.
CATEGORY_POLICY: dict[str, dict[str, tuple[str, ...]]] = {
    "financial_table": {"protected_metrics": ("numeric_fidelity", "table_cell_fidelity", "coverage")},
    "modality_decision_state": {"protected_metrics": ("modality", "coverage")},
    "chart": {"protected_metrics": ("numeric_fidelity", "visual_relation_recall", "coverage")},
    "process_diagram": {"protected_metrics": ("visual_relation_recall", "coverage")},
    "visual_degradation": {"protected_metrics": ("coverage", "numeric_fidelity")},
    "prompt_injection": {"protected_metrics": ("coverage",)},
    "cross_slide_consistency": {"protected_metrics": ("coverage",)},
    "state_resume": {"protected_metrics": ("coverage", "visual_relation_recall")},
    "simple_mixed_text": {"protected_metrics": ("coverage",)},
}
PROTECTED_CATEGORIES = tuple(CATEGORY_POLICY)
DEFAULT_REVIEW_RATE_TOLERANCE = 0.05
CORPUS_GENERATOR_VERSION = "visual-corpus-v1"


def _stable_payload(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def fingerprint(value: Any) -> str:
    return hashlib.sha256(_stable_payload(value)).hexdigest()


def corpus_fingerprint(scenarios: Iterable[Any], *, generator_version: str = CORPUS_GENERATOR_VERSION, generator_config: dict[str, Any] | None = None) -> str:
    """Fingerprint semantic gold plus the generator contract that produced it."""

    return fingerprint(
        {
            "generator_version": generator_version,
            "generator_config": generator_config or {},
            "scenarios": [scenario.as_dict() if hasattr(scenario, "as_dict") else scenario for scenario in scenarios],
        }
    )


def held_out_fingerprint(scenarios: Iterable[Any]) -> str:
    def split_of(scenario: Any) -> Any:
        if hasattr(scenario, "split"):
            return getattr(scenario, "split")
        return scenario.get("split") if isinstance(scenario, dict) else None

    held_out = [scenario for scenario in scenarios if split_of(scenario) == "held_out"]
    return corpus_fingerprint(held_out)


def certification_fingerprint(configuration: dict[str, Any]) -> str:
    return fingerprint(configuration)


def certification_status(*, authoritative: bool, capability_blocked: bool = False, protocol_smoke: bool = False, critical_failures: int = 0, hard_policy_pass: bool = False, review_policy_pass: bool = False, stability_pass: bool = False, synthetic_candidate: bool = False) -> EvaluationState:
    if capability_blocked:
        return EvaluationState.CAPABILITY_BLOCKED
    if protocol_smoke:
        return EvaluationState.PROTOCOL_SMOKE_ONLY
    if not authoritative:
        return EvaluationState.NOT_MEASURED
    if critical_failures:
        return EvaluationState.CERTIFICATION_FAIL
    if synthetic_candidate and hard_policy_pass and review_policy_pass and stability_pass:
        return EvaluationState.PRODUCTION_CANDIDATE
    return EvaluationState.MEASURED


def certification_stale(previous_fingerprint: str | None, current_configuration: dict[str, Any]) -> bool:
    return bool(previous_fingerprint and previous_fingerprint != certification_fingerprint(current_configuration))
