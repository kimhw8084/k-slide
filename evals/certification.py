"""Shared certification policy, status semantics, and reproducibility fingerprints."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Iterable


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


@dataclass(frozen=True)
class ModelPolicy:
    target_family: str = "Gemma 4"
    target_size: str = "31B"
    target_variant: str = "instruction_tuned"
    approved_model_ids: tuple[str, ...] = ("google/gemma-4-31b-it",)
    approved_aliases: tuple[str, ...] = ()

    @classmethod
    def from_mapping(cls, value: dict[str, Any] | None) -> "ModelPolicy":
        value = value or {}
        def values(key: str, default: tuple[str, ...]) -> tuple[str, ...]:
            raw = value.get(key, default)
            if isinstance(raw, str):
                return (raw,)
            if isinstance(raw, (list, tuple)):
                return tuple(str(item) for item in raw)
            return default
        return cls(
            target_family=str(value.get("target_family", cls.target_family)),
            target_size=str(value.get("target_size", cls.target_size)),
            target_variant=str(value.get("target_variant", cls.target_variant)),
            approved_model_ids=values("approved_model_ids", cls.approved_model_ids),
            approved_aliases=values("approved_aliases", ()),
        )

    def approved(self, *, requested: str | None, effective: str | None) -> bool:
        if not requested or not effective:
            return False
        approved = set(self.approved_model_ids) | set(self.approved_aliases)
        return requested in approved and effective in approved


def load_model_policy(root: Path | None = None) -> ModelPolicy:
    """Load a public policy plus an optional ignored local JSON/YAML overlay.

    The public repository keeps the default policy exact. The local overlay is
    intentionally small and supports the list/scalar subset needed for private
    provider aliases without requiring PyYAML at runtime.
    """

    root = root or Path.cwd()
    local = root / ".k-slide-config" / "model-policy.local.yaml"
    if not local.is_file():
        local = root / ".k-slide-config" / "model-policy.local.json"
    if not local.is_file():
        return ModelPolicy()
    try:
        text = local.read_text(encoding="utf-8")
        if local.suffix == ".json":
            return ModelPolicy.from_mapping(json.loads(text))
        mapping: dict[str, Any] = {}
        current_list: str | None = None
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].rstrip()
            if not line.strip():
                continue
            if line.startswith("  - ") and current_list:
                mapping.setdefault(current_list, []).append(line[4:].strip().strip("'\""))
                continue
            if ":" not in line:
                continue
            key, raw_value = (item.strip() for item in line.split(":", 1))
            if not raw_value:
                current_list = key
                mapping[key] = []
            else:
                current_list = None
                mapping[key] = raw_value.strip().strip("'\"")
        return ModelPolicy.from_mapping(mapping)
    except (OSError, json.JSONDecodeError, ValueError):
        # A malformed private overlay must not silently certify a model.
        return ModelPolicy(approved_model_ids=(), approved_aliases=())


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
