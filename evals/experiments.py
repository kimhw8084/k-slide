"""Reproducible champion/challenger governance for model experiments."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


PROTECTED = ("financial", "numeric", "tables", "modality", "decision_status", "risk", "visual_relation")


def configuration_hash(configuration: dict[str, Any]) -> str:
    payload = json.dumps(configuration, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _category_metrics(value: dict[str, Any]) -> dict[str, dict[str, Any]]:
    metrics = value.get("by_category") or value.get("category_metrics") or {}
    return metrics if isinstance(metrics, dict) else {}


def _metric(metrics: dict[str, Any], names: tuple[str, ...], default: float = 0.0) -> float:
    for name in names:
        if name in metrics:
            return float(metrics[name])
    return default


def compare_aggregate(baseline: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    baseline_critical = int(baseline.get("critical_failure_count", baseline.get("critical_failures", 0)))
    candidate_critical = int(candidate.get("critical_failure_count", candidate.get("critical_failures", 0)))
    base_scores = baseline.get("mean_scores", baseline.get("metrics", {}))
    candidate_scores = candidate.get("mean_scores", candidate.get("metrics", {}))
    improvements = {key: float(candidate_scores.get(key, 0)) - float(base_scores.get(key, 0)) for key in set(base_scores) | set(candidate_scores)}
    base_categories = _category_metrics(baseline)
    candidate_categories = _category_metrics(candidate)
    protected_regressions: dict[str, dict[str, float]] = {}
    for category in PROTECTED:
        base = base_categories.get(category, {})
        current = candidate_categories.get(category, {})
        base_hard = _metric(base, ("hard_score", "numeric_fidelity", "score"), 1.0)
        current_hard = _metric(current, ("hard_score", "numeric_fidelity", "score"), 1.0)
        if current_hard < base_hard:
            protected_regressions[category] = {"baseline": base_hard, "candidate": current_hard}
    baseline_types = set(baseline.get("critical_failure_types", []))
    candidate_types = set(candidate.get("critical_failure_types", []))
    new_critical_types = sorted(candidate_types - baseline_types)
    baseline_worst = float(baseline.get("worst_case_critical_frequency", 0.0))
    candidate_worst = float(candidate.get("worst_case_critical_frequency", 0.0))
    split = str(candidate.get("split", ""))
    held_out_critical = candidate_critical if split == "held_out" else 0
    accepted = (
        candidate_critical <= baseline_critical
        and not protected_regressions
        and not new_critical_types
        and candidate_worst <= baseline_worst
        and held_out_critical == 0
        and any(value > 0 for value in improvements.values())
    )
    return {
        "baseline_critical_failures": baseline_critical,
        "candidate_critical_failures": candidate_critical,
        "critical_delta": candidate_critical - baseline_critical,
        "score_delta": improvements,
        "protected_regressions": protected_regressions,
        "new_critical_types": new_critical_types,
        "baseline_worst_case_critical_frequency": baseline_worst,
        "candidate_worst_case_critical_frequency": candidate_worst,
        "held_out_critical_failures": held_out_critical,
        "accepted": accepted,
    }


def promote_champion(path: Path, candidate: dict[str, Any], *, baseline: dict[str, Any]) -> bool:
    comparison = compare_aggregate(baseline, candidate)
    if not comparison["accepted"]:
        return False
    configuration = candidate.get("configuration", {})
    record = {
        "schema_version": "1.0",
        "status": "candidate",
        "comparison": comparison,
        "configuration": configuration,
        "configuration_hash": candidate.get("configuration_hash") or configuration_hash(configuration),
        "result_hash": candidate.get("result_hash"),
        "model": candidate.get("model"),
        "split": candidate.get("split", "validation"),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return True
