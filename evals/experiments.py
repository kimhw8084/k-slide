"""Reproducible champion/challenger governance for model experiments."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .certification import CATEGORY_POLICY, DEFAULT_REVIEW_RATE_TOLERANCE

# Compatibility name retained for callers; values are the real Scenario.category
# keys and are governed by CATEGORY_POLICY.
PROTECTED = tuple(CATEGORY_POLICY)


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


def _review_rate(value: dict[str, Any]) -> float:
    return float(value.get("review_rate", value.get("needs_review_rate", value.get("unresolved_rate", 0.0))))


def compare_aggregate(baseline: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    baseline_critical = int(baseline.get("critical_failure_count", baseline.get("critical_failures", 0)))
    candidate_critical = int(candidate.get("critical_failure_count", candidate.get("critical_failures", 0)))
    base_scores = baseline.get("mean_scores", baseline.get("metrics", {}))
    candidate_scores = candidate.get("mean_scores", candidate.get("metrics", {}))
    improvements = {key: float(candidate_scores.get(key, 0)) - float(base_scores.get(key, 0)) for key in set(base_scores) | set(candidate_scores)}
    base_categories = _category_metrics(baseline)
    candidate_categories = _category_metrics(candidate)
    protected_regressions: dict[str, dict[str, dict[str, float]]] = {}
    for category, policy in CATEGORY_POLICY.items():
        base = base_categories.get(category)
        current = candidate_categories.get(category)
        if base is None:
            continue
        if current is None:
            protected_regressions[category] = {metric: {"baseline": _metric(base, (metric,), 0.0), "candidate": 0.0} for metric in policy["protected_metrics"]}
            continue
        for metric in policy["protected_metrics"]:
            base_value = _metric(base, (metric,), 0.0)
            current_value = _metric(current, (metric,), 0.0)
            if current_value < base_value:
                protected_regressions.setdefault(category, {})[metric] = {"baseline": base_value, "candidate": current_value}
    baseline_types = set(baseline.get("critical_failure_types", []))
    candidate_types = set(candidate.get("critical_failure_types", []))
    new_critical_types = sorted(candidate_types - baseline_types)
    baseline_worst = float(baseline.get("worst_case_critical_frequency", 0.0))
    candidate_worst = float(candidate.get("worst_case_critical_frequency", 0.0))
    split = str(candidate.get("split", ""))
    held_out_critical = candidate_critical if split == "held_out" else 0
    review_rate_regression = max(0.0, _review_rate(candidate) - _review_rate(baseline)) > DEFAULT_REVIEW_RATE_TOLERANCE
    qualification_failures: list[str] = []
    if candidate.get("target_model_approved") is not True:
        qualification_failures.append("TARGET_MODEL_NOT_APPROVED")
    if candidate.get("quality_metrics_authoritative") is not True:
        qualification_failures.append("QUALITY_METRICS_NOT_AUTHORITATIVE")
    if split != "validation":
        qualification_failures.append("PROMOTION_REQUIRES_VALIDATION")
    accepted = (
        not qualification_failures
        and
        candidate_critical <= baseline_critical
        and not protected_regressions
        and not new_critical_types
        and candidate_worst <= baseline_worst
        and not review_rate_regression
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
        "review_rate_regression": review_rate_regression,
        "qualification_failures": qualification_failures,
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
