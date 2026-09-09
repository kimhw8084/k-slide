"""Small, reproducible champion/challenger utilities for evaluation outputs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


PROTECTED = ("financial", "numeric", "tables", "modality", "decision_status", "risk")


def compare_aggregate(baseline: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    baseline_critical = int(baseline.get("critical_failure_count", baseline.get("critical_failures", 0)))
    candidate_critical = int(candidate.get("critical_failure_count", candidate.get("critical_failures", 0)))
    base_scores = baseline.get("mean_scores", baseline.get("metrics", {}))
    candidate_scores = candidate.get("mean_scores", candidate.get("metrics", {}))
    improvements = {key: float(candidate_scores.get(key, 0)) - float(base_scores.get(key, 0)) for key in set(base_scores) | set(candidate_scores)}
    return {"baseline_critical_failures": baseline_critical, "candidate_critical_failures": candidate_critical, "critical_delta": candidate_critical - baseline_critical, "score_delta": improvements, "accepted": candidate_critical <= baseline_critical and any(value > 0 for value in improvements.values())}


def promote_champion(path: Path, candidate: dict[str, Any], *, baseline: dict[str, Any]) -> bool:
    comparison = compare_aggregate(baseline, candidate)
    if not comparison["accepted"]:
        return False
    record = {"schema_version": "1.0", "status": "candidate", "comparison": comparison, "configuration": candidate.get("configuration", {}), "result_hash": candidate.get("result_hash")}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return True
