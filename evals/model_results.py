"""Result records and aggregates for OpenCode-backed model evaluation."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


def aggregate_model_results(results: Iterable[dict[str, Any]], *, model: str, split: str) -> dict[str, Any]:
    cases = list(results)
    scored = [item for item in cases if item.get("semantic_scored")]
    metric_names = ("coverage", "numeric_fidelity", "modality", "table_cell_fidelity", "visual_relation_recall")
    mean_scores = {name: sum(float(item.get("semantic", {}).get(name, 0.0)) for item in scored) / len(scored) if scored else 0.0 for name in metric_names}
    category_values: dict[str, list[dict[str, Any]]] = defaultdict(list)
    format_values: dict[str, list[dict[str, Any]]] = defaultdict(list)
    critical_types: Counter[str] = Counter()
    for item in scored:
        category_values[str(item.get("category"))].append(item)
        format_values[str(item.get("format"))].append(item)
        critical_types.update(item.get("semantic", {}).get("critical_failures", []))

    def summarize(values: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "case_count": len(values),
            "hard_score": sum(not item.get("semantic", {}).get("critical_failures") for item in values) / len(values) if values else 0.0,
            "critical_failure_count": sum(len(item.get("semantic", {}).get("critical_failures", [])) for item in values),
            **{name: sum(float(item.get("semantic", {}).get(name, 0.0)) for item in values) / len(values) if values else 0.0 for name in metric_names},
        }

    end_to_end_failures = sum(1 for item in cases if item.get("status") not in {"PASS", "PROTOCOL_SMOKE_ONLY"})
    quality_authoritative = bool(cases) and all(item.get("quality_metrics_authoritative") is True for item in cases)
    endpoint_blocked = any(
        any(
            marker in (
                str(item.get("opencode", {}).get("reason", ""))
                + " "
                + " ".join(item.get("opencode", {}).get("diagnostics", {}).get("structured_error_text", []))
            ).lower()
            for marker in ("model not found", "model unavailable", "unknown model")
        )
        for item in cases
    )
    return {
        "model": model,
        "split": split,
        "case_count": len(cases),
        "semantic_scored_case_count": len(scored),
        "model_given_valid_evidence_case_count": sum(item.get("engine_gate") == "PASS" for item in cases),
        "total_system_end_to_end_failures": end_to_end_failures,
        "quality_metrics_authoritative": quality_authoritative,
        "target_endpoint_blocked": endpoint_blocked,
        "effective_model_identity_proven_count": sum(1 for item in cases if item.get("opencode", {}).get("diagnostics", {}).get("model_identity_proven") is True),
        "mean_scores": mean_scores,
        "critical_failure_count": sum(len(item.get("semantic", {}).get("critical_failures", [])) for item in scored),
        "critical_failure_types": sorted(critical_types),
        "worst_case_critical_frequency": max((1.0 if item.get("semantic", {}).get("critical_failures") else 0.0 for item in scored), default=0.0),
        "by_category": {key: summarize(value) for key, value in sorted(category_values.items())},
        "by_format": {key: summarize(value) for key, value in sorted(format_values.items())},
    }


def write_results(output: Path, results: list[dict[str, Any]], summary: dict[str, Any], report: str) -> None:
    output.mkdir(parents=True, exist_ok=True)
    with (output / "results.jsonl").open("w", encoding="utf-8") as stream:
        for result in results:
            stream.write(json.dumps(result, ensure_ascii=False) + "\n")
    (output / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (output / "MODEL_EVAL_REPORT.md").write_text(report, encoding="utf-8")
