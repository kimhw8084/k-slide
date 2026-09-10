"""Result records and aggregates for OpenCode-backed model evaluation."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

from .certification import EvaluationState, certification_status


def aggregate_model_results(results: Iterable[dict[str, Any]], *, model: str, split: str) -> dict[str, Any]:
    cases = list(results)
    scored = [item for item in cases if item.get("semantic_scored")]
    metric_names = ("coverage", "numeric_fidelity", "modality", "table_cell_fidelity", "visual_relation_recall")
    mean_scores = {name: sum(float(item.get("semantic", {}).get(name, 0.0)) for item in scored) / len(scored) if scored else 0.0 for name in metric_names}
    category_values: dict[str, list[dict[str, Any]]] = defaultdict(list)
    format_values: dict[str, list[dict[str, Any]]] = defaultdict(list)
    repeated_groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    critical_types: Counter[str] = Counter()
    for item in scored:
        category_values[str(item.get("category"))].append(item)
        format_values[str(item.get("format"))].append(item)
        repeated_groups[(str(item.get("scenario_id")), str(item.get("format")))].append(item)
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
    requested_models = sorted({str(item.get("opencode", {}).get("model")) for item in cases if item.get("opencode", {}).get("model")})
    effective_models = sorted({str(item.get("opencode", {}).get("diagnostics", {}).get("effective_model")) for item in cases if item.get("opencode", {}).get("diagnostics", {}).get("effective_model")})
    media_cases = []
    for item in cases:
        media_units = item.get("media_by_work_unit", {})
        media_cases.append(bool(media_units) and all(value.get("media_sequence_valid") is True for value in media_units.values() if isinstance(value, dict)))
    locked_terms = [float(item.get("semantic", {}).get("term_consistency_recall", 1.0)) for item in scored]
    unexpected_unresolved = [float(item.get("semantic", {}).get("unexpected_unresolved_rate", 0.0)) for item in scored]
    review_case_count = sum(1 for item in scored if float(item.get("semantic", {}).get("unresolved_region_rate", 0.0)) > 0)
    stability_groups = {
        f"{scenario}/{format_name}": {
            "repetitions": len(group),
            "critical_failure_runs": sum(bool(item.get("semantic", {}).get("critical_failures")) for item in group),
            "critical_frequency": sum(bool(item.get("semantic", {}).get("critical_failures")) for item in group) / len(group),
            "mean_hard_score": sum(not item.get("semantic", {}).get("critical_failures") for item in group) / len(group),
            "minimum_hard_score": min((float(item.get("semantic", {}).get("coverage", 0.0)) for item in group), default=0.0),
            "maximum_hard_score": max((float(item.get("semantic", {}).get("coverage", 0.0)) for item in group), default=0.0),
        }
        for (scenario, format_name), group in sorted(repeated_groups.items())
    }
    worst_case_frequency = max((item["critical_frequency"] for item in stability_groups.values()), default=0.0)
    protocol_smoke = any(item.get("status") == "PROTOCOL_SMOKE_ONLY" or item.get("opencode", {}).get("mode") == "protocol" for item in cases)
    if quality_authoritative:
        evaluation_state = certification_status(
            authoritative=True,
            critical_failures=sum(len(item.get("semantic", {}).get("critical_failures", [])) for item in scored),
        ).value
    elif protocol_smoke:
        evaluation_state = EvaluationState.PROTOCOL_SMOKE_ONLY.value
    elif endpoint_blocked:
        evaluation_state = EvaluationState.CAPABILITY_BLOCKED.value
    else:
        evaluation_state = EvaluationState.NOT_MEASURED.value
    return {
        "model": model,
        "requested_model": requested_models[0] if len(requested_models) == 1 else model,
        "effective_model_ids": effective_models,
        "split": split,
        "case_count": len(cases),
        "semantic_scored_case_count": len(scored),
        "model_given_valid_evidence_case_count": sum(item.get("engine_gate") == "PASS" for item in cases),
        "total_system_end_to_end_failures": end_to_end_failures,
        "quality_metrics_authoritative": quality_authoritative,
        "evaluation_state": evaluation_state,
        "target_endpoint_blocked": endpoint_blocked,
        "effective_model_identity_proven_count": sum(1 for item in cases if item.get("opencode", {}).get("diagnostics", {}).get("model_identity_proven") is True),
        "mean_scores": mean_scores,
        "critical_failure_count": sum(len(item.get("semantic", {}).get("critical_failures", [])) for item in scored),
        "critical_failure_types": sorted(critical_types),
        "worst_case_critical_frequency": worst_case_frequency,
        "review_case_count": review_case_count,
        "review_rate": review_case_count / len(scored) if scored else 0.0,
        "unresolved_region_rate": sum(float(item.get("semantic", {}).get("unresolved_region_rate", 0.0)) for item in scored) / len(scored) if scored else 0.0,
        "unexpected_unresolved_rate": sum(unexpected_unresolved) / len(unexpected_unresolved) if unexpected_unresolved else 0.0,
        "required_media_compliance": bool(media_cases) and all(media_cases),
        "media_compliance_rate": sum(media_cases) / len(media_cases) if media_cases else 0.0,
        "locked_terminology_recall": sum(locked_terms) / len(locked_terms) if locked_terms else 1.0,
        "stability_groups": stability_groups,
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
