"""Result records and aggregates for OpenCode-backed model evaluation."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

from .certification import EvaluationState, certification_status
from k_slide.quality_policy import (
    QUALITY_POLICY_IDENTITY,
    QUALITY_FLOORS,
    deterministic_mean,
    make_hard_gate_finding,
    policy_identity_record,
)


def repeated_group_key(row: dict[str, Any]) -> tuple[str, str]:
    """Canonical repeated-run identity shared by aggregation and certification."""

    scenario_id = row.get("scenario_id")
    format_name = row.get("format")
    if not isinstance(scenario_id, str) or not scenario_id:
        raise ValueError("model result row is missing scenario_id")
    if not isinstance(format_name, str) or not format_name:
        raise ValueError("model result row is missing format")
    return scenario_id, format_name.lower()


def _scorer_gate_codes(semantic: dict[str, Any]) -> set[str]:
    evidence = semantic.get("hard_gate_evidence")
    if not isinstance(evidence, dict):
        return set()
    codes: set[str] = set()
    if evidence.get("missing_required_region_ids"):
        codes.add("SILENT_REGION_OMISSION")
    if evidence.get("numeric_mismatch_fact_ids"):
        codes.add("CRITICAL_NUMERIC_MISMATCH")
    if float(evidence.get("modality_score", 1.0)) < 1.0:
        codes.add("CRITICAL_MODALITY_MISMATCH")
    if evidence.get("modality_source_binding_failure") is True or evidence.get("noncritical_semantic_source_binding_failure") is True or evidence.get("duplicate_region_ids"):
        codes.add("SCORER_SOURCE_BINDING_FAILURE")
    if int(evidence.get("hangul_violation_count", 0)) > 0:
        codes.add("UNEXPECTED_HANGUL")
    if int(evidence.get("unsupported_claim_count", 0)) > 0:
        codes.add("UNSUPPORTED_EXECUTIVE_CLAIM")
    codes.update(str(value) for value in evidence.get("executive_claim_failure_codes", []) if isinstance(value, str))
    if evidence.get("table_cardinality_mismatch") is True:
        codes.add("TABLE_CARDINALITY_MISMATCH")
    table_failures = set(str(value) for value in evidence.get("table_failure_codes", []) if isinstance(value, str))
    if table_failures:
        codes.add("TABLE_CELL_SEMANTIC_FAILURE")
        if "TABLE_CARDINALITY_MISMATCH" in table_failures:
            codes.add("TABLE_CARDINALITY_MISMATCH")
        codes.update(code for code in table_failures if code.startswith(("MISSING_TABLE:", "MISSING_CELL:")))
    if evidence.get("table_header_failure_ids"):
        codes.add("TABLE_HEADER_SEMANTIC_FAILURE")
    codes.update(str(value) for value in evidence.get("chart_failure_codes", []) if isinstance(value, str))
    codes.update(str(value) for value in evidence.get("process_failure_codes", []) if isinstance(value, str))
    if evidence.get("process_failure_codes"):
        codes.add("VISUAL_RELATION_OMISSION")
    if set(evidence.get("material_unresolved_required_ids", [])) - set(evidence.get("material_unresolved_observed_ids", [])):
        codes.add("MATERIAL_UNRESOLVED_MISSED")
    return codes


def _noncritical_semantic_counts(semantic: dict[str, Any]) -> tuple[int, int]:
    observations = semantic.get("noncritical_semantic_observations")
    if not isinstance(observations, list):
        raise ValueError("model result is missing non-critical semantic observations")
    identifiers: list[str] = []
    required = correct = 0
    for item in observations:
        if not isinstance(item, dict) or set(item) != {"assertion_id", "source_object_id", "anchor_kind", "anchor_sha256", "outcome"}:
            raise ValueError("model result has a malformed non-critical semantic observation")
        assertion_id = item.get("assertion_id")
        if not isinstance(assertion_id, str) or not assertion_id:
            raise ValueError("model result has an invalid non-critical semantic assertion ID")
        identifiers.append(assertion_id)
        outcome = item.get("outcome")
        if outcome not in {"CORRECT", "INCORRECT", "UNRESOLVED_EXEMPT"}:
            raise ValueError("model result has an unknown non-critical semantic outcome")
        if outcome != "UNRESOLVED_EXEMPT":
            required += 1
            correct += int(outcome == "CORRECT")
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("model result duplicates a non-critical semantic assertion ID")
    expected_ids = semantic.get("noncritical_semantic_assertion_ids")
    if not isinstance(expected_ids, list) or any(not isinstance(value, str) or not value for value in expected_ids) or len(expected_ids) != len(set(expected_ids)) or sorted(expected_ids) != sorted(identifiers):
        raise ValueError("model result non-critical semantic assertion membership is incomplete")
    rate = correct / required if required else 1.0
    if semantic.get("noncritical_semantic_required_count") != required or semantic.get("noncritical_semantic_correct_count") != correct:
        raise ValueError("model result non-critical semantic counts disagree with observations")
    if semantic.get("noncritical_semantic_equivalence") != rate:
        raise ValueError("model result non-critical semantic rate disagrees with observations")
    return required, correct


def derive_result_hard_gate_findings(row: dict[str, Any]) -> list[dict[str, str]]:
    """Build source-free case findings from semantic and structured runtime facts."""

    findings: dict[tuple[str, str, str | None], dict[str, str]] = {}

    def add(code: str, unit_id: str | None = None) -> None:
        finding = make_hard_gate_finding(code, work_unit_id=unit_id)
        key = (finding["code"], finding.get("unknown_code_sha256", ""), unit_id)
        findings[key] = finding

    semantic = row.get("semantic") if isinstance(row.get("semantic"), dict) else {}
    unit_rows = row.get("units") if isinstance(row.get("units"), list) else []
    semantic_codes: set[str] = set()
    unit_codes: set[str] = set()
    if unit_rows:
        for unit in unit_rows:
            if not isinstance(unit, dict):
                continue
            unit_id = str(unit.get("work_unit_id") or "") or None
            unit_semantic = unit.get("semantic") if isinstance(unit.get("semantic"), dict) else {}
            codes = {str(code) for code in unit_semantic.get("critical_failures", []) if isinstance(code, str)}
            codes.update(_scorer_gate_codes(unit_semantic))
            semantic_codes.update(codes)
            unit_codes.update(codes)
            for code in codes:
                add(code, unit_id)
    semantic_codes.update(str(code) for code in semantic.get("critical_failures", []) if isinstance(code, str))
    if int(semantic.get("inconsistent_alternate_count", 0) or 0) > 0:
        semantic_codes.add("CROSS_SLIDE_TERM_INCONSISTENCY")
    for code in semantic_codes - unit_codes:
        add(code)

    opencode = row.get("opencode") if isinstance(row.get("opencode"), dict) else {}
    tool_calls = opencode.get("tool_calls", [])
    forbidden = opencode.get("forbidden_attempts", [])
    try:
        from .opencode_events import FORBIDDEN_TOOL_NAMES

        calls_forbidden = isinstance(tool_calls, list) and any(str(tool).lower() in FORBIDDEN_TOOL_NAMES for tool in tool_calls)
    except ImportError:
        calls_forbidden = False
    if forbidden or calls_forbidden or int(opencode.get("read_policy_violation_count", 0) or 0) > 0:
        add("FORBIDDEN_TOOL_ATTEMPT")

    media = row.get("media_by_work_unit")
    if row.get("semantic_scored") is True and (
        not isinstance(media, dict) or not media or any(
            not isinstance(value, dict)
            or value.get("media_sequence_valid") is not True
            or value.get("required_context_image_read") is not True
            or value.get("required_count", 0) < 1
            or value.get("read_count") != value.get("required_count")
            for value in media.values()
        )
    ):
        add("REQUIRED_MEDIA_READ_FAILURE")

    identity = row.get("model_identity") if isinstance(row.get("model_identity"), dict) else {}
    diagnostics = opencode.get("diagnostics") if isinstance(opencode.get("diagnostics"), dict) else {}
    if identity.get("executed") is True and (
        identity.get("approved") is not True
        or identity.get("proven") is not True
        or identity.get("mixed") is True
    ):
        add("WRONG_MODEL_IDENTITY" if identity.get("approved") is not True or identity.get("mixed") is True else "MODEL_IDENTITY_UNPROVEN")
    elif diagnostics.get("model_identity_proven") is False and row.get("semantic_scored") is True:
        add("MODEL_IDENTITY_UNPROVEN")

    contract = row.get("work_unit_contract") if isinstance(row.get("work_unit_contract"), dict) else {}
    failures = contract.get("failures", [])
    if row.get("semantic_scored") is True and (contract.get("pass") is not True or bool(failures)):
        add("WORK_UNIT_CONTRACT_FAILURE")
    if row.get("engine_gate") not in {None, "PASS"} and row.get("semantic_scored") is True:
        add("ENGINE_EVIDENCE_CONTRACT_FAILURE")
    execution = row.get("persisted_execution") if isinstance(row.get("persisted_execution"), dict) else {}
    if execution.get("false_done_recovery_violation") is True or (execution.get("material_unresolved_required_count", 0) and execution.get("run_complete") is True):
        add("FALSE_DONE_WITH_MATERIAL_UNRESOLVED")
    if execution.get("verification_contract_failure") is True:
        add("ENGINE_EVIDENCE_CONTRACT_FAILURE")
    if execution.get("available") is True and execution.get("reported_run_complete") is not execution.get("run_complete"):
        add("ENGINE_EVIDENCE_CONTRACT_FAILURE")
    if execution.get("conflict_resolution_failure") is True:
        add("MATERIAL_CONFLICT_RESOLUTION_FAILURE")

    return sorted(findings.values(), key=lambda item: (item["category"], item["code"], item.get("work_unit_id", ""), item.get("unknown_code_sha256", "")))


def aggregate_model_results(results: Iterable[dict[str, Any]], *, model: str, split: str) -> dict[str, Any]:
    cases = list(results)
    scored = [item for item in cases if item.get("semantic_scored")]
    metric_names = ("coverage", "numeric_fidelity", "modality", "table_cell_fidelity", "visual_relation_recall")
    mean_scores = {name: deterministic_mean([float(item.get("semantic", {}).get(name, 0.0)) for item in scored]) for name in metric_names}
    category_values: dict[str, list[dict[str, Any]]] = defaultdict(list)
    format_values: dict[str, list[dict[str, Any]]] = defaultdict(list)
    repeated_groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    critical_types: Counter[str] = Counter()
    for item in scored:
        category_values[str(item.get("category"))].append(item)
        format_values[str(item.get("format"))].append(item)
        repeated_groups[repeated_group_key(item)].append(item)
        critical_types.update(item.get("semantic", {}).get("critical_failures", []))
    for item in cases:
        findings = derive_result_hard_gate_findings(item)
        item["hard_gate_findings"] = findings
        critical_types.update(finding["code"] for finding in findings)

    def summarize(values: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "case_count": len(values),
            "hard_score": sum(not item.get("semantic", {}).get("critical_failures") for item in values) / len(values) if values else 0.0,
            "critical_failure_count": sum(len(item.get("hard_gate_findings", [])) for item in values),
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
    locked_terms = [float(item["semantic"]["term_consistency_recall"]) for item in scored if "term_consistency_recall" in item.get("semantic", {})]
    unexpected_unresolved = [float(item["semantic"]["unexpected_unresolved_rate"]) for item in scored if "unexpected_unresolved_rate" in item.get("semantic", {})]
    locked_terminology_recall = deterministic_mean(locked_terms) if len(locked_terms) == len(scored) and locked_terms else None
    unexpected_unresolved_rate = deterministic_mean(unexpected_unresolved) if len(unexpected_unresolved) == len(scored) and unexpected_unresolved else None
    review_case_count = sum(1 for item in scored if float(item.get("semantic", {}).get("unresolved_region_rate", 0.0)) > 0)
    noncritical_counts = [_noncritical_semantic_counts(item.get("semantic", {})) for item in scored]
    noncritical_required = sum(required for required, _correct in noncritical_counts)
    noncritical_correct = sum(correct for _required, correct in noncritical_counts)
    required_unresolved = sum(int(item.get("semantic", {}).get("material_unresolved_required_count", 0)) for item in scored)
    recovered_unresolved = sum(int(item.get("semantic", {}).get("material_unresolved_true_positive_count", 0)) for item in scored)
    observed_unresolved = sum(int(item.get("semantic", {}).get("unresolved_observed_count", 0)) for item in scored)
    unnecessary_unresolved = sum(int(item.get("semantic", {}).get("unresolved_false_positive_count", 0)) for item in scored)
    material_unresolved_recall = recovered_unresolved / required_unresolved if required_unresolved else 1.0
    unresolved_precision = recovered_unresolved / observed_unresolved if observed_unresolved else 1.0
    noncritical_semantic_equivalence = noncritical_correct / noncritical_required if noncritical_required else 1.0
    noncritical_floor_pass = (
        material_unresolved_recall >= QUALITY_FLOORS["material_unresolved_recall_min"]
        and noncritical_semantic_equivalence >= QUALITY_FLOORS["noncritical_semantic_equivalence_min"]
        and unresolved_precision >= QUALITY_FLOORS["unresolved_precision_min"]
        and locked_terminology_recall is not None
        and locked_terminology_recall >= QUALITY_FLOORS["locked_terminology_recall_min"]
    )
    hard_gate_failure_count = sum(len(item.get("hard_gate_findings", [])) for item in cases)
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
            critical_failures=hard_gate_failure_count,
            quality_floors_pass=noncritical_floor_pass,
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
        "quality_authority_state": "AUTHORITATIVE" if quality_authoritative else "NOT_AUTHORITATIVE",
        "quality_policy": policy_identity_record(),
        "quality_policy_identity": QUALITY_POLICY_IDENTITY,
        "evaluation_state": evaluation_state,
        "target_endpoint_blocked": endpoint_blocked,
        "effective_model_identity_proven_count": sum(1 for item in cases if item.get("opencode", {}).get("diagnostics", {}).get("model_identity_proven") is True),
        "mean_scores": mean_scores,
        "critical_failure_count": hard_gate_failure_count,
        "critical_failure_types": sorted(critical_types),
        "hard_gate_failure_count": hard_gate_failure_count,
        "hard_gate_failure_types": sorted({finding["code"] for item in cases for finding in item.get("hard_gate_findings", [])}),
        "hard_gate_pass": hard_gate_failure_count == 0,
        "noncritical_floor_pass": noncritical_floor_pass,
        "noncritical_semantic_required_count": noncritical_required,
        "noncritical_semantic_correct_count": noncritical_correct,
        "noncritical_semantic_equivalence": noncritical_semantic_equivalence,
        "material_unresolved_recall": material_unresolved_recall,
        "unresolved_precision": unresolved_precision,
        "unresolved_observed_count": observed_unresolved,
        "unnecessary_unresolved_count": unnecessary_unresolved,
        "worst_case_critical_frequency": worst_case_frequency,
        "review_case_count": review_case_count,
        "review_rate": review_case_count / len(scored) if scored else 0.0,
        "unresolved_region_rate": sum(float(item.get("semantic", {}).get("unresolved_region_rate", 0.0)) for item in scored) / len(scored) if scored else 0.0,
        "unexpected_unresolved_rate": unexpected_unresolved_rate,
        "required_media_compliance": bool(media_cases) and all(media_cases),
        "media_compliance_rate": sum(media_cases) / len(media_cases) if media_cases else 0.0,
        "locked_terminology_recall": locked_terminology_recall,
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
