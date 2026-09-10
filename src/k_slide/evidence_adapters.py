"""Type-specific, result-derived certification evidence adapters.

Machine evidence is deliberately produced from runner output rather than from
an administrator-authored metrics dictionary.  The adapters are small,
strict, and source-free: they return only the aggregate facts needed by the
release gate while retaining hashes for every underlying result file.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Callable

from .certification import (
    EvidenceValidationError,
    candidate_deployment_fingerprint,
    canonical_dependency_inventory,
    canonical_package_name,
    dependency_inventory_hash,
    explicit_unavailable_value,
    load_dependency_inventory,
    resolve_candidate_spec,
    NOT_APPLICABLE_VALUE,
    NOT_EXPOSED_VALUE,
    sha256_file,
)
from .model_policy import load_model_policy

# 2.2 adds candidate-bound multimodal and production dependency proof to the
# candidate-bound identity/provenance contract introduced in 2.1.
# separation and exact frozen scenario matrices. No production-certified v1
# or 2.0 evidence exists, so ambiguous development envelopes are not migrated.
ADAPTER_VERSION = "2.2"

_ROLES: dict[str, tuple[str, ...]] = {
    "runtime": ("diagnostic_ladder", "simple_run", "three_slide", "five_slide"),
    "heavy_runtime": ("required_doctor", "networkless_doctor", "representative_engine"),
    "model_validation": ("model_summary", "experiment_manifest", "results_jsonl"),
    "model_high_risk_stability": ("model_summary", "experiment_manifest", "results_jsonl"),
    "model_held_out": ("model_summary", "experiment_manifest", "results_jsonl"),
    "security": ("pip_audit", "gitleaks", "semgrep", "scanner_exits", "audit_context", "semgrep_ruleset", "dependency_inventory", "production_sbom"),
    "reliability": ("failure_injection", "concurrency", "large_deck", "performance_slo"),
    "governance": ("governance_api",),
}


class AdapterError(ValueError):
    """Raised when a source result cannot prove its evidence type."""


def required_roles(evidence_type: str) -> tuple[str, ...]:
    try:
        return _ROLES[evidence_type]
    except KeyError as exc:
        raise AdapterError(f"no machine adapter for {evidence_type}") from exc


def _read_json(path: Path) -> Any:
    if path.is_symlink() or not path.is_file():
        raise AdapterError(f"source result is missing or symlinked: {path.name}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(value, dict) and value.get("schema_version") not in (None, "1.0", "2.0", "2.1", "2.2"):
            raise AdapterError(f"unsupported source result schema version: {path.name}")
        return value
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AdapterError(f"source result is malformed: {path.name}") from exc


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if path.is_symlink() or not path.is_file():
        raise AdapterError(f"source result is missing or symlinked: {path.name}")
    rows: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise AdapterError(f"source result is unreadable: {path.name}") from exc
    for index, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise AdapterError(f"malformed JSONL at {path.name}:{index}") from exc
        if not isinstance(value, dict):
            raise AdapterError(f"JSONL row is not an object at {path.name}:{index}")
        rows.append(value)
    if not rows:
        raise AdapterError(f"source result is empty: {path.name}")
    return rows


def _bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise AdapterError(f"{label} must be boolean")
    return value


def _status(value: Any, label: str) -> None:
    if not isinstance(value, dict) or value.get("status") != "PASS":
        raise AdapterError(f"{label} did not PASS")


def _number(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AdapterError(f"{label} must be numeric")
    return float(value)


def _sha256_text(value: Any, label: str) -> str:
    text = str(value or "").lower()
    if len(text) != 64 or any(char not in "0123456789abcdef" for char in text):
        raise AdapterError(f"{label} must be a SHA-256 hex digest")
    return text


def _hash_file(path: Path) -> str:
    from .certification import sha256_file

    return sha256_file(path)


def source_records(sources: dict[str, Path], *, expected: tuple[str, ...]) -> tuple[dict[str, Path], list[dict[str, str]]]:
    if set(sources) != set(expected):
        missing = sorted(set(expected) - set(sources))
        extra = sorted(set(sources) - set(expected))
        raise AdapterError(f"source roles mismatch; missing={missing}; extra={extra}")
    result: list[dict[str, str]] = []
    normalized: dict[str, Path] = {}
    for role in expected:
        path = Path(sources[role]).expanduser()
        if path.is_symlink() or not path.is_file():
            raise AdapterError(f"source result is missing or symlinked: {role}")
        normalized[role] = path.resolve()
        result.append({"role": role, "path": path.name, "sha256": _hash_file(path)})
    return normalized, result


def _level_map(value: dict[str, Any]) -> dict[str, dict[str, Any]]:
    levels = value.get("levels")
    if not isinstance(levels, list):
        raise AdapterError("diagnostic ladder levels are missing")
    result: dict[str, dict[str, Any]] = {}
    for item in levels:
        if isinstance(item, dict) and item.get("level"):
            result[str(item["level"])] = item
    return result


def _run_contract(value: dict[str, Any], label: str, *, require_deck_count: bool = False) -> dict[str, Any]:
    if value.get("status") not in {"PASS", "PROTOCOL_SMOKE_ONLY"} and value.get("completion_contract", {}).get("pass") is not True:
        raise AdapterError(f"{label} did not PASS")
    completion = value.get("diagnostics", {}).get("completion", {})
    run_complete = value.get("run_complete") is True or value.get("completion_contract", {}).get("pass") is True or (value.get("kslide_complete") is True and completion.get("phase") == "COMPLETE" and not completion.get("missing_artifacts"))
    if value.get("kslide_complete") is False or not run_complete:
        raise AdapterError(f"{label} is not a complete K-Slide run")
    forbidden = value.get("forbidden_tool_attempts", value.get("forbidden_attempts", [])) or value.get("diagnostics", {}).get("forbidden_attempts", [])
    if forbidden:
        raise AdapterError(f"{label} contains forbidden tool attempts")
    if value.get("required_media_compliance") is not True and value.get("media_compliance") is not True:
        media = value.get("media") or value.get("media_compliance") or {}
        media_units = media.get("work_units", {}) if isinstance(media, dict) else {}
        media_pass = value.get("completion_contract", {}).get("media_pass") is True or (bool(media_units) and all(item.get("media_sequence_valid") is True for item in media_units.values() if isinstance(item, dict)))
        if not media_pass:
            raise AdapterError(f"{label} does not prove required media compliance")
    if require_deck_count:
        expected = value.get("expected_units")
        actual = value.get("artifact_units", value.get("actual_units"))
        if not isinstance(expected, int) or not isinstance(actual, int) or expected != actual:
            raise AdapterError(f"{label} work-unit count is incomplete")
    return {
        "status": True,
        "media": True,
        "run_complete": True,
        "expected_units": value.get("expected_units"),
        "artifact_units": value.get("artifact_units", value.get("actual_units")),
    }


def _derive_runtime(sources: dict[str, Path]) -> dict[str, Any]:
    values, _ = source_records(sources, expected=_ROLES["runtime"] + (("resume",) if "resume" in sources else ()))
    ladder = _level_map(_read_json(values["diagnostic_ladder"]))
    for name in ("level1a_pure_opencode", "level1_plain_opencode", "level2_explicit_model", "level3_k_slide_agent"):
        if name not in ladder or ladder[name].get("status") != "PASS":
            raise AdapterError(f"diagnostic ladder level failed: {name}")
    simple = _run_contract(_read_json(values["simple_run"]), "simple_run")
    three = _run_contract(_read_json(values["three_slide"]), "three_slide", require_deck_count=True)
    five = _run_contract(_read_json(values["five_slide"]), "five_slide", require_deck_count=True)
    resume_pass = False
    if "resume" in values:
        resume = _read_json(values["resume"])
        _run_contract(resume, "resume", require_deck_count=True)
        resume_pass = True
    return {
        "runtime_pass": True,
        "clean_opencode_pass": True,
        "explicit_model_pass": True,
        "kslide_agent_pass": True,
        "required_media_compliance": True,
        "run_complete": True,
        "simple_pass": simple["status"],
        "three_slide_pass": three["status"],
        "five_slide_pass": five["status"],
        "resume_pass": resume_pass,
        "expected_deck_units": {"three": three["expected_units"], "five": five["expected_units"]},
        "artifact_deck_units": {"three": three["artifact_units"], "five": five["artifact_units"]},
    }


def _doctor_pass(value: dict[str, Any], *, networkless: bool = False) -> None:
    required = ("libreoffice", "pymupdf", "python_pptx", "pillow", "paddleocr", "paddlepaddle", "korean_font", "paddle_load", "libreoffice_roundtrip", "paddle_ocr_roundtrip")
    for key in required:
        item = value.get(key)
        if not isinstance(item, dict) or item.get("status") != "PASS":
            raise AdapterError(f"heavy doctor check failed: {key}")
    if networkless:
        network = value.get("network")
        if not isinstance(network, dict) or network.get("networkless_asserted") is not True or network.get("network_required") is not False:
            raise AdapterError("networkless heavy doctor proof is missing")


def _engine_pass(value: dict[str, Any], label: str) -> None:
    engine = value.get("engine", value)
    if not isinstance(engine, dict):
        raise AdapterError(f"{label} engine summary is missing")
    if _number(engine.get("critical_failure_count"), f"{label}.critical_failure_count") != 0 or _number(engine.get("capability_block_count"), f"{label}.capability_block_count") != 0:
        raise AdapterError(f"{label} has critical or capability failures")
    for key in ("artifact_generation_pass_rate", "engine_normalization_pass_rate", "evidence_generation_pass_rate"):
        if _number(engine.get(key), f"{label}.{key}") < 1.0:
            raise AdapterError(f"{label}.{key} is incomplete")


def _derive_heavy(sources: dict[str, Path]) -> dict[str, Any]:
    values, _ = source_records(sources, expected=_ROLES["heavy_runtime"] + (("full_engine",) if "full_engine" in sources else ()))
    _doctor_pass(_read_json(values["required_doctor"]))
    _doctor_pass(_read_json(values["networkless_doctor"]), networkless=True)
    _engine_pass(_read_json(values["representative_engine"]), "representative_engine")
    full = "full_engine" in values
    if full:
        _engine_pass(_read_json(values["full_engine"]), "full_engine")
    return {"heavy_pass": True, "networkless_pass": True, "representative_engine_pass": True, "full_engine_pass": full, "unexpected_capability_blocks": 0}


def _execution_provenance(sources: dict[str, Path], *, evidence_type: str) -> dict[str, set[str]]:
    """Collect producer provenance without mixing it into candidate identity."""

    values: dict[str, set[str]] = {}
    for role, path in sources.items():
        provenance: list[dict[str, Any]] = []
        if evidence_type in {"model_validation", "model_high_risk_stability", "model_held_out"} and role == "results_jsonl":
            for row in _read_jsonl(path):
                opencode = row.get("opencode")
                if isinstance(opencode, dict) and opencode.get("runtime_version"):
                    provenance.append({"opencode_version": opencode["runtime_version"]})
        else:
            try:
                value = _read_json(path)
            except AdapterError:
                continue
            if not isinstance(value, dict):
                continue
            for key in ("runtime_provenance", "execution_runtime_provenance"):
                item = value.get(key)
                if isinstance(item, dict):
                    provenance.append(item)
        for item in provenance:
            for key, raw in item.items():
                if raw is not None and str(raw) and str(raw).upper() != "UNSET":
                    values.setdefault(str(key), set()).add(str(raw))
    return values


def _verify_candidate_execution_provenance(candidate_spec: dict[str, Any], *, evidence_type: str, sources: dict[str, Path]) -> None:
    """Require declared material runtime versions to be proven by the producer."""

    relevant = {
        "runtime": ("opencode_version", "python_version", "provider", "provider_backend", "model_revision", "quantization_or_dtype", "ocr_provider"),
        "heavy_runtime": ("python_version", "paddle_version", "paddleocr_version", "libreoffice_version"),
        "model_validation": ("opencode_version", "provider", "provider_backend", "model_revision", "quantization_or_dtype", "ocr_provider"),
        "model_high_risk_stability": ("opencode_version", "provider", "provider_backend", "model_revision", "quantization_or_dtype", "ocr_provider"),
        "model_held_out": ("opencode_version", "provider", "provider_backend", "model_revision", "quantization_or_dtype", "ocr_provider"),
    }.get(evidence_type, ())
    actual = _execution_provenance(sources, evidence_type=evidence_type)
    for key in relevant:
        expected = str(candidate_spec.get(key) or "")
        if not expected or expected.upper() == "UNSET":
            continue
        observed = actual.get(key, set())
        if explicit_unavailable_value(candidate_spec.get(key)) is not None:
            if observed:
                raise AdapterError(f"{evidence_type} execution {key} exposes metadata declared unavailable")
            continue
        if not observed:
            raise AdapterError(f"candidate {key} is not proven by {evidence_type} execution provenance")
        for value in observed:
            compatible = value == expected
            if key in {"python_version", "libreoffice_version"}:
                compatible = value == expected
            if not compatible:
                raise AdapterError(f"{evidence_type} execution {key} disagrees with candidate")


def _model_rows(values: dict[str, Path]) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    summary = _read_json(values["model_summary"])
    experiment = _read_json(values["experiment_manifest"])
    rows = _read_jsonl(values["results_jsonl"])
    if not isinstance(summary, dict) or not isinstance(experiment, dict):
        raise AdapterError("model summary/experiment must be objects")
    return summary, experiment, rows


def _model_matrix(experiment: dict[str, Any], rows: list[dict[str, Any]], *, expected_split: str, require_full_split: bool, root: Path | None) -> dict[str, Any]:
    """Validate the declared scenario × format × repeat matrix exactly."""

    scenario_ids = experiment.get("scenario_ids")
    formats = experiment.get("formats")
    repetitions = experiment.get("repetitions")
    if not isinstance(scenario_ids, list) or not scenario_ids or any(not isinstance(item, str) or not item for item in scenario_ids) or len(set(scenario_ids)) != len(scenario_ids):
        raise AdapterError("model experiment must declare unique scenario_ids")
    if not isinstance(formats, list) or not formats or any(not isinstance(item, str) or not item for item in formats) or len(set(str(item).lower() for item in formats)) != len(formats):
        raise AdapterError("model experiment must declare unique formats")
    if not isinstance(repetitions, int) or isinstance(repetitions, bool) or repetitions < 1:
        raise AdapterError("model experiment repetitions must be a positive integer")
    formats = [str(item).lower() for item in formats]
    plan = experiment.get("experiment_plan")
    if not isinstance(plan, dict):
        raise AdapterError("model experiment plan is missing")
    try:
        from evals.experiments import experiment_plan as build_plan, experiment_plan_hash as hash_plan
        expected_plan = build_plan(
            split=expected_split,
            scenario_ids=scenario_ids,
            formats=formats,
            repetitions=repetitions,
            categories=experiment.get("categories", plan.get("categories", ())),
            limit=plan.get("limit"),
            timeout=plan.get("timeout"),
            mode=plan.get("mode"),
            scenario_filter=plan.get("scenario_filter", ()),
            filters=plan.get("filters", {}),
        )
    except (ImportError, TypeError, ValueError) as exc:
        raise AdapterError("model experiment plan cannot be canonicalized") from exc
    if plan != expected_plan or experiment.get("experiment_plan_hash") != hash_plan(expected_plan):
        raise AdapterError("model experiment plan hash does not match its declared sampling contract")
    try:
        from evals.scenarios import scenario_specs
    except ImportError as exc:
        raise AdapterError("model matrix requires the frozen scenario manifest") from exc
    frozen = {item.scenario_id: item for item in scenario_specs()}
    if any(item not in frozen for item in scenario_ids):
        raise AdapterError("model experiment contains an unknown scenario_id")
    if any(frozen[item].split != expected_split for item in scenario_ids):
        raise AdapterError("model experiment scenario_ids do not belong to its split")
    expected_ids = {item.scenario_id for item in frozen.values() if item.split == expected_split}
    declared_ids = set(scenario_ids)
    if require_full_split and declared_ids != expected_ids:
        raise AdapterError("model experiment does not declare the complete frozen split")
    declared = {(scenario_id, format_name, repeat) for scenario_id in scenario_ids for format_name in formats for repeat in range(1, repetitions + 1)}
    observed: set[tuple[str, str, int]] = set()
    for row in rows:
        scenario_id = row.get("scenario_id")
        format_name = str(row.get("format", "")).lower()
        repeat = row.get("repeat")
        if not isinstance(scenario_id, str) or not isinstance(repeat, int) or isinstance(repeat, bool):
            raise AdapterError("model result row has invalid scenario_id/format/repeat")
        key = (scenario_id, format_name, repeat)
        if key in observed:
            raise AdapterError(f"duplicate model result row: {scenario_id}/{format_name}/{repeat}")
        observed.add(key)
        if row.get("split") != expected_split:
            raise AdapterError("model result row split disagrees with experiment")
        scenario = frozen.get(scenario_id)
        if scenario is None or row.get("category") != scenario.category:
            raise AdapterError(f"model result category does not match frozen scenario: {scenario_id}")
    missing = sorted(declared - observed)
    extra = sorted(observed - declared)
    if missing or extra:
        raise AdapterError(f"model result matrix mismatch; missing={missing[:3]}; extra={extra[:3]}")
    return {"scenario_ids": sorted(scenario_ids), "formats": formats, "repetitions": repetitions, "case_count": len(rows), "matrix_hash": _sha256_text(experiment.get("experiment_plan_hash"), "experiment_plan_hash")}


def _model_identity(summary: dict[str, Any], experiment: dict[str, Any], rows: list[dict[str, Any]], policy: Any) -> tuple[str, list[str], bool]:

    requested = str(summary.get("requested_model") or experiment.get("model") or summary.get("model") or "")
    requested_values = {str(item.get("opencode", {}).get("model")) for item in rows if item.get("opencode", {}).get("model")}
    every_row_declares_requested = bool(rows) and all(isinstance(item.get("opencode", {}).get("model"), str) and item.get("opencode", {}).get("model") for item in rows)
    declared_requested = {str(value) for value in (summary.get("requested_model"), summary.get("model"), experiment.get("model")) if value}
    if not requested or not summary.get("requested_model") or not experiment.get("model") or not every_row_declares_requested or len(declared_requested) > 1 or (requested_values and requested_values != {requested}) or (declared_requested and requested not in declared_requested):
        raise AdapterError("model result requested identity is inconsistent")
    raw_effective = [item.get("opencode", {}).get("diagnostics", {}).get("effective_model") for item in rows]
    row_effective = [item.get("effective_model") for item in rows]
    if not rows or any(not isinstance(item, str) or not item for item in raw_effective) or any(not isinstance(item, str) or not item for item in row_effective):
        raise AdapterError("model result does not prove requested/effective identity")
    if any(item.get("opencode", {}).get("diagnostics", {}).get("model_identity_proven") is not True for item in rows):
        raise AdapterError("model result does not prove effective identity from every case")
    effective = sorted({canonical for item in raw_effective if (canonical := policy.canonical_effective(requested=requested, effective=item))})
    if not effective:
        raise AdapterError("model result effective identity is not approved")
    if len(effective) > 1:
        raise AdapterError("model result contains mixed effective model deployments")
    for row in rows:
        declared_row_effective = row.get("effective_model")
        if policy.canonical_effective(requested=requested, effective=str(declared_row_effective)) != effective[0]:
            raise AdapterError("model result row effective identity disagrees with diagnostics")
    for declared in (summary.get("effective_model"), experiment.get("effective_model")):
        if not declared or str(declared).upper() == "UNSET" or policy.canonical_effective(requested=requested, effective=str(declared)) != effective[0]:
            raise AdapterError("model result effective identity disagrees with its finalized manifest")
    approved = all(policy.approved(requested=requested, effective=item) for item in raw_effective)
    return requested, effective, approved


def _vision_input_proven(rows: list[dict[str, Any]]) -> bool:
    """Require actual image reads from the authoritative OpenCode cases."""

    if not rows:
        return False
    for row in rows:
        opencode = row.get("opencode")
        diagnostics = opencode.get("diagnostics") if isinstance(opencode, dict) else None
        media = opencode.get("media_compliance") if isinstance(opencode, dict) else None
        if (
            not isinstance(diagnostics, dict)
            or diagnostics.get("model_identity_proven") is not True
            or not isinstance(media, dict)
            or media.get("planned") is not True
            or media.get("required_context_image_read") is not True
            or media.get("media_sequence_valid") is not True
            or not isinstance(media.get("required_count"), int)
            or media.get("required_count", 0) < 1
            or media.get("read_count") != media.get("required_count")
        ):
            return False
    return True


def _aggregate_model(values: dict[str, Path], *, expected_split: str, root: Path | None) -> dict[str, Any]:
    summary, experiment, rows = _model_rows(values)
    if any(not isinstance(item.get("subject_git_sha"), str) or not item.get("subject_git_sha") or not isinstance(item.get("deployment_fingerprint"), str) or not item.get("deployment_fingerprint") for item in rows):
        raise AdapterError("model result row subject/deployment provenance is missing")
    identities = {(item.get("subject_git_sha"), item.get("deployment_fingerprint")) for item in (summary, experiment)}
    identities.update((item.get("subject_git_sha"), item.get("deployment_fingerprint")) for item in rows)
    if any(not isinstance(subject, str) or not subject or not isinstance(deployment, str) or not deployment for subject, deployment in identities):
        raise AdapterError("model result subject/deployment provenance is missing")
    if len(identities) > 1:
        raise AdapterError("model result provenance disagrees between summary and experiment")
    if summary.get("split") != expected_split or experiment.get("split") != expected_split or any(item.get("split") != expected_split for item in rows):
        raise AdapterError(f"model result split is not {expected_split}")
    candidate_specs = [item.get("candidate_spec") for item in (summary, experiment) if isinstance(item.get("candidate_spec"), dict)]
    if candidate_specs and isinstance(candidate_specs[0].get("model_policy"), dict):
        from .model_policy import ModelPolicy

        policy = ModelPolicy.from_mapping(candidate_specs[0]["model_policy"])
    else:
        policy = load_model_policy(root) if root else load_model_policy()
    requested, effective, approved = _model_identity(summary, experiment, rows, policy)
    if candidate_specs:
        if any(item != candidate_specs[0] for item in candidate_specs[1:]):
            raise AdapterError("model candidate specifications disagree")
        try:
            from .certification import candidate_deployment_fingerprint

            if candidate_deployment_fingerprint(candidate_specs[0]) != summary.get("deployment_fingerprint"):
                raise AdapterError("model candidate specification does not match deployment fingerprint")
        except (EvidenceValidationError, TypeError, ValueError) as exc:
            raise AdapterError("model candidate specification is malformed") from exc
        declared_effective = str(candidate_specs[0].get("effective_model") or "")
        if declared_effective.upper() == "UNSET" or str(candidate_specs[0].get("requested_model")) != requested:
            raise AdapterError("model candidate specification lacks finalized model identity")
        if policy.canonical_effective(requested=requested, effective=declared_effective) != effective[0]:
            raise AdapterError("model candidate specification effective identity disagrees with rows")
    authoritative = bool(rows) and all(item.get("quality_metrics_authoritative") is True for item in rows)
    if summary.get("quality_metrics_authoritative") is not authoritative:
        raise AdapterError("summary quality authority disagrees with case results")
    critical_count = sum(len(item.get("semantic", {}).get("critical_failures", [])) for item in rows if item.get("semantic_scored"))
    media_rates = []
    review_rates = []
    unresolved_rates = []
    unexpected_rates = []
    terminology_rates = []
    categories: set[str] = set()
    for item in rows:
        categories.add(str(item.get("category")))
        semantic = item.get("semantic", {})
        unresolved_rates.append(float(semantic.get("unresolved_region_rate", 0.0)))
        if "unexpected_unresolved_rate" not in semantic:
            raise AdapterError("model result is missing semantic.unexpected_unresolved_rate")
        if "term_consistency_recall" not in semantic:
            raise AdapterError("model result is missing semantic.term_consistency_recall")
        unexpected_rates.append(_number(semantic["unexpected_unresolved_rate"], "semantic.unexpected_unresolved_rate"))
        terminology_rates.append(_number(semantic["term_consistency_recall"], "semantic.term_consistency_recall"))
        review_rates.append(float(semantic.get("unresolved_region_rate", 0.0)) > 0)
        media = item.get("media_by_work_unit", {})
        media_rates.append(bool(media) and all(value.get("media_sequence_valid") is True for value in media.values() if isinstance(value, dict)))
    behavior_hash = _sha256_text(experiment.get("behavior_configuration_hash") or experiment.get("configuration_hash"), "model behavior_configuration_hash")
    behavior_config = experiment.get("behavior_configuration")
    if not isinstance(behavior_config, dict):
        raise AdapterError("model behavior configuration is missing")
    try:
        from evals.experiments import behavior_configuration_hash as hash_behavior
        expected_behavior_hash = hash_behavior(behavior_config, strict=True)
    except (ImportError, TypeError, ValueError) as exc:
        raise AdapterError("model behavior configuration cannot be canonicalized") from exc
    if behavior_hash != expected_behavior_hash:
        raise AdapterError("model behavior configuration hash does not match its declared behavior")
    if summary.get("behavior_configuration_hash", summary.get("configuration_hash")) != behavior_hash:
        raise AdapterError("model summary behavior configuration hash disagrees with experiment")
    plan_hash = _sha256_text(experiment.get("experiment_plan_hash"), "experiment_plan_hash")
    if summary.get("experiment_plan_hash") not in (None, plan_hash):
        raise AdapterError("model summary experiment plan hash disagrees with experiment")
    if not terminology_rates or not unexpected_rates:
        raise AdapterError("model result has no certifiable semantic safety metrics")
    derived_terminology = round(sum(terminology_rates) / len(terminology_rates), 12)
    derived_unexpected = round(sum(unexpected_rates) / len(unexpected_rates), 12)
    if not isinstance(summary.get("locked_terminology_recall"), (int, float)) or isinstance(summary.get("locked_terminology_recall"), bool):
        raise AdapterError("model summary is missing locked_terminology_recall")
    if abs(float(summary["locked_terminology_recall"]) - derived_terminology) > 1e-9:
        raise AdapterError("model summary locked terminology disagrees with case results")
    if not isinstance(summary.get("unexpected_unresolved_rate"), (int, float)) or isinstance(summary.get("unexpected_unresolved_rate"), bool):
        raise AdapterError("model summary is missing unexpected_unresolved_rate")
    if abs(float(summary["unexpected_unresolved_rate"]) - derived_unexpected) > 1e-9:
        raise AdapterError("model summary unexpected unresolved rate disagrees with case results")
    repetitions = int(experiment.get("repetitions", max((int(item.get("repeat", 1)) for item in rows), default=0)))
    matrix = _model_matrix(experiment, rows, expected_split=expected_split, require_full_split=False, root=root)
    if summary.get("case_count") is not None and summary.get("case_count") != len(rows):
        raise AdapterError("model summary case_count disagrees with result rows")
    if summary.get("semantic_scored_case_count") is not None and summary.get("semantic_scored_case_count") != sum(item.get("semantic_scored") is True for item in rows):
        raise AdapterError("model summary semantic_scored_case_count disagrees with result rows")
    for field, derived in (("critical_failure_count", critical_count), ("repetitions", repetitions), ("required_media_compliance", bool(media_rates) and all(media_rates))):
        if field in summary and summary[field] != derived:
            raise AdapterError(f"model summary {field} disagrees with result rows")
    return {
        "split": expected_split,
        "requested_model": requested,
        "effective_model": effective[0],
        "effective_model_ids": effective,
        "target_model_approved": approved,
        "quality_metrics_authoritative": authoritative,
        "critical_failure_count": critical_count,
        "repetitions": repetitions,
        "configuration_hash": behavior_hash,
        "behavior_configuration_hash": behavior_hash,
        "experiment_plan_hash": plan_hash,
        "scenario_ids": matrix["scenario_ids"],
        "formats": matrix["formats"],
        "required_media_compliance": bool(media_rates) and all(media_rates),
        "vision_input_proven": _vision_input_proven(rows),
        "media_compliance_rate": sum(media_rates) / len(media_rates) if media_rates else 0.0,
        "review_rate": sum(review_rates) / len(review_rates) if review_rates else 0.0,
        "unresolved_region_rate": sum(unresolved_rates) / len(unresolved_rates) if unresolved_rates else 0.0,
        "unexpected_unresolved_rate": derived_unexpected,
        "locked_terminology_recall": derived_terminology,
        "categories": sorted(categories),
        "case_count": len(rows),
    }


def _derive_validation(sources: dict[str, Path], *, root: Path | None) -> dict[str, Any]:
    payload = _aggregate_model(sources, expected_split="validation", root=root)
    _summary, experiment, rows = _model_rows(sources)
    _model_matrix(experiment, rows, expected_split="validation", require_full_split=True, root=root)
    plan = experiment["experiment_plan"]
    if plan.get("limit") is not None or plan.get("categories") or plan.get("scenario_filter") or plan.get("filters"):
        raise AdapterError("validation certification cannot use a reduced or filtered experiment plan")
    if (
        not payload["target_model_approved"]
        or not payload["quality_metrics_authoritative"]
        or payload["critical_failure_count"] != 0
        or payload["repetitions"] < 3
        or not payload["required_media_compliance"]
        or not payload["vision_input_proven"]
        or payload["locked_terminology_recall"] + 1e-12 < 0.995
        or payload["unexpected_unresolved_rate"] != 0
    ):
        raise AdapterError("validation result fails target, authority, critical, repeat, media, vision, terminology, or unresolved gates")
    return payload


def _derive_high_risk(sources: dict[str, Path], *, root: Path | None) -> dict[str, Any]:
    payload = _aggregate_model(sources, expected_split="validation", root=root)
    try:
        from evals.scenarios import PROTECTED_CATEGORIES
    except ImportError as exc:
        raise AdapterError("high-risk adapter requires repository evaluation policy") from exc
    _summary, experiment, _ = _model_rows(sources)
    rows = _read_jsonl(sources["results_jsonl"])
    matrix = _model_matrix(experiment, rows, expected_split="validation", require_full_split=False, root=root)
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for item in rows:
        from evals.model_results import repeated_group_key

        key = repeated_group_key(item)
        groups.setdefault(key, []).append(item)
    scenario_ids = experiment.get("scenario_ids")
    formats = experiment.get("formats")
    if not isinstance(scenario_ids, list) or not scenario_ids or not isinstance(formats, list) or not formats:
        raise AdapterError("high-risk experiment manifest must declare scenario_ids and formats")
    declared = {(str(scenario_id), str(format_name).lower()) for scenario_id in scenario_ids for format_name in formats}
    observed = set(groups)
    if observed != declared:
        raise AdapterError(f"high-risk declared groups do not exactly match observed groups; missing={sorted(declared - observed)}; extra={sorted(observed - declared)}")
    selected_categories = set(PROTECTED_CATEGORIES)
    declared_categories = experiment.get("high_risk_categories")
    if not isinstance(declared_categories, list) or len(declared_categories) != len(selected_categories) or set(declared_categories) != selected_categories:
        raise AdapterError("high-risk experiment does not declare the complete protected-category policy")
    observed_categories = {str(item.get("category")) for item in rows}
    missing_categories = sorted(selected_categories - observed_categories)
    if missing_categories:
        raise AdapterError(f"high-risk protected categories are missing: {missing_categories}")
    unexpected_categories = sorted(observed_categories - selected_categories)
    if unexpected_categories:
        raise AdapterError(f"high-risk result contains categories outside the protected policy: {unexpected_categories}")
    coverage: dict[str, int] = {}
    frequencies: dict[str, float] = {}
    category_coverage: dict[str, int] = {category: 0 for category in sorted(selected_categories)}
    for scenario_id, format_name in sorted(declared):
        items = groups.get((scenario_id, format_name), [])
        repeats = sorted(item.get("repeat") for item in items)
        if repeats != list(range(1, int(experiment["repetitions"]) + 1)) or len(items) < 5:
            raise AdapterError(f"high-risk group fails repetition gate: {scenario_id}/{format_name}")
        frequency = sum(bool(item.get("semantic", {}).get("critical_failures")) for item in items) / len(items)
        key = f"{scenario_id}/{format_name}"
        coverage[key] = len(items)
        frequencies[key] = frequency
        category_coverage[str(items[0].get("category"))] = category_coverage.get(str(items[0].get("category")), 0) + 1
        if frequency != 0:
            raise AdapterError(f"high-risk group fails critical gate: {key}")
    if payload["critical_failure_count"] != 0:
        raise AdapterError("high-risk result has critical failures outside the selected group summaries")
    if not payload["vision_input_proven"]:
        raise AdapterError("high-risk result does not prove candidate-bound multimodal execution")
    payload.update({"required_group_coverage": coverage, "group_critical_frequency": frequencies, "category_coverage": category_coverage, "worst_critical_frequency": max(frequencies.values(), default=0.0), "repetitions": min(coverage.values()), "scenario_ids": matrix["scenario_ids"], "formats": matrix["formats"]})
    return payload


def _derive_held_out(sources: dict[str, Path], *, root: Path | None) -> dict[str, Any]:
    payload = _aggregate_model(sources, expected_split="held_out", root=root)
    try:
        from evals.scenarios import split_manifest
    except ImportError as exc:
        raise AdapterError("held-out adapter requires repository evaluation schemas") from exc

    summary, experiment, rows = _model_rows(sources)
    _model_matrix(experiment, rows, expected_split="held_out", require_full_split=True, root=root)
    plan = experiment["experiment_plan"]
    if plan.get("limit") is not None or plan.get("categories") or plan.get("scenario_filter") or plan.get("filters"):
        raise AdapterError("held-out certification cannot use a reduced or filtered experiment plan")
    frozen = split_manifest()
    if summary.get("corpus_fingerprint", experiment.get("corpus_fingerprint")) != frozen["corpus_fingerprint"] or summary.get("held_out_fingerprint", experiment.get("held_out_fingerprint")) != frozen["held_out_fingerprint"] or experiment.get("corpus_fingerprint") != frozen["corpus_fingerprint"] or experiment.get("held_out_fingerprint") != frozen["held_out_fingerprint"]:
        raise AdapterError("held-out corpus fingerprints do not match frozen corpus")
    if (
        not payload["target_model_approved"]
        or not payload["quality_metrics_authoritative"]
        or payload["critical_failure_count"] != 0
        or not payload["required_media_compliance"]
        or not payload["vision_input_proven"]
        or payload["locked_terminology_recall"] + 1e-12 < 0.995
        or payload["unexpected_unresolved_rate"] != 0
    ):
        raise AdapterError("held-out result fails target, authority, critical, media, vision, terminology, or unresolved gates")
    payload.update({"corpus_fingerprint": frozen["corpus_fingerprint"], "held_out_fingerprint": frozen["held_out_fingerprint"]})
    return payload


def _derive_security(sources: dict[str, Path], *, root: Path | None = None, candidate_spec: dict[str, Any] | None = None) -> dict[str, Any]:
    values, _ = source_records(sources, expected=_ROLES["security"])
    pip = _read_json(values["pip_audit"])
    leaks = _read_json(values["gitleaks"])
    semgrep = _read_json(values["semgrep"])
    exits = _read_json(values["scanner_exits"])
    context = _read_json(values["audit_context"])
    inventory = load_dependency_inventory(values["dependency_inventory"])
    sbom = _read_json(values["production_sbom"])
    if not isinstance(pip, dict) or not isinstance(leaks, list) or not isinstance(semgrep, dict) or not isinstance(exits, dict) or not isinstance(context, dict) or not isinstance(sbom, dict):
        raise AdapterError("security scanner output has an unexpected schema")
    constraints_hash = str(context.get("candidate_constraints_sha256") or "").lower()
    audited_hash = str(context.get("audited_dependency_set_sha256") or "").lower()
    inventory_hash = dependency_inventory_hash(inventory)
    resolved_context_hash = str(context.get("resolved_dependency_set_sha256") or "").lower()
    audited_subject = str(context.get("audited_dependency_subject") or "").strip().lower()
    if len(constraints_hash) != 64 or len(audited_hash) != 64 or audited_hash != inventory_hash or resolved_context_hash != inventory_hash:
        raise AdapterError("security audit input is not bound to the resolved production dependency set")
    if audited_subject != "production-env":
        raise AdapterError("security audit did not identify the production dependency subject")
    if candidate_spec is not None:
        expected_constraints = str(candidate_spec.get("constraints_sha256") or "").lower()
        if expected_constraints != constraints_hash:
            raise AdapterError("security audit input hash disagrees with candidate constraints identity")
        expected_inventory = str(candidate_spec.get("resolved_dependency_set_sha256") or "").lower()
        if expected_inventory not in {"", "unset"} and expected_inventory != inventory_hash:
            raise AdapterError("security audit dependency set disagrees with candidate identity")
    for key in ("pip_audit_version", "semgrep_version", "semgrep_ruleset_identity"):
        value = context.get(key)
        if not isinstance(value, str) or not value or value.upper() in {"UNSET", NOT_EXPOSED_VALUE, NOT_APPLICABLE_VALUE}:
            raise AdapterError(f"security audit context is missing immutable {key}")
    ruleset_hash = str(context.get("semgrep_ruleset_sha256") or "").lower()
    if len(ruleset_hash) != 64:
        raise AdapterError("security audit context is missing Semgrep ruleset hash")
    ruleset_source = values["semgrep_ruleset"]
    if sha256_file(ruleset_source) != ruleset_hash:
        raise AdapterError("Semgrep ruleset hash does not match the staged ruleset source")
    if root is not None and candidate_spec is not None:
        repository_root = root.expanduser().resolve()
        constraints = repository_root / "constraints-production.txt"
        if not constraints.is_file() or constraints.is_symlink():
            constraints = repository_root / ".k-slide-engine" / "constraints-production.txt"
        if constraints.is_file() and not constraints.is_symlink() and sha256_file(constraints) != constraints_hash:
            raise AdapterError("security audit input hash does not match constraints-production.txt")
        ruleset_identity = Path(context["semgrep_ruleset_identity"]).expanduser()
        if ruleset_identity.is_absolute():
            raise AdapterError("Semgrep ruleset identity must be repository-relative")
        try:
            repository_ruleset_input = repository_root / ruleset_identity
            if repository_ruleset_input.is_symlink():
                raise AdapterError("Semgrep production ruleset is symlinked")
            repository_ruleset = repository_ruleset_input.resolve()
            repository_ruleset.relative_to(repository_root)
        except ValueError as exc:
            raise AdapterError("Semgrep ruleset identity escapes the repository root") from exc
        if repository_ruleset.is_file() and sha256_file(repository_ruleset) != ruleset_hash:
            raise AdapterError("Semgrep ruleset hash does not match the repository ruleset")
    dependencies = pip.get("dependencies")
    if not isinstance(dependencies, list):
        raise AdapterError("pip-audit did not report a dependency set")
    inventory_packages = {item["name"]: item["version"] for item in inventory["packages"]}
    audited_records: list[dict[str, Any]] = []
    for item in dependencies:
        if not isinstance(item, dict) or not item.get("name") or not item.get("version"):
            raise AdapterError("pip-audit dependency set contains an invalid package record")
        audited_records.append({"name": item["name"], "version": item["version"]})
    try:
        audited_inventory = canonical_dependency_inventory(audited_records)
    except EvidenceValidationError as exc:
        raise AdapterError("pip-audit dependency set is not canonical") from exc
    audited_packages = {item["name"]: item["version"] for item in audited_inventory["packages"]}
    if audited_packages != inventory_packages:
        raise AdapterError("pip-audit dependency set does not equal the resolved production inventory")
    required_names = {"pillow", "pymupdf", "python-pptx", "paddlepaddle", "paddleocr"}
    if not required_names.issubset(inventory_packages):
        raise AdapterError("production dependency audit does not include the deployed K-Slide dependency lock")
    constraint_versions = {str(key).lower().replace("_", "-"): str(value) for key, value in context.get("constraint_versions", {}).items()} if isinstance(context.get("constraint_versions"), dict) else {}
    if any(not constraint_versions.get(name) or inventory_packages.get(name) != constraint_versions.get(name) for name in required_names):
        raise AdapterError("production dependency audit versions do not match constraints-production.txt")
    if sbom.get("bomFormat") != "CycloneDX" or sbom.get("complete") is not True or not isinstance(sbom.get("components"), list):
        raise AdapterError("production SBOM is incomplete")
    if sbom.get("dependency_set_sha256") != inventory_hash:
        raise AdapterError("production SBOM is not bound to the resolved production inventory")
    sbom_records: list[dict[str, Any]] = []
    for item in sbom["components"]:
        if not isinstance(item, dict) or not item.get("name") or not item.get("version"):
            raise AdapterError("production SBOM contains an invalid component")
        if canonical_package_name(item["name"]) != "k-slide":
            sbom_records.append({"name": item["name"], "version": item["version"]})
    try:
        sbom_inventory = canonical_dependency_inventory(sbom_records)
    except EvidenceValidationError as exc:
        raise AdapterError("production SBOM dependency set is not canonical") from exc
    sbom_packages = {item["name"]: item["version"] for item in sbom_inventory["packages"]}
    if sbom_packages != inventory_packages:
        raise AdapterError("production SBOM dependency set does not equal the resolved production inventory")
    sbom_hash = sha256_file(values["production_sbom"])
    if str(context.get("production_sbom_sha256") or "").lower() != sbom_hash:
        raise AdapterError("production SBOM hash is missing or inconsistent")
    dependency_findings = sum(len(item.get("vulns", [])) for item in pip.get("dependencies", []) if isinstance(item, dict))
    if not isinstance(semgrep.get("results"), list) or not isinstance(semgrep.get("errors", []), list) or semgrep.get("errors"):
        raise AdapterError("semgrep result is malformed or contains scan errors")
    static_findings = len(semgrep.get("results", []))
    high_findings = sum(1 for item in semgrep.get("results", []) if isinstance(item, dict) and str(item.get("extra", {}).get("metadata", {}).get("severity", "")).upper() in {"HIGH", "CRITICAL"})
    secret_findings = len(leaks)
    exit_ok = all(isinstance(exits.get(name), int) and exits.get(name) == 0 for name in ("pip_audit", "gitleaks", "semgrep"))
    if not exit_ok:
        raise AdapterError("one or more security scanners failed to execute cleanly")
    if dependency_findings or secret_findings or static_findings:
        raise AdapterError("security scanner findings fail the production security gate")
    return {"dependency_audit_pass": exit_ok and dependency_findings == 0, "secret_scan_pass": exit_ok and secret_findings == 0, "static_scan_pass": exit_ok and static_findings == 0, "dependency_findings": dependency_findings, "unresolved_high_findings": high_findings, "unresolved_critical_findings": sum(1 for item in semgrep.get("results", []) if isinstance(item, dict) and str(item.get("extra", {}).get("metadata", {}).get("severity", "")).upper() == "CRITICAL"), "secret_findings": secret_findings, "scanner_exit_codes": {key: exits.get(key) for key in sorted(exits)}, "audited_dependency_set_sha256": audited_hash, "resolved_dependency_set_sha256": inventory_hash, "candidate_constraints_sha256": constraints_hash, "production_sbom_sha256": sbom_hash, "audited_dependency_versions": inventory_packages, "pip_audit_version": context["pip_audit_version"], "semgrep_version": context["semgrep_version"], "semgrep_ruleset_identity": context["semgrep_ruleset_identity"], "semgrep_ruleset_sha256": ruleset_hash}


def _derive_reliability(sources: dict[str, Path]) -> dict[str, Any]:
    values, _ = source_records(sources, expected=_ROLES["reliability"])
    failure = _read_json(values["failure_injection"])
    concurrency = _read_json(values["concurrency"])
    deck = _read_json(values["large_deck"])
    slo = _read_json(values["performance_slo"])
    for value, label in ((failure, "failure_injection"), (concurrency, "concurrency"), (deck, "large_deck"), (slo, "performance_slo")):
        _status(value, label)
    for key in ("timeout_recovery_pass", "resume_pass"):
        if failure.get(key) is not True:
            raise AdapterError(f"failure_injection.{key} must be explicitly true")
    if concurrency.get("concurrency_pass") is not True:
        raise AdapterError("concurrency.concurrency_pass must be explicitly true")
    runs = concurrency.get("concurrent_runs")
    if not isinstance(runs, int) or runs < 5:
        raise AdapterError("reliability concurrency coverage is below five isolated runs")
    if deck.get("fifty_slide_pass") is not True:
        raise AdapterError("large_deck.fifty_slide_pass must be explicitly true")
    if slo.get("slo_pass") is not True:
        raise AdapterError("performance_slo.slo_pass must be explicitly true")
    return {"timeout_recovery_pass": True, "resume_pass": True, "fifty_slide_pass": True, "concurrency_pass": True, "slo_pass": True, "concurrent_runs": runs}


def _derive_governance(sources: dict[str, Path]) -> dict[str, Any]:
    values, _ = source_records(sources, expected=_ROLES["governance"])
    value = _read_json(values["governance_api"])
    if not isinstance(value, dict) or value.get("source_kind") not in {"github_api", "approved_governance_api"}:
        raise AdapterError("governance result is not an authoritative API result")
    for key in ("codeowners_pass", "branch_protection_pass", "required_ci_pass", "review_required"):
        if value.get(key) is not True:
            raise AdapterError(f"governance check failed: {key}")
    return {key: True for key in ("codeowners_pass", "branch_protection_pass", "required_ci_pass", "review_required")}


_DERIVERS: dict[str, Callable[..., dict[str, Any]]] = {
    "runtime": _derive_runtime,
    "heavy_runtime": _derive_heavy,
    "model_validation": _derive_validation,
    "model_high_risk_stability": _derive_high_risk,
    "model_held_out": _derive_held_out,
    "security": _derive_security,
    "reliability": _derive_reliability,
    "governance": _derive_governance,
}


def derive_runtime_evidence(sources: dict[str, Path], *, root: Path | None = None) -> dict[str, Any]:
    return derive_payload("runtime", sources, root=root)


def derive_heavy_runtime_evidence(sources: dict[str, Path], *, root: Path | None = None) -> dict[str, Any]:
    return derive_payload("heavy_runtime", sources, root=root)


def derive_model_validation_evidence(sources: dict[str, Path], *, root: Path | None = None) -> dict[str, Any]:
    return derive_payload("model_validation", sources, root=root)


def derive_high_risk_evidence(sources: dict[str, Path], *, root: Path | None = None) -> dict[str, Any]:
    return derive_payload("model_high_risk_stability", sources, root=root)


def derive_held_out_evidence(sources: dict[str, Path], *, root: Path | None = None) -> dict[str, Any]:
    return derive_payload("model_held_out", sources, root=root)


def derive_security_evidence(sources: dict[str, Path], *, root: Path | None = None, candidate_spec: dict[str, Any] | None = None) -> dict[str, Any]:
    return derive_payload("security", sources, root=root, candidate_spec=candidate_spec)


def derive_reliability_evidence(sources: dict[str, Path], *, root: Path | None = None) -> dict[str, Any]:
    return derive_payload("reliability", sources, root=root)


def derive_governance_evidence(sources: dict[str, Path], *, root: Path | None = None) -> dict[str, Any]:
    return derive_payload("governance", sources, root=root)


def derive_payload(evidence_type: str, sources: dict[str, Path], *, root: Path | None = None, candidate_spec: dict[str, Any] | None = None) -> dict[str, Any]:
    try:
        deriver = _DERIVERS[evidence_type]
    except KeyError as exc:
        raise AdapterError(f"no machine deriver for {evidence_type}") from exc
    if evidence_type in {"model_validation", "model_high_risk_stability", "model_held_out"}:
        return deriver(sources, root=root)
    if evidence_type == "security":
        return deriver(sources, root=root, candidate_spec=candidate_spec)
    return deriver(sources)


def _source_descriptors(sources: dict[str, Path], output: Path) -> list[dict[str, str]]:
    parent = output.parent.resolve()
    descriptors: list[dict[str, str]] = []
    for role in sorted(sources):
        raw_path = Path(sources[role]).expanduser()
        if raw_path.is_symlink():
            raise AdapterError(f"source {role} is symlinked")
        path = raw_path.resolve()
        try:
            relative = path.relative_to(parent)
        except ValueError as exc:
            raise AdapterError(f"source {role} must be inside the evidence directory") from exc
        try:
            path.relative_to(parent)
        except ValueError as exc:
            raise AdapterError(f"source {role} escapes evidence directory") from exc
        if not path.is_file() or relative.as_posix().startswith("../"):
            raise AdapterError(f"source {role} is unsafe")
        descriptors.append({"role": role, "path": relative.as_posix(), "sha256": _hash_file(path)})
    return descriptors


def _check_embedded_identity(sources: dict[str, Path], *, subject_git_sha: str | None, deployment_fingerprint: str | None) -> None:
    """Reject contradictory provenance when a runner persisted it."""

    for role, path in sources.items():
        try:
            value = _read_json(path)
        except AdapterError:
            continue
        if not isinstance(value, dict):
            continue
        embedded_subject = value.get("subject_git_sha")
        embedded_deployment = value.get("deployment_fingerprint")
        if embedded_subject is not None or embedded_deployment is not None:
            if subject_git_sha is not None and embedded_subject != subject_git_sha:
                raise AdapterError(f"source provenance mismatch: {role}")
            if deployment_fingerprint is not None and embedded_deployment != deployment_fingerprint:
                raise AdapterError(f"source provenance mismatch: {role}")


def _finalize_candidate_spec(candidate_spec: dict[str, Any], *, evidence_type: str, sources: dict[str, Path]) -> dict[str, Any]:
    """Complete provisional candidate inputs from the runner's final manifest."""

    if evidence_type not in {"model_validation", "model_high_risk_stability", "model_held_out"}:
        return candidate_spec
    manifest = sources.get("experiment_manifest")
    if manifest is None:
        return candidate_spec
    value = _read_json(manifest)
    if not isinstance(value, dict) or value.get("candidate_identity_status") != "FINAL":
        raise AdapterError("model experiment identity is not finalized")
    finalized = value.get("candidate_spec")
    effective = finalized.get("effective_model") if isinstance(finalized, dict) else None
    if not effective or str(effective).upper() == "UNSET":
        raise AdapterError("model experiment has no finalized effective model identity")
    result = dict(candidate_spec)
    result.update(finalized)
    return result
def verify_envelope_sources(envelope_path: Path, envelope: dict[str, Any]) -> tuple[dict[str, Path], list[dict[str, str]]]:
    raw = envelope.get("sources")
    if not isinstance(raw, list) or not raw:
        raise AdapterError("machine evidence sources are missing")
    sources: dict[str, Path] = {}
    descriptors: list[dict[str, str]] = []
    root = envelope_path.parent.resolve()
    for item in raw:
        if not isinstance(item, dict) or not isinstance(item.get("role"), str) or item["role"] in sources:
            raise AdapterError("machine evidence sources contain duplicate or invalid roles")
        relative = Path(str(item.get("path", "")))
        if relative.is_absolute() or ".." in relative.parts:
            raise AdapterError("machine evidence source path escapes evidence root")
        path = root / relative
        try:
            path.resolve().relative_to(root)
        except ValueError as exc:
            raise AdapterError("machine evidence source path escapes evidence root") from exc
        expected = str(item.get("sha256", "")).lower()
        actual = _hash_file(path)
        if actual != expected:
            raise AdapterError(f"source hash mismatch for {item['role']}")
        sources[str(item["role"])] = path
        descriptors.append({"role": str(item["role"]), "path": relative.as_posix(), "sha256": actual})
    return sources, sorted(descriptors, key=lambda item: item["role"])


def build_machine_evidence(output: Path, *, evidence_type: str, subject_git_sha: str, deployment_fingerprint: str, sources: dict[str, Path], root: Path | None = None, generated_at: str | None = None, candidate_spec: dict[str, Any] | None = None) -> Path:
    from .certification import EVIDENCE_SCHEMA_VERSION, _require_hex, candidate_deployment_fingerprint, canonical_candidate_factors
    from datetime import datetime, timezone

    output = output.expanduser()
    candidate_factors = None
    if candidate_spec is not None:
        candidate_spec = _finalize_candidate_spec(candidate_spec, evidence_type=evidence_type, sources=sources)
        if root is not None:
            try:
                from .model_policy import ModelPolicy
                policy = ModelPolicy.from_mapping(candidate_spec.get("model_policy")) if isinstance(candidate_spec.get("model_policy"), dict) else None
                resolved = resolve_candidate_spec(candidate_spec, root=root, subject_git_sha=subject_git_sha, model_policy=policy, corpus=candidate_spec.get("corpus_identity"), require_sources=True)
            except (EvidenceValidationError, OSError, ValueError, TypeError) as exc:
                raise AdapterError(f"candidate execution inputs could not be verified: {exc}") from exc
            if canonical_candidate_factors(resolved) != canonical_candidate_factors(candidate_spec):
                raise AdapterError("candidate specification is not the finalized executable candidate")
        candidate_factors = canonical_candidate_factors(candidate_spec)
        expected = candidate_deployment_fingerprint(candidate_spec)
        if expected != deployment_fingerprint:
            raise AdapterError("candidate specification does not match deployment fingerprint")
        if candidate_spec.get("subject_git_sha") != subject_git_sha:
            raise AdapterError("candidate specification does not match subject SHA")
        _verify_candidate_execution_provenance(candidate_spec, evidence_type=evidence_type, sources=sources)
    _check_embedded_identity(sources, subject_git_sha=subject_git_sha, deployment_fingerprint=deployment_fingerprint)
    descriptors = _source_descriptors(sources, output)
    payload = derive_payload(evidence_type, sources, root=root, candidate_spec=candidate_spec)
    envelope = {"schema_version": EVIDENCE_SCHEMA_VERSION, "evidence_type": evidence_type, "status": "PASS", "subject_git_sha": subject_git_sha, "deployment_fingerprint": _require_hex(deployment_fingerprint, "deployment_fingerprint"), "generated_at": generated_at or datetime.now(timezone.utc).isoformat(), "adapter_version": ADAPTER_VERSION, "sources": descriptors, "payload": payload}
    if candidate_factors is not None:
        envelope["candidate_spec"] = candidate_factors
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(envelope, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    # Fail closed if the generated envelope cannot immediately be revalidated.
    verify_machine_envelope(output, envelope, subject_git_sha=subject_git_sha, deployment_fingerprint=deployment_fingerprint, root=root)
    return output


def verify_machine_envelope(path: Path, envelope: dict[str, Any], *, subject_git_sha: str | None, deployment_fingerprint: str | None, root: Path | None = None, candidate_spec: dict[str, Any] | None = None) -> dict[str, Any]:
    from .certification import candidate_deployment_fingerprint

    evidence_type = str(envelope.get("evidence_type"))
    if envelope.get("adapter_version") != ADAPTER_VERSION:
        raise AdapterError("unsupported machine evidence adapter version")
    sources, descriptors = verify_envelope_sources(path, envelope)
    if subject_git_sha and envelope.get("subject_git_sha") != subject_git_sha:
        raise AdapterError("machine evidence subject does not match candidate")
    if deployment_fingerprint and envelope.get("deployment_fingerprint") != deployment_fingerprint:
        raise AdapterError("machine evidence deployment does not match candidate")
    candidate_spec = envelope.get("candidate_spec")
    if candidate_spec is not None:
        if not isinstance(candidate_spec, dict) or candidate_deployment_fingerprint(candidate_spec) != envelope.get("deployment_fingerprint"):
            raise AdapterError("machine evidence candidate specification is inconsistent")
        _verify_candidate_execution_provenance(candidate_spec, evidence_type=evidence_type, sources=sources)
    _check_embedded_identity(sources, subject_git_sha=subject_git_sha, deployment_fingerprint=deployment_fingerprint)
    derived = derive_payload(evidence_type, sources, root=root, candidate_spec=candidate_spec)
    if envelope.get("payload") != derived:
        raise AdapterError("machine evidence payload does not match derived source result")
    return {"sources": descriptors, "payload": derived}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Derive K-Slide machine evidence from runner results")
    parser.add_argument("evidence_type", choices=sorted(_DERIVERS))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--subject-sha")
    parser.add_argument("--deployment-fingerprint")
    parser.add_argument("--root", type=Path)
    parser.add_argument("--candidate-profile", type=Path, required=True, help="Explicit candidate deployment specification")
    parser.add_argument("--source", action="append", required=True, metavar="ROLE=PATH")
    args = parser.parse_args(argv)
    sources: dict[str, Path] = {}
    try:
        for item in args.source:
            role, separator, raw = item.partition("=")
            if not separator or not role or not raw or role in sources:
                raise AdapterError("--source must be unique ROLE=PATH entries")
            sources[role] = Path(raw)
        from .certification import load_candidate_spec, resolve_candidate_spec

        candidate_root = args.root or args.candidate_profile.expanduser().resolve().parent
        candidate = load_candidate_spec(args.candidate_profile, root=candidate_root, require_identity=True)
        subject = args.subject_sha or str(candidate.get("subject_git_sha"))
        candidate = resolve_candidate_spec(candidate, root=candidate_root, subject_git_sha=subject, require_sources=True)
        candidate = _finalize_candidate_spec(candidate, evidence_type=args.evidence_type, sources=sources)
        deployment = args.deployment_fingerprint or candidate_deployment_fingerprint(candidate)
        # The candidate root is also the execution/source root when callers do
        # not pass a separate root. This keeps the CLI certification path
        # source-verifying instead of degrading to a profile-only fingerprint.
        build_machine_evidence(args.output, evidence_type=args.evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, sources=sources, root=candidate_root, candidate_spec=candidate)
    except (AdapterError, OSError, ValueError) as exc:
        print(json.dumps({"status": "BLOCKED", "reason": str(exc)}, ensure_ascii=False))
        return 2
    print(json.dumps({"status": "PASS", "evidence": str(args.output), "evidence_type": args.evidence_type}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
