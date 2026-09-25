"""Type-specific, result-derived certification evidence adapters.

Machine evidence is deliberately produced from runner output rather than from
an administrator-authored metrics dictionary.  The adapters are small,
strict, and source-free: they return only the aggregate facts needed by the
release gate while retaining hashes for every underlying result file.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from pathlib import Path
from typing import Any, Callable

from .certification import (
    EvidenceValidationError,
    candidate_deployment_fingerprint,
    canonical_dependency_inventory,
    canonical_package_name,
    cyclonedx_dependency_set_hash,
    dependency_inventory_hash,
    explicit_unavailable_value,
    load_dependency_lock,
    load_dependency_inventory,
    resolve_candidate_spec,
    NOT_APPLICABLE_VALUE,
    NOT_EXPOSED_VALUE,
    _NON_DEPLOYED_BASE_PACKAGES,
    sha256_file,
    safe_path_under,
    safe_relative_path,
    validate_ocr_asset_manifest,
)
from .model_policy import load_model_policy
from .quality_policy import (
    QUALITY_FLOORS,
    QUALITY_POLICY_IDENTITY,
    deterministic_mean,
    make_hard_gate_finding,
    policy_identity_record,
    validate_policy_identity,
)
from evals.model_results import certification_matrix_metadata, derive_stability_groups, persisted_false_done
from .corpus_governance import (
    CorpusGovernanceError,
    is_certification_corpus_ready,
    canonical_manifest,
    manifest_identity,
    require_set_purpose,
    set_identity_for_role,
    validate_contamination_report,
    canonical_bytes,
    sha256_bytes,
    validate_corpus_bundle,
)

# 2.9 adds the candidate-bound KSA-33 security release contract to the
# existing security adapter; earlier derivation behavior remains unchanged.
# 2.8 binds model result derivation to the current closed KSA-27 quality policy.
# 2.7 binds model evidence to the candidate's four governed corpus identities
# and re-derives the source-free corpus membership/contamination contract.
# 2.6 retains and re-derives the exact PaddleX configuration selected by the
# heavy OCR runtime. 2.5 retains and re-derives the heavy image dependency and
# OCR asset subjects alongside the portable security evidence bundle. 2.3 binds the resolved production lock
# and standards-valid SBOM. 2.2 added candidate-bound multimodal and
# production dependency proof to the
# candidate-bound identity/provenance contract introduced in 2.1.
# separation and exact frozen scenario matrices. No production-certified v1
# or 2.0 evidence exists, so ambiguous development envelopes are not migrated.
ADAPTER_VERSION = "2.9"

_ROLES: dict[str, tuple[str, ...]] = {
    "runtime": ("diagnostic_ladder", "simple_run", "three_slide", "five_slide"),
    "heavy_runtime": ("required_doctor", "networkless_doctor", "representative_engine", "production_inventory", "production_lock", "built_image_inventory", "dependency_context"),
    "model_validation": ("model_summary", "experiment_manifest", "results_jsonl"),
    "model_high_risk_stability": ("model_summary", "experiment_manifest", "results_jsonl"),
    "model_held_out": ("model_summary", "experiment_manifest", "results_jsonl"),
    "security": ("pip_audit", "gitleaks", "semgrep", "scanner_exits", "audit_context", "semgrep_ruleset", "dependency_inventory", "production_lock", "production_sbom", "container_scan", "security_release_context", "release_security_policy", "vulnerability_dispositions", "release_egress_policy"),
    "reliability": ("failure_injection", "concurrency", "large_deck", "performance_slo"),
    "governance": (
        "repository_metadata", "target_branch", "ruleset_collection", "ruleset_details",
        "legacy_branch_protection", "pull_request", "pull_request_reviews",
        "pull_request_check_runs", "workflow_run_provenance", "head_commit_pull_requests",
        "pull_request_files", "merge_commit",
        "candidate_codeowners", "candidate_governance_policy",
    ),
}

_SECURITY_SCANNER_ROLES = ("pip_audit", "gitleaks", "semgrep", "scanner_exits")
_SCANNER_EXIT_KEYS = ("pip_audit", "gitleaks", "semgrep")


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
        if isinstance(value, dict) and value.get("schema_version") not in (None, "1.0", "2.0", "2.1", "2.2", "2.3"):
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


def enforce_security_scanners(sources: dict[str, Path], *, allow_disposition_review: bool = False) -> dict[str, Any]:
    """Enforce scanner execution/results independently of candidate eligibility.

    This is intentionally separate from ``_derive_security``: an incomplete
    public candidate may be ``NOT_CERTIFYING``, but it must never turn a dirty
    or failed scanner run into a successful workflow.
    """

    values, _ = source_records(sources, expected=_SECURITY_SCANNER_ROLES)
    pip = _read_json(values["pip_audit"])
    leaks = _read_json(values["gitleaks"])
    semgrep = _read_json(values["semgrep"])
    exits = _read_json(values["scanner_exits"])
    if not isinstance(pip, dict) or not isinstance(pip.get("dependencies"), list) or not pip["dependencies"]:
        raise AdapterError("pip-audit output is missing or has an empty dependency set")
    for item in pip["dependencies"]:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not item["name"] or not isinstance(item.get("version"), str) or not item["version"] or "vulns" not in item or not isinstance(item["vulns"], list):
            raise AdapterError("pip-audit output is malformed")
    if not isinstance(leaks, list):
        raise AdapterError("gitleaks output is malformed")
    if not isinstance(semgrep, dict) or not isinstance(semgrep.get("results"), list) or not isinstance(semgrep.get("errors"), list):
        raise AdapterError("Semgrep output is malformed")
    if not isinstance(exits, dict) or set(exits) != set(_SCANNER_EXIT_KEYS):
        raise AdapterError("scanner exit-code evidence is missing or malformed")
    if any(isinstance(exits.get(name), bool) or not isinstance(exits.get(name), int) for name in _SCANNER_EXIT_KEYS):
        raise AdapterError("scanner exit-code evidence is malformed")
    if any(exits[name] != 0 for name in _SCANNER_EXIT_KEYS if name != "pip_audit"):
        raise AdapterError("one or more security scanners failed to execute cleanly")
    vulnerability_count = sum(len(item["vulns"]) for item in pip["dependencies"])
    if exits["pip_audit"] not in ({0, 1} if vulnerability_count else {0}):
        raise AdapterError("pip-audit did not complete with an explainable result")
    if vulnerability_count and not allow_disposition_review:
        raise AdapterError("production dependency vulnerabilities were found")
    if leaks:
        raise AdapterError("secret findings were found")
    if semgrep["errors"]:
        raise AdapterError("Semgrep reported scan errors")
    if semgrep["results"]:
        raise AdapterError("Semgrep findings were found")
    return {
        "dependency_count": len(pip["dependencies"]),
        "vulnerability_count": vulnerability_count,
        "secret_count": len(leaks),
        "semgrep_finding_count": len(semgrep["results"]),
        "scanner_exit_codes": {name: exits[name] for name in sorted(_SCANNER_EXIT_KEYS)},
    }


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


def _quality_rate(value: Any, label: str) -> float:
    number = _number(value, label)
    if not math.isfinite(number) or not 0.0 <= number <= 1.0:
        raise AdapterError(f"{label} must be a finite rate in [0, 1]")
    return number


def _nonnegative_int(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise AdapterError(f"{label} must be a non-negative integer")
    return value


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


def _derive_heavy(sources: dict[str, Path], *, root: Path | None = None, candidate_spec: dict[str, Any] | None = None) -> dict[str, Any]:
    expected = _ROLES["heavy_runtime"] + (("full_engine",) if "full_engine" in sources else ())
    asset_roles = ("ocr_asset_manifest", "ocr_asset_context")
    if candidate_spec is not None and candidate_spec.get("ocr_provider") == "paddle":
        expected += asset_roles
    values, _ = source_records(sources, expected=expected)
    _doctor_pass(_read_json(values["required_doctor"]))
    _doctor_pass(_read_json(values["networkless_doctor"]), networkless=True)
    _engine_pass(_read_json(values["representative_engine"]), "representative_engine")
    full = "full_engine" in values
    if full:
        _engine_pass(_read_json(values["full_engine"]), "full_engine")
    inventory = load_dependency_inventory(values["production_inventory"])
    lock_inventory = load_dependency_lock(values["production_lock"])
    built_inventory = load_dependency_inventory(values["built_image_inventory"])
    context = _read_json(values["dependency_context"])
    if not isinstance(context, dict):
        raise AdapterError("heavy dependency context is malformed")
    inventory_hash = dependency_inventory_hash(inventory)
    lock_hash = sha256_file(values["production_lock"])
    if lock_inventory != inventory:
        raise AdapterError("heavy production lock does not equal the frozen production inventory")
    if built_inventory != inventory:
        raise AdapterError("heavy image dependency inventory does not equal the frozen production inventory")
    required_hashes = {
        "expected_dependency_set_sha256": inventory_hash,
        "frozen_dependency_set_sha256": inventory_hash,
        "built_image_dependency_set_sha256": inventory_hash,
        "production_lock_sha256": lock_hash,
    }
    for key, expected in required_hashes.items():
        if str(context.get(key) or "").lower() != expected:
            raise AdapterError(f"heavy dependency context {key} does not match retained sources")
    if str(context.get("dependency_subject") or "") != "production-env":
        raise AdapterError("heavy dependency context does not identify the production subject")
    if candidate_spec is not None:
        if context.get("subject_git_sha") != candidate_spec.get("subject_git_sha"):
            raise AdapterError("heavy dependency context subject does not match candidate")
        context_deployment = context.get("deployment_fingerprint")
        if context_deployment != candidate_deployment_fingerprint(candidate_spec):
            raise AdapterError("heavy dependency context deployment does not match candidate")
        expected_candidate = str(candidate_spec.get("resolved_dependency_set_sha256") or "").lower()
        if expected_candidate != inventory_hash:
            raise AdapterError("heavy dependency identity does not match candidate")
        if candidate_spec.get("ocr_provider") == "paddle":
            expected_asset_hash = str(candidate_spec.get("ocr_asset_manifest_sha256") or "").lower()
            if len(expected_asset_hash) != 64:
                raise AdapterError("heavy evidence has no candidate OCR asset identity")
            try:
                asset_identity = validate_ocr_asset_manifest(values["ocr_asset_manifest"], expected_sha256=expected_asset_hash, verify_files=False)
            except EvidenceValidationError as exc:
                raise AdapterError(f"heavy OCR asset manifest is invalid ({type(exc).__name__})") from exc
            asset_context = _read_json(values["ocr_asset_context"])
            if not isinstance(asset_context, dict) or asset_context.get("status") != "PASS" or asset_context.get("runtime_verified") is not True or asset_context.get("after_engine") is not True:
                raise AdapterError("heavy OCR asset runtime proof is missing")
            if str(asset_context.get("manifest_sha256") or "").lower() != asset_identity["sha256"] or str(asset_context.get("manifest_sha256") or "").lower() != expected_asset_hash:
                raise AdapterError("heavy OCR asset runtime identity does not match the candidate")
            if asset_context.get("files") != asset_identity.get("entries"):
                raise AdapterError("heavy OCR runtime asset file inventory does not match the candidate manifest")
            if asset_context.get("paddlex_config") != asset_identity.get("paddlex_config") or str(asset_context.get("paddlex_config_sha256") or "").lower() != asset_identity.get("paddlex_config_sha256"):
                raise AdapterError("heavy OCR runtime selected configuration does not match the candidate manifest")
            if asset_context.get("offline_assets_required") is not True:
                raise AdapterError("heavy OCR runtime did not prove offline local assets were required")
    return {
        "heavy_pass": True,
        "networkless_pass": True,
        "representative_engine_pass": True,
        "full_engine_pass": full,
        "unexpected_capability_blocks": 0,
        "dependency_subject": "production-env",
        "resolved_dependency_set_sha256": inventory_hash,
        "resolved_dependency_lock_sha256": lock_hash,
        "built_image_dependency_set_sha256": inventory_hash,
        **({"ocr_asset_manifest_sha256": str(candidate_spec.get("ocr_asset_manifest_sha256")).lower()} if candidate_spec is not None and candidate_spec.get("ocr_provider") == "paddle" else {}),
        **({"ocr_paddlex_config": asset_identity["paddlex_config"], "ocr_paddlex_config_sha256": asset_identity["paddlex_config_sha256"], "ocr_offline_assets_required": True} if candidate_spec is not None and candidate_spec.get("ocr_provider") == "paddle" else {}),
    }


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
    set_identity = experiment.get("corpus_set_identity")
    if isinstance(set_identity, dict) and set_identity.get("role") != "public_synthetic_regression":
        return _governed_model_matrix(
            experiment,
            rows,
            expected_split=expected_split,
            require_full_split=require_full_split,
            scenario_ids=scenario_ids,
            formats=formats,
            repetitions=repetitions,
        )
    try:
        from evals.scenarios import scenario_specs
        from evals.noncritical_semantics import public_assertion_ids_by_scenario
    except ImportError as exc:
        raise AdapterError("model matrix requires the frozen scenario manifest") from exc
    frozen = {item.scenario_id: item for item in scenario_specs()}
    public_assertions = public_assertion_ids_by_scenario()
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
        expected_assertion_ids = public_assertions.get(scenario_id, [])
        semantic = row.get("semantic") if isinstance(row.get("semantic"), dict) else {}
        if semantic.get("noncritical_semantic_assertion_ids") != expected_assertion_ids:
            raise AdapterError("public result assertion IDs do not match the repository-controlled scenario gold")
    missing = sorted(declared - observed)
    extra = sorted(observed - declared)
    if missing or extra:
        raise AdapterError(f"model result matrix mismatch; missing={missing[:3]}; extra={extra[:3]}")
    return {"scenario_ids": sorted(scenario_ids), "formats": formats, "repetitions": repetitions, "case_count": len(rows), "matrix_hash": _sha256_text(experiment.get("experiment_plan_hash"), "experiment_plan_hash"), **certification_matrix_metadata(declared)}


def _governed_model_matrix(experiment: dict[str, Any], rows: list[dict[str, Any]], *, expected_split: str, require_full_split: bool, scenario_ids: list[str], formats: list[str], repetitions: int) -> dict[str, Any]:
    """Re-derive governed membership and result metadata without public scenarios."""

    try:
        from evals.governed_corpus import case_matrix_fingerprint, case_matrix_item_fingerprint
        from .corpus_governance import canonical_manifest, manifest_identity

        source_manifest = canonical_manifest(experiment.get("corpus_manifest"))
        consumed = manifest_identity(source_manifest)
    except (ImportError, CorpusGovernanceError, TypeError, ValueError) as exc:
        raise AdapterError("governed model case matrix has no valid source manifest") from exc
    if consumed != experiment.get("corpus_set_identity"):
        raise AdapterError("governed case manifest disagrees with consumed set identity")
    case_matrix = experiment.get("case_matrix")
    matrix_hash = experiment.get("case_matrix_sha256")
    if not isinstance(case_matrix, list) or not case_matrix or not isinstance(matrix_hash, str) or case_matrix_fingerprint(case_matrix) != matrix_hash:
        raise AdapterError("governed model case matrix is missing or its hash is invalid")
    descriptor_identity = experiment.get("case_descriptor_identity")
    expected_descriptor = {
        "schema_version": "1.0",
        "role": consumed["role"],
        "set_id": consumed["set_id"],
        "version": consumed["version"],
        "manifest_fingerprint": consumed["manifest_fingerprint"],
        "case_matrix_sha256": matrix_hash,
    }
    if descriptor_identity != expected_descriptor:
        raise AdapterError("governed case descriptor identity disagrees with its manifest or matrix")
    members = {item["item_id"]: item for item in source_manifest["items"] if item["state"] == "active"}
    matrix_items: dict[str, dict[str, Any]] = {}
    try:
        bundle_manifests = [canonical_manifest(item) for item in experiment.get("governed_corpus_manifests", [])]
        public_manifest = next(item for item in bundle_manifests if item["role"] == "public_synthetic_regression")
    except (CorpusGovernanceError, StopIteration, TypeError) as exc:
        raise AdapterError("governed case matrix lacks the candidate-bound public regression manifest") from exc
    public_ids = {item["item_id"] for item in public_manifest["items"]}
    public_gold_hashes = {item["gold_sha256"] for item in public_manifest["items"]}
    allowed_fields = {"item_id", "category", "protected_group", "split", "source_sha256", "gold_sha256", "gold_contract_sha256", "noncritical_semantic_assertion_ids", "formats"}
    for item in case_matrix:
        if not isinstance(item, dict) or set(item) != allowed_fields:
            raise AdapterError("governed case matrix item has an unsupported shape")
        item_id = item.get("item_id")
        if not isinstance(item_id, str) or not item_id or item_id in matrix_items or item_id not in members:
            raise AdapterError("governed case matrix contains duplicate or inactive membership")
        member = members[item_id]
        if (item.get("source_sha256"), item.get("gold_sha256")) != (member["source_sha256"], member["gold_sha256"]):
            raise AdapterError("governed case matrix identity does not match its manifest item")
        if item_id in public_ids or item.get("gold_contract_sha256") in public_gold_hashes:
            raise AdapterError("governed case metadata reuses a public synthetic item or gold contract")
        if not isinstance(item.get("gold_contract_sha256"), str) or len(item["gold_contract_sha256"]) != 64 or set(item["gold_contract_sha256"]) - set("0123456789abcdef"):
            raise AdapterError("governed case gold contract identity is malformed")
        assertion_ids = item.get("noncritical_semantic_assertion_ids")
        if not isinstance(assertion_ids, list) or any(not isinstance(value, str) or not re.fullmatch(r"ncs-[0-9a-f]{24}", value) for value in assertion_ids) or assertion_ids != sorted(set(assertion_ids)):
            raise AdapterError("governed case non-critical semantic assertion IDs are malformed")
        if item.get("split") != expected_split:
            raise AdapterError("governed case matrix split disagrees with its role contract")
        try:
            from evals.certification import CATEGORY_POLICY
        except ImportError as exc:
            raise AdapterError("governed case matrix requires the closed semantic policy") from exc
        if not isinstance(item.get("category"), str) or item.get("category") not in CATEGORY_POLICY:
            raise AdapterError("governed case matrix category is missing")
        case_formats = item.get("formats")
        if not isinstance(case_formats, list) or not case_formats or any(not isinstance(value, str) for value in case_formats) or case_formats != sorted(set(case_formats)) or not set(formats) <= set(case_formats):
            raise AdapterError("governed case matrix format coverage is incomplete")
        protected_group = item.get("protected_group")
        if protected_group is not None and (not isinstance(protected_group, str) or protected_group not in CATEGORY_POLICY):
            raise AdapterError("governed case matrix protected group is outside the closed semantic policy")
        matrix_items[item_id] = item
    active_ids = set(members)
    matrix_ids = set(matrix_items)
    if matrix_ids != active_ids or set(scenario_ids) != matrix_ids:
        raise AdapterError("governed experiment membership differs from exact active manifest membership")
    if require_full_split and set(scenario_ids) != active_ids:
        raise AdapterError("authoritative governed evidence must use every active item")
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
            raise AdapterError("model result row split disagrees with governed case matrix")
        matrix_item = matrix_items.get(scenario_id)
        if matrix_item is None or row.get("category") != matrix_item["category"]:
            raise AdapterError("model result category does not match governed case metadata")
        semantic = row.get("semantic") if isinstance(row.get("semantic"), dict) else {}
        if semantic.get("noncritical_semantic_assertion_ids") != matrix_item["noncritical_semantic_assertion_ids"]:
            raise AdapterError("model result assertion IDs do not match the hash-bound governed gold contract")
        if row.get("case_identity_sha256") != case_matrix_item_fingerprint(matrix_item):
            raise AdapterError("model result case identity does not match governed case metadata")
    missing = sorted(declared - observed)
    extra = sorted(observed - declared)
    if missing or extra:
        raise AdapterError(f"model result matrix mismatch; missing={missing[:3]}; extra={extra[:3]}")
    return {"scenario_ids": sorted(scenario_ids), "formats": formats, "repetitions": repetitions, "case_count": len(rows), "matrix_hash": _sha256_text(experiment.get("experiment_plan_hash"), "experiment_plan_hash"), **certification_matrix_metadata(declared)}


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


def _string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise AdapterError(f"{label} must be a list of non-empty strings")
    if len(value) != len(set(value)):
        raise AdapterError(f"{label} contains duplicate values")
    return value


def _rederive_noncritical_observations(semantic: dict[str, Any], *, label: str, work_unit_id: str, verify_anchor: bool = True) -> tuple[list[dict[str, str]], int, int]:
    observations = semantic.get("noncritical_semantic_observations")
    if not isinstance(observations, list):
        raise AdapterError(f"{label} is missing non-critical semantic observations")
    ids: list[str] = []
    normalized: list[dict[str, str]] = []
    required = correct = 0
    for item in observations:
        if not isinstance(item, dict) or set(item) != {"assertion_id", "source_object_id", "anchor_kind", "anchor_sha256", "outcome"}:
            raise AdapterError(f"{label} has an unknown non-critical semantic observation shape")
        assertion_id = item.get("assertion_id")
        source_object_id = item.get("source_object_id")
        anchor_kind = item.get("anchor_kind")
        anchor_sha256 = item.get("anchor_sha256")
        outcome = item.get("outcome")
        if not isinstance(assertion_id, str) or not re.fullmatch(r"ncs-[0-9a-f]{24}", assertion_id):
            raise AdapterError(f"{label} has a malformed non-critical semantic assertion ID")
        if not isinstance(source_object_id, str) or not source_object_id or anchor_kind not in {"region", "table_cell", "visual_element"}:
            raise AdapterError(f"{label} has a malformed non-critical semantic source anchor")
        if not isinstance(anchor_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", anchor_sha256):
            raise AdapterError(f"{label} has a malformed non-critical semantic anchor digest")
        expected_anchor = hashlib.sha256(f"{work_unit_id}\0{anchor_kind}\0{source_object_id}".encode("utf-8")).hexdigest()
        if verify_anchor and anchor_sha256 != expected_anchor:
            raise AdapterError(f"{label} non-critical semantic anchor digest disagrees with its source identity")
        if outcome not in {"CORRECT", "INCORRECT", "UNRESOLVED_EXEMPT"}:
            raise AdapterError(f"{label} has an unknown non-critical semantic outcome")
        ids.append(assertion_id)
        normalized.append({
            "assertion_id": assertion_id,
            "source_object_id": source_object_id,
            "anchor_kind": anchor_kind,
            "anchor_sha256": anchor_sha256,
            "outcome": outcome,
        })
        if outcome != "UNRESOLVED_EXEMPT":
            required += 1
            correct += int(outcome == "CORRECT")
    if len(ids) != len(set(ids)):
        raise AdapterError(f"{label} duplicates a non-critical semantic assertion ID")
    if _nonnegative_int(semantic.get("noncritical_semantic_required_count"), f"{label} required count") != required:
        raise AdapterError(f"{label} non-critical semantic required count disagrees with observations")
    if _nonnegative_int(semantic.get("noncritical_semantic_correct_count"), f"{label} correct count") != correct:
        raise AdapterError(f"{label} non-critical semantic correct count disagrees with observations")
    rate = correct / required if required else 1.0
    if abs(_quality_rate(semantic.get("noncritical_semantic_equivalence"), f"{label} equivalence") - rate) > 1e-12:
        raise AdapterError(f"{label} non-critical semantic rate disagrees with observations")
    return normalized, required, correct


def _rederive_unit_semantics(unit_semantic: dict[str, Any], *, work_unit_id: str) -> tuple[set[str], float, set[str], set[str], set[str], list[dict[str, str]], int, int]:
    """Rebuild scorer-critical codes and unresolved observations from persisted facts."""

    evidence = unit_semantic.get("hard_gate_evidence")
    if not isinstance(evidence, dict):
        raise AdapterError("current model result is missing source-local hard-gate evidence")
    missing_regions = set(_string_list(evidence.get("missing_required_region_ids"), "missing required region IDs"))
    numeric_mismatches = set(_string_list(evidence.get("numeric_mismatch_fact_ids"), "numeric mismatch fact IDs"))
    exec_codes = set(_string_list(evidence.get("executive_claim_failure_codes"), "executive claim failure codes"))
    duplicate_regions = set(_string_list(evidence.get("duplicate_region_ids"), "duplicate region IDs"))
    table_failures = set(_string_list(evidence.get("table_failure_codes"), "table failure codes"))
    header_failure_ids = set(_string_list(evidence.get("table_header_failure_ids"), "table header failure IDs"))
    chart_codes = set(_string_list(evidence.get("chart_failure_codes"), "chart failure codes"))
    process_codes = set(_string_list(evidence.get("process_failure_codes"), "process failure codes"))
    required_unresolved = set(_string_list(evidence.get("material_unresolved_required_ids"), "material unresolved source IDs"))
    evidence_observed_material = set(_string_list(evidence.get("material_unresolved_observed_ids"), "observed material unresolved source IDs"))
    unresolved_ids = set(_string_list(unit_semantic.get("unresolved_ids"), "unresolved source IDs"))
    if not evidence_observed_material <= unresolved_ids:
        raise AdapterError("material unresolved observations are not source-bound")
    observed_material = required_unresolved & unresolved_ids
    if observed_material != evidence_observed_material:
        raise AdapterError("material unresolved observations disagree with source-local unresolved IDs")
    modality = _quality_rate(evidence.get("modality_score"), "hard_gate_evidence.modality_score")
    hangul_count = evidence.get("hangul_violation_count")
    unsupported_count = evidence.get("unsupported_claim_count")
    if not isinstance(hangul_count, int) or isinstance(hangul_count, bool) or hangul_count < 0:
        raise AdapterError("Hangul violation count is invalid")
    if not isinstance(unsupported_count, int) or isinstance(unsupported_count, bool) or unsupported_count < 0:
        raise AdapterError("unsupported claim count is invalid")
    if not isinstance(evidence.get("modality_source_binding_failure"), bool) or not isinstance(evidence.get("noncritical_semantic_source_binding_failure"), bool) or not isinstance(evidence.get("table_cardinality_mismatch"), bool):
        raise AdapterError("source-local binding/table structure facts are invalid")

    expected_critical: set[str] = set(exec_codes) | chart_codes | process_codes
    if missing_regions:
        expected_critical.add("SILENT_REGION_OMISSION")
    if numeric_mismatches:
        expected_critical.add("CRITICAL_NUMERIC_MISMATCH")
    if modality < 1.0:
        expected_critical.add("CRITICAL_MODALITY_MISMATCH")
    if evidence["modality_source_binding_failure"] or evidence["noncritical_semantic_source_binding_failure"] or duplicate_regions:
        expected_critical.add("SCORER_SOURCE_BINDING_FAILURE")
    if hangul_count:
        expected_critical.add("UNEXPECTED_HANGUL")
    if unsupported_count:
        expected_critical.add("UNSUPPORTED_EXECUTIVE_CLAIM")
    if table_failures:
        expected_critical.add("TABLE_CELL_SEMANTIC_FAILURE")
    if evidence["table_cardinality_mismatch"]:
        expected_critical.add("TABLE_CARDINALITY_MISMATCH")
    if header_failure_ids:
        expected_critical.add("TABLE_HEADER_SEMANTIC_FAILURE")
    if process_codes:
        expected_critical.add("VISUAL_RELATION_OMISSION")
    if required_unresolved - observed_material:
        expected_critical.add("MATERIAL_UNRESOLVED_MISSED")
    stored_critical = set(_string_list(unit_semantic.get("critical_failures"), "semantic critical failures"))
    if stored_critical != expected_critical:
        raise AdapterError("semantic critical failure codes disagree with source-local scorer facts")

    # Each canonical source-local failure remains a finding. More specific
    # table membership failures are retained alongside the public scorer code.
    finding_codes = set(expected_critical) | table_failures
    metrics = ("coverage", "numeric_fidelity", "modality", "table_cell_fidelity", "visual_relation_recall")
    values = [_quality_rate(unit_semantic.get(name), f"semantic.{name}") for name in metrics]
    fidelity = min(values)
    if abs(_quality_rate(unit_semantic.get("critical_axis_minimum_diagnostic"), "semantic.critical_axis_minimum_diagnostic") - fidelity) > 1e-12:
        raise AdapterError("critical-axis diagnostic is not rederived from scorer metrics")
    noncritical_observations, noncritical_required, noncritical_correct = _rederive_noncritical_observations(
        unit_semantic, label="unit semantic", work_unit_id=work_unit_id,
    )
    for observation in noncritical_observations:
        if observation["outcome"] == "UNRESOLVED_EXEMPT" and (
            observation["source_object_id"] not in required_unresolved
            or observation["source_object_id"] not in unresolved_ids
        ):
            raise AdapterError("non-critical semantic unresolved exemption is not bound to an observed material unresolved source")
        if observation["outcome"] == "CORRECT" and observation["source_object_id"] in unresolved_ids:
            raise AdapterError("unresolved source output cannot satisfy a non-critical semantic assertion")
    false_negative = required_unresolved - unresolved_ids
    false_positive = unresolved_ids - required_unresolved
    if set(_string_list(unit_semantic.get("material_unresolved_false_negative_ids"), "material unresolved false negatives")) != false_negative:
        raise AdapterError("material unresolved false-negative set disagrees with scorer facts")
    if set(_string_list(unit_semantic.get("unresolved_false_positive_ids"), "unresolved false positives")) != false_positive:
        raise AdapterError("unresolved false-positive set disagrees with scorer facts")
    for field, derived in (
        ("unresolved_count", len(unresolved_ids)),
        ("material_unresolved_required_ids", sorted(required_unresolved)),
        ("material_unresolved_observed_ids", sorted(observed_material)),
        ("material_unresolved_false_negative_ids", sorted(false_negative)),
        ("unresolved_false_positive_ids", sorted(false_positive)),
        ("material_unresolved_recall", len(observed_material) / len(required_unresolved) if required_unresolved else 1.0),
        ("unresolved_precision", len(observed_material) / len(unresolved_ids) if unresolved_ids else 1.0),
    ):
        value = unit_semantic.get(field)
        if isinstance(derived, list):
            if value != derived:
                raise AdapterError(f"unit semantic {field} disagrees with source-local unresolved observations")
        elif isinstance(derived, int):
            if _nonnegative_int(value, f"semantic.{field}") != derived:
                raise AdapterError(f"unit semantic {field} disagrees with source-local unresolved observations")
        elif abs(_quality_rate(value, f"semantic.{field}") - derived) > 1e-12:
            raise AdapterError(f"unit semantic {field} disagrees with source-local unresolved observations")
    return finding_codes, fidelity, required_unresolved, observed_material, false_positive, noncritical_observations, noncritical_required, noncritical_correct


def _derive_case_hard_gates(row: dict[str, Any], *, model_policy: Any) -> tuple[list[dict[str, str]], float, int, int, int, int, int, int]:
    """Independently rederive one persisted result row's gates and floors."""

    findings: dict[tuple[str, str, str], dict[str, str]] = {}

    def add(code: str, unit_id: str | None = None) -> None:
        finding = make_hard_gate_finding(code, work_unit_id=unit_id)
        findings[(finding["code"], finding.get("unknown_code_sha256", ""), finding.get("work_unit_id", ""))] = finding

    if row.get("quality_policy") != policy_identity_record() or row.get("quality_policy_identity") != QUALITY_POLICY_IDENTITY:
        raise AdapterError("model result row is missing the exact current quality-policy identity")
    if row.get("quality_metrics_authoritative") is True and row.get("semantic_scored") is not True:
        raise AdapterError("authoritative model result is missing semantic scoring")
    semantic = row.get("semantic") if isinstance(row.get("semantic"), dict) else {}
    units = row.get("units")
    if row.get("semantic_scored") is True and (not isinstance(units, list) or not units):
        raise AdapterError("authoritative model result is missing source-local unit scores")
    if not isinstance(units, list):
        units = []
    source_unit_ids: set[str] = set()
    case_codes: set[str] = set()
    fidelities: list[float] = []
    required_unresolved = 0
    true_positive = 0
    observed_unresolved = 0
    unnecessary_unresolved = 0
    noncritical_observations: list[dict[str, str]] = []
    noncritical_required = 0
    noncritical_correct = 0
    for unit in units:
        if not isinstance(unit, dict) or not isinstance(unit.get("work_unit_id"), str) or not unit.get("work_unit_id") or not isinstance(unit.get("semantic"), dict):
            raise AdapterError("model result unit score is malformed")
        unit_id = unit["work_unit_id"]
        if unit_id in source_unit_ids:
            raise AdapterError("model result contains duplicate work-unit ownership")
        source_unit_ids.add(unit_id)
        codes, fidelity, expected, observed, extra, observations, semantic_required, semantic_correct = _rederive_unit_semantics(unit["semantic"], work_unit_id=unit_id)
        case_codes.update(codes)
        fidelities.append(fidelity)
        required_unresolved += len(expected)
        true_positive += len(observed)
        observed_unresolved += len(_string_list(unit["semantic"].get("unresolved_ids"), "unresolved source IDs"))
        unnecessary_unresolved += len(extra)
        noncritical_observations.extend(observations)
        noncritical_required += semantic_required
        noncritical_correct += semantic_correct
        for code in codes:
            add(code, unit_id)

    semantic_codes = set(_string_list(semantic.get("critical_failures", []), "case critical failures"))
    derived_semantic_codes = set(case_codes)
    if int(semantic.get("inconsistent_alternate_count", 0) or 0) > 0:
        derived_semantic_codes.add("CROSS_SLIDE_TERM_INCONSISTENCY")
    if semantic_codes != derived_semantic_codes:
        raise AdapterError("case critical failure summary disagrees with source-local unit findings")
    for code in derived_semantic_codes - case_codes:
        add(code)

    case_fidelity = deterministic_mean(fidelities)
    if row.get("semantic_scored") is True:
        case_observations, case_required, case_correct = _rederive_noncritical_observations(
            semantic, label="case semantic", work_unit_id="", verify_anchor=False,
        )
        # Case observations repeat work-unit facts and are compared structurally;
        # their anchor digests were already rederived with each real work-unit ID.
        if case_observations != sorted(noncritical_observations, key=lambda item: item["assertion_id"]):
            raise AdapterError("case non-critical semantic observations disagree with work-unit scorer results")
        if (case_required, case_correct) != (noncritical_required, noncritical_correct):
            raise AdapterError("case non-critical semantic counts disagree with work-unit observations")
        expected_assertion_ids = _string_list(semantic.get("noncritical_semantic_assertion_ids"), "non-critical semantic expected assertion IDs")
        if any(not re.fullmatch(r"ncs-[0-9a-f]{24}", value) for value in expected_assertion_ids) or expected_assertion_ids != sorted(expected_assertion_ids):
            raise AdapterError("case non-critical semantic assertion membership is malformed")
        observed_assertion_ids = sorted(item["assertion_id"] for item in noncritical_observations)
        if expected_assertion_ids != observed_assertion_ids:
            raise AdapterError("case non-critical semantic assertion IDs were dropped, duplicated, or changed")
    elif noncritical_observations or noncritical_required or noncritical_correct:
        raise AdapterError("unscored model result contains non-critical semantic observations")

    opencode = row.get("opencode")
    if not isinstance(opencode, dict):
        raise AdapterError("model result is missing structured OpenCode facts")
    execution = row.get("persisted_execution")
    if not isinstance(execution, dict) or execution.get("available") is not True:
        if row.get("quality_metrics_authoritative") is True:
            raise AdapterError("authoritative result has no persisted execution/verification evidence")
        execution = execution if isinstance(execution, dict) else {}
    reported_complete = execution.get("reported_run_complete")
    run_complete = execution.get("run_complete")
    if execution.get("available") is True and (not isinstance(run_complete, bool) or not isinstance(reported_complete, bool)):
        raise AdapterError("persisted completion facts are incomplete")
    if execution.get("available") is True and reported_complete != run_complete:
        add("ENGINE_EVIDENCE_CONTRACT_FAILURE")
    if execution.get("available") is True and opencode.get("kslide_complete") is not reported_complete:
        raise AdapterError("OpenCode completion claim disagrees with persisted K-Slide completion")
    execution_required_count = _nonnegative_int(execution.get("material_unresolved_required_count", 0), "persisted material-unresolved count")
    if execution.get("available") is True:
        statuses = execution.get("work_unit_states")
        if not isinstance(statuses, dict) or any(not isinstance(key, str) or not key or not isinstance(value, str) for key, value in statuses.items()):
            raise AdapterError("persisted work-unit recovery states are malformed")
        expected_false_done = persisted_false_done(execution)
        if execution.get("false_done_recovery_violation") is not expected_false_done:
            raise AdapterError("persisted false-DONE finding disagrees with completion and recovery state")
        if expected_false_done:
            add("FALSE_DONE_WITH_MATERIAL_UNRESOLVED")
        verification_count = execution.get("verification_critical_count")
        if verification_count is not None and (not isinstance(verification_count, int) or isinstance(verification_count, bool) or verification_count < 0):
            raise AdapterError("persisted verification critical count is invalid")
        expected_verification_failure = execution.get("run_phase") == "COMPLETE" and (execution.get("verification_status") != "PASS" or verification_count != 0)
        if execution.get("verification_contract_failure") is not expected_verification_failure:
            raise AdapterError("persisted verification contract finding disagrees with verification evidence")
        if expected_verification_failure:
            add("ENGINE_EVIDENCE_CONTRACT_FAILURE")
    if execution_required_count:
        required_total = execution_required_count
        unresolved_conflicts = execution.get("unresolved_conflict_count", 0)
        if not isinstance(required_total, int) or isinstance(required_total, bool) or required_total < 0 or not isinstance(unresolved_conflicts, int) or isinstance(unresolved_conflicts, bool) or required_total != required_unresolved + unresolved_conflicts:
            raise AdapterError("persisted material-unresolved count is inconsistent")
        conflict_unresolved = unresolved_conflicts
        if run_complete is True:
            add("FALSE_DONE_WITH_MATERIAL_UNRESOLVED")
        elif execution.get("run_phase") == "NEEDS_REVIEW" and conflict_unresolved:
            true_positive += conflict_unresolved
            observed_unresolved += conflict_unresolved
            required_unresolved = required_total
        else:
            required_unresolved = required_total
    conflict_codes = _string_list(execution.get("conflict_failure_codes", []), "persisted conflict failure codes")
    conflict_count = execution.get("conflict_count", 0)
    unresolved_conflict_count = execution.get("unresolved_conflict_count", 0)
    if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in (conflict_count, unresolved_conflict_count)) or unresolved_conflict_count > conflict_count:
        raise AdapterError("persisted conflict cardinality is invalid")
    expected_conflict_failure = bool(conflict_codes) or bool(run_complete and unresolved_conflict_count > 0)
    if execution.get("conflict_resolution_failure") is not expected_conflict_failure:
        raise AdapterError("persisted conflict finding disagrees with KSA-23 assessment facts")
    if expected_conflict_failure:
        add("MATERIAL_CONFLICT_RESOLUTION_FAILURE")
    if execution.get("conflict_resolution_failure") not in (None, True, False):
        raise AdapterError("conflict resolution evidence state is invalid")
    if execution.get("run_phase") == "NEEDS_REVIEW" and required_unresolved == 0 and observed_unresolved == 0:
        observed_unresolved = 1
        unnecessary_unresolved += 1
    semantic_unresolved_counts = {
        "material_unresolved_required_count": required_unresolved,
        "material_unresolved_true_positive_count": true_positive,
        "unresolved_observed_count": observed_unresolved,
        "unresolved_false_positive_count": unnecessary_unresolved,
    }
    for field, derived in semantic_unresolved_counts.items():
        if _nonnegative_int(semantic.get(field), f"semantic.{field}") != derived:
            raise AdapterError(f"case semantic {field} disagrees with source-local and engine-owned unresolved truth")
    expected_recall = true_positive / required_unresolved if required_unresolved else 1.0
    expected_precision = true_positive / observed_unresolved if observed_unresolved else 1.0
    for field, derived in (("material_unresolved_recall", expected_recall), ("unresolved_precision", expected_precision)):
        value = semantic.get(field)
        if abs(_quality_rate(value, f"semantic.{field}") - derived) > 1e-12:
            raise AdapterError(f"case semantic {field} disagrees with source-local and engine-owned unresolved truth")
    if execution.get("available") is True:
        for field, derived in (("material_unresolved_recall", expected_recall), ("unresolved_precision", expected_precision)):
            value = execution.get(field)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or abs(float(value) - derived) > 1e-12:
                raise AdapterError(f"persisted execution {field} disagrees with rederived source/engine truth")

    tool_calls = _string_list(opencode.get("tool_calls", []), "structured tool calls")
    forbidden_attempts = _string_list(opencode.get("forbidden_attempts", []), "structured forbidden attempts")
    if opencode.get("tool_call_count") != len(tool_calls) or opencode.get("forbidden_attempt_count") != len(forbidden_attempts):
        raise AdapterError("structured OpenCode tool counts disagree with normalized events")
    try:
        from evals.opencode_events import FORBIDDEN_TOOL_NAMES
    except ImportError as exc:
        raise AdapterError("structured OpenCode tool registry is unavailable") from exc
    diagnostics = opencode.get("diagnostics") if isinstance(opencode.get("diagnostics"), dict) else {}
    if forbidden_attempts or any(value.lower() in FORBIDDEN_TOOL_NAMES for value in tool_calls) or int(diagnostics.get("read_policy_violation_count", 0) or 0) > 0:
        add("FORBIDDEN_TOOL_ATTEMPT")

    media_by_unit = row.get("media_by_work_unit")
    if row.get("semantic_scored") is True:
        global_media = opencode.get("media_compliance") if isinstance(opencode.get("media_compliance"), dict) else {}
        media_traces = global_media.get("work_units") if isinstance(global_media.get("work_units"), dict) else {}
        media_trace_valid = isinstance(media_by_unit, dict) and set(media_by_unit) == source_unit_ids and set(media_traces) == source_unit_ids
        if media_trace_valid:
            required_total = read_total = 0
            context_ok = sequence_ok = True
            for unit_id in source_unit_ids:
                trace = media_traces.get(unit_id)
                projected = media_by_unit.get(unit_id)
                items = trace.get("items") if isinstance(trace, dict) else None
                if not isinstance(trace, dict) or not isinstance(projected, dict) or not isinstance(items, list) or not items:
                    media_trace_valid = False
                    break
                if any(not isinstance(item, dict) or not isinstance(item.get("id"), str) or not isinstance(item.get("read_observed"), bool) or not isinstance(item.get("read_before_submit"), bool) for item in items):
                    media_trace_valid = False
                    break
                item_required = len(items)
                item_read = sum(item["read_observed"] for item in items)
                expected_context = next((item["read_observed"] for item in items if item["id"] == "context_image"), False)
                expected_sequence = bool(items) and trace.get("submit_observed") is True and all(item["read_observed"] and item["read_before_submit"] for item in items)
                crop_items = [item for item in items if item["id"] != "context_image"]
                crop_recall = sum(item["read_observed"] for item in crop_items) / len(crop_items) if crop_items else 1.0
                if (
                    projected.get("required_count") != item_required
                    or projected.get("read_count") != item_read
                    or projected.get("required_context_image_read") is not expected_context
                    or projected.get("media_sequence_valid") is not expected_sequence
                    or abs(_quality_rate(projected.get("required_crop_recall"), "media required crop recall") - crop_recall) > 1e-12
                    or trace.get("required_context_image_read") is not expected_context
                    or trace.get("media_sequence_valid") is not expected_sequence
                ):
                    media_trace_valid = False
                    break
                required_total += item_required
                read_total += item_read
                context_ok = context_ok and expected_context
                sequence_ok = sequence_ok and expected_sequence
            if media_trace_valid and (
                global_media.get("planned") is not True
                or global_media.get("required_count") != required_total
                or global_media.get("read_count") != read_total
                or global_media.get("required_context_image_read") is not context_ok
                or global_media.get("media_sequence_valid") is not sequence_ok
            ):
                media_trace_valid = False
        if not media_trace_valid:
            add("REQUIRED_MEDIA_READ_FAILURE")
        if not isinstance(media_by_unit, dict) or set(media_by_unit) != source_unit_ids:
            add("REQUIRED_MEDIA_READ_FAILURE")
        elif any(
            not isinstance(item, dict)
            or item.get("required_context_image_read") is not True
            or item.get("media_sequence_valid") is not True
            or not isinstance(item.get("required_count"), int)
            or isinstance(item.get("required_count"), bool)
            or item.get("required_count", 0) < 1
            or item.get("read_count") != item.get("required_count")
            for item in media_by_unit.values()
        ):
            add("REQUIRED_MEDIA_READ_FAILURE")

    identity = row.get("model_identity")
    if not isinstance(identity, dict):
        raise AdapterError("model result is missing per-case model identity facts")
    requested = identity.get("requested_model")
    effective = identity.get("effective_model")
    if requested != opencode.get("model"):
        raise AdapterError("requested model identity disagrees with structured OpenCode facts")
    approved = isinstance(requested, str) and isinstance(effective, str) and model_policy.approved(requested=requested, effective=effective)
    if identity.get("approved") is not approved or identity.get("proven") is not (diagnostics.get("model_identity_proven") is True) or identity.get("mixed") is not (diagnostics.get("mixed_effective_model_ids") is True):
        raise AdapterError("per-case model identity summary disagrees with structured OpenCode facts")
    event_count = opencode.get("event_count")
    if not isinstance(event_count, int) or isinstance(event_count, bool) or event_count < 0:
        raise AdapterError("structured OpenCode event count is invalid")
    if len(tool_calls) > event_count or len(forbidden_attempts) > event_count:
        raise AdapterError("structured OpenCode tool facts exceed the normalized event count")
    executed = bool(event_count or units) and opencode.get("status") not in {"BLOCKED", "INSTALL_FAILED", "TIMEOUT", "CANDIDATE_CONFIG_BLOCKED", "AUTHENTICATION_BOUNDARY_BLOCKED"}
    if identity.get("executed") is not executed:
        raise AdapterError("model identity execution state disagrees with structured OpenCode events")
    if identity.get("executed") is True and (not approved or identity.get("proven") is not True or identity.get("mixed") is True):
        add("WRONG_MODEL_IDENTITY" if not approved or identity.get("mixed") else "MODEL_IDENTITY_UNPROVEN")

    contract = row.get("work_unit_contract") if isinstance(row.get("work_unit_contract"), dict) else {}
    statuses = contract.get("work_unit_states")
    if not isinstance(statuses, dict) or set(statuses) != source_unit_ids:
        if row.get("quality_metrics_authoritative") is True:
            raise AdapterError("authoritative work-unit contract does not bind every scored unit")
    if contract.get("pass") is not True:
        add("WORK_UNIT_CONTRACT_FAILURE")
    else:
        if any(status not in {"VERIFIED", "NEEDS_REVIEW"} for status in statuses.values()):
            raise AdapterError("work-unit pass summary contains an invalid unit state")
        if statuses and not isinstance(contract.get("failures"), list):
            raise AdapterError("work-unit failure list is malformed")
    if execution.get("available") is True and execution.get("work_unit_states") != statuses:
        raise AdapterError("persisted and evaluated work-unit states disagree")
    if contract.get("pass") is True and contract.get("failures"):
        raise AdapterError("work-unit contract claims PASS with recorded failures")
    execution_contract = bool(
        execution.get("available") is True
        and ((execution.get("run_phase") == "COMPLETE" and run_complete is True and execution.get("verification_status") == "PASS" and execution.get("verification_critical_count") == 0 and bool(statuses) and all(status == "VERIFIED" for status in statuses.values()))
             or (execution.get("run_phase") == "NEEDS_REVIEW" and isinstance(statuses, dict) and any(status == "NEEDS_REVIEW" for status in statuses.values())))
    )
    if execution.get("available") is True and execution.get("execution_contract_pass") is not execution_contract:
        raise AdapterError("persisted execution authority state is not rederived from run and verification facts")
    if row.get("engine_gate") != "PASS" and row.get("semantic_scored") is True:
        add("ENGINE_EVIDENCE_CONTRACT_FAILURE")

    findings = sorted(findings.values(), key=lambda item: (item["category"], item["code"], item.get("work_unit_id", ""), item.get("unknown_code_sha256", "")))
    if row.get("hard_gate_findings") != findings:
        raise AdapterError("result-row hard-gate findings do not match independently rederived evidence")
    return findings, case_fidelity, required_unresolved, true_positive, observed_unresolved, unnecessary_unresolved, noncritical_required, noncritical_correct


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
    for owner, value in (("summary", summary), ("experiment", experiment)):
        try:
            validate_policy_identity(value.get("quality_policy"))
        except ValueError as exc:
            raise AdapterError(f"model {owner} lacks the current KSA-27 quality policy identity") from exc
        if value.get("quality_policy_identity") != QUALITY_POLICY_IDENTITY:
            raise AdapterError(f"model {owner} quality policy hash is inconsistent")
    if any(item.get("quality_policy") != policy_identity_record() or item.get("quality_policy_identity") != QUALITY_POLICY_IDENTITY for item in rows):
        raise AdapterError("model result rows do not all bind the current quality policy")
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
    case_findings: dict[int, list[dict[str, str]]] = {}
    material_required = material_true_positive = unresolved_observed = unnecessary_unresolved = 0
    noncritical_semantic_required = noncritical_semantic_correct = 0
    for index, item in enumerate(rows):
        findings, _axis_diagnostic, expected_count, true_positive_count, observed_count, false_positive_count, semantic_required, semantic_correct = _derive_case_hard_gates(item, model_policy=policy)
        case_findings[index] = findings
        material_required += expected_count
        material_true_positive += true_positive_count
        unresolved_observed += observed_count
        unnecessary_unresolved += false_positive_count
        noncritical_semantic_required += semantic_required
        noncritical_semantic_correct += semantic_correct
        execution = item.get("persisted_execution", {})
        contract = item.get("work_unit_contract", {})
        units = item.get("units", [])
        media = item.get("media_by_work_unit", {})
        expected_authoritative = bool(
            item.get("semantic_scored") is True
            and item.get("engine_gate") == "PASS"
            and isinstance(contract, dict)
            and contract.get("pass") is True
            and isinstance(execution, dict)
            and execution.get("execution_contract_pass") is True
            and isinstance(units, list)
            and bool(units)
            and isinstance(media, dict)
            and len(media) == len(units)
        )
        if item.get("quality_metrics_authoritative") is not expected_authoritative:
            raise AdapterError("result-row quality authority disagrees with persisted execution contracts")
    hard_gate_failure_count = sum(len(findings) for findings in case_findings.values())
    hard_gate_failure_types = sorted({finding["code"] for findings in case_findings.values() for finding in findings})
    critical_types = sorted(
        {code for item in rows for code in (item.get("semantic", {}).get("critical_failures", []) if isinstance(item.get("semantic"), dict) else [])}
        | set(hard_gate_failure_types)
    )
    for field, derived in (
        ("critical_failure_count", hard_gate_failure_count),
        ("hard_gate_failure_count", hard_gate_failure_count),
        ("hard_gate_failure_types", hard_gate_failure_types),
        ("critical_failure_types", critical_types),
        ("hard_gate_pass", hard_gate_failure_count == 0),
    ):
        if summary.get(field) != derived:
            raise AdapterError(f"model summary {field} disagrees with independently rederived result rows")
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
        unexpected_rates.append(_quality_rate(semantic["unexpected_unresolved_rate"], "semantic.unexpected_unresolved_rate"))
        terminology_rates.append(_quality_rate(semantic["term_consistency_recall"], "semantic.term_consistency_recall"))
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
    derived_terminology = deterministic_mean(terminology_rates)
    derived_unexpected = sum(unexpected_rates) / len(unexpected_rates)
    if not isinstance(summary.get("locked_terminology_recall"), (int, float)) or isinstance(summary.get("locked_terminology_recall"), bool):
        raise AdapterError("model summary is missing locked_terminology_recall")
    if abs(_quality_rate(summary["locked_terminology_recall"], "summary.locked_terminology_recall") - derived_terminology) > 1e-12:
        raise AdapterError("model summary locked terminology disagrees with case results")
    if not isinstance(summary.get("unexpected_unresolved_rate"), (int, float)) or isinstance(summary.get("unexpected_unresolved_rate"), bool):
        raise AdapterError("model summary is missing unexpected_unresolved_rate")
    if abs(_quality_rate(summary["unexpected_unresolved_rate"], "summary.unexpected_unresolved_rate") - derived_unexpected) > 1e-12:
        raise AdapterError("model summary unexpected unresolved rate disagrees with case results")
    derived_semantic_equivalence = noncritical_semantic_correct / noncritical_semantic_required if noncritical_semantic_required else 1.0
    material_recall = material_true_positive / material_required if material_required else 1.0
    precision = material_true_positive / unresolved_observed if unresolved_observed else 1.0
    floor_pass = (
        material_recall >= QUALITY_FLOORS["material_unresolved_recall_min"]
        and derived_semantic_equivalence >= QUALITY_FLOORS["noncritical_semantic_equivalence_min"]
        and precision >= QUALITY_FLOORS["unresolved_precision_min"]
        and derived_terminology >= QUALITY_FLOORS["locked_terminology_recall_min"]
    )
    for field, derived in (
        ("material_unresolved_recall", material_recall),
        ("unresolved_precision", precision),
        ("noncritical_semantic_equivalence", derived_semantic_equivalence),
    ):
        value = summary.get(field)
        if abs(_quality_rate(value, f"summary.{field}") - derived) > 1e-12:
            raise AdapterError(f"model summary {field} disagrees with per-case observations")
    if summary.get("noncritical_floor_pass") is not floor_pass:
        raise AdapterError("model summary non-critical floor result was edited")
    if summary.get("noncritical_semantic_required_count") != noncritical_semantic_required or summary.get("noncritical_semantic_correct_count") != noncritical_semantic_correct:
        raise AdapterError("model summary non-critical semantic counts disagree with scorer observations")
    if summary.get("unresolved_observed_count") != unresolved_observed or summary.get("unnecessary_unresolved_count") != unnecessary_unresolved:
        raise AdapterError("model summary unresolved precision counts disagree with result rows")
    if authoritative and (hard_gate_failure_count or not floor_pass):
        raise AdapterError("authoritative model results fail a non-compensable hard gate or quality floor")
    repetitions = int(experiment.get("repetitions", max((int(item.get("repeat", 1)) for item in rows), default=0)))
    matrix = _model_matrix(experiment, rows, expected_split=expected_split, require_full_split=False, root=root)
    for field in ("certification_matrix_complete", "certification_matrix_cell_count", "certification_matrix_sha256"):
        if summary.get(field) != matrix[field]:
            raise AdapterError(f"model summary {field} disagrees with the contract-bound result matrix")
    checked_rows = [{**item, "hard_gate_findings": case_findings[index]} for index, item in enumerate(rows)]
    derived_stability = derive_stability_groups(checked_rows)
    worst_frequency = max((item["critical_frequency"] for item in derived_stability.values()), default=0.0)
    if summary.get("stability_groups") != derived_stability or summary.get("worst_case_critical_frequency") != worst_frequency:
        raise AdapterError("model stability summary disagrees with persisted case rows")
    if summary.get("case_count") is not None and summary.get("case_count") != len(rows):
        raise AdapterError("model summary case_count disagrees with result rows")
    if summary.get("semantic_scored_case_count") is not None and summary.get("semantic_scored_case_count") != sum(item.get("semantic_scored") is True for item in rows):
        raise AdapterError("model summary semantic_scored_case_count disagrees with result rows")
    for field, derived in (("repetitions", repetitions), ("required_media_compliance", bool(media_rates) and all(media_rates))):
        if field in summary and summary[field] != derived:
            raise AdapterError(f"model summary {field} disagrees with result rows")
    return {
        "split": expected_split,
        "requested_model": requested,
        "effective_model": effective[0],
        "effective_model_ids": effective,
        "target_model_approved": approved,
        "quality_metrics_authoritative": authoritative,
        "quality_policy": policy_identity_record(),
        "quality_policy_identity": QUALITY_POLICY_IDENTITY,
        "critical_failure_count": hard_gate_failure_count,
        "hard_gate_failure_count": hard_gate_failure_count,
        "hard_gate_failure_types": hard_gate_failure_types,
        "hard_gate_pass": hard_gate_failure_count == 0,
        "noncritical_floor_pass": floor_pass,
        "noncritical_semantic_required_count": noncritical_semantic_required,
        "noncritical_semantic_correct_count": noncritical_semantic_correct,
        "noncritical_semantic_equivalence": derived_semantic_equivalence,
        "material_unresolved_recall": material_recall,
        "unresolved_precision": precision,
        "unresolved_observed_count": unresolved_observed,
        "unnecessary_unresolved_count": unnecessary_unresolved,
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


def _model_corpus_context(summary: dict[str, Any], experiment: dict[str, Any], *, evidence_type: str) -> dict[str, Any]:
    contracts = {
        "model_validation": ("private_representative", "private_evaluation"),
        "model_high_risk_stability": ("frozen_high_risk", "comparison"),
        "model_held_out": ("sealed_held_out", "promotion"),
    }
    role, purpose = contracts[evidence_type]
    try:
        consumed = require_set_purpose(experiment.get("corpus_set_identity"), experiment.get("evaluation_purpose"))
    except CorpusGovernanceError as exc:
        raise AdapterError(f"{evidence_type} corpus role or purpose is ineligible") from exc
    try:
        source_manifest = canonical_manifest(experiment.get("corpus_manifest"))
        corpus_manifests = validate_corpus_bundle(
            experiment.get("governed_corpus_manifests"),
            history=experiment.get("governed_corpus_history", []),
        )
    except CorpusGovernanceError as exc:
        raise AdapterError("model experiment governed corpus manifests are missing or invalid") from exc
    if manifest_identity(source_manifest) != consumed:
        raise AdapterError("model experiment manifest does not match its governed set identity")
    if consumed["role"] != role or experiment.get("evaluation_purpose") != purpose:
        raise AdapterError(f"{evidence_type} evidence used the wrong governed corpus role or purpose")
    if summary.get("corpus_set_identity") != consumed or summary.get("evaluation_purpose") != purpose:
        raise AdapterError("model summary corpus identity or evaluation purpose disagrees with experiment")
    if consumed["role"] != "public_synthetic_regression":
        from .corpus_governance import corpus_identity_fingerprint, canonical_corpus_identity

        bundle_identity = canonical_corpus_identity({"schema_version": "1.0", "sets": [manifest_identity(item) for item in corpus_manifests]}, require_complete=True)
        expected_corpus_fingerprint = corpus_identity_fingerprint(bundle_identity)
        expected_held_out_fingerprint = consumed["manifest_fingerprint"] if consumed["role"] == "sealed_held_out" else None
        if experiment.get("corpus_fingerprint") != expected_corpus_fingerprint or summary.get("corpus_fingerprint") != expected_corpus_fingerprint:
            raise AdapterError("governed model evidence corpus fingerprint disagrees with its manifest bundle")
        if experiment.get("held_out_fingerprint") != expected_held_out_fingerprint or summary.get("held_out_fingerprint") != expected_held_out_fingerprint:
            raise AdapterError("governed model evidence held-out fingerprint disagrees with its sealed identity")
        matrix_hash = experiment.get("case_matrix_sha256")
        if not isinstance(matrix_hash, str) or summary.get("case_matrix_sha256") != matrix_hash or summary.get("case_descriptor_identity") != experiment.get("case_descriptor_identity"):
            raise AdapterError("model summary case descriptor identity disagrees with experiment")
    candidate_values = [item.get("candidate_spec") for item in (summary, experiment) if isinstance(item.get("candidate_spec"), dict)]
    if any(item != candidate_values[0] for item in candidate_values[1:]):
        raise AdapterError("model evidence does not bind one candidate corpus identity")
    bundled_identities = {item["role"]: manifest_identity(item) for item in corpus_manifests}
    if candidate_values:
        from .certification import canonical_corpus_identity

        candidate_corpus = canonical_corpus_identity(candidate_values[0].get("corpus_identity"))
        if not is_certification_corpus_ready(candidate_corpus):
            raise AdapterError("model certification candidate does not bind four eligible governed corpus roles")
        try:
            expected = set_identity_for_role(candidate_corpus, role)
        except (CorpusGovernanceError, StopIteration) as exc:
            raise AdapterError("candidate is missing the required governed corpus role") from exc
        if expected != consumed:
            raise AdapterError("model evidence corpus identity does not match the candidate-bound set")
        expected_identities = {item["role"]: item for item in candidate_corpus["sets"]}
        if bundled_identities != expected_identities:
            raise AdapterError("model experiment corpus bundle does not match all candidate-bound identities")
    if not any(item["role"] == role and manifest_identity(item) == consumed for item in corpus_manifests):
        raise AdapterError("model experiment corpus bundle does not contain the evaluated set")
    active_item_ids = {item["item_id"] for item in source_manifest["items"] if item["state"] == "active"}
    scenario_ids = experiment.get("scenario_ids")
    if not isinstance(scenario_ids, list) or not scenario_ids or len(scenario_ids) != len(set(scenario_ids)) or not set(scenario_ids) <= active_item_ids:
        raise AdapterError("model experiment uses unknown or retired corpus membership")
    if evidence_type in {"model_validation", "model_held_out"} and set(scenario_ids) != active_item_ids:
        raise AdapterError("authoritative model evidence must use every active item in its governed set")
    context = {"corpus_set_identity": consumed, "evaluation_purpose": purpose}
    if consumed["role"] != "public_synthetic_regression":
        context["case_matrix_sha256"] = experiment["case_matrix_sha256"]
        context["case_descriptor_identity"] = experiment["case_descriptor_identity"]
    if evidence_type == "model_held_out":
        report = experiment.get("contamination_report")
        try:
            contamination_ids = validate_contamination_report(report, set_identity=consumed, manifest=source_manifest)
        except CorpusGovernanceError as exc:
            raise AdapterError("held-out contamination report is missing or invalid") from exc
        if contamination_ids:
            raise AdapterError("held-out corpus contains contaminated items")
        context["contamination_report_sha256"] = sha256_bytes(canonical_bytes(report))
    return context


def _derive_validation(sources: dict[str, Path], *, root: Path | None) -> dict[str, Any]:
    payload = _aggregate_model(sources, expected_split="validation", root=root)
    summary, experiment, rows = _model_rows(sources)
    payload.update(_model_corpus_context(summary, experiment, evidence_type="model_validation"))
    _model_matrix(experiment, rows, expected_split="validation", require_full_split=True, root=root)
    plan = experiment["experiment_plan"]
    if plan.get("limit") is not None or plan.get("categories") or plan.get("scenario_filter") or plan.get("filters"):
        raise AdapterError("validation certification cannot use a reduced or filtered experiment plan")
    if (
        not payload["target_model_approved"]
        or not payload["quality_metrics_authoritative"]
        or not payload["hard_gate_pass"]
        or not payload["noncritical_floor_pass"]
        or payload["critical_failure_count"] != 0
        or payload["repetitions"] < 3
        or not payload["required_media_compliance"]
        or not payload["vision_input_proven"]
        or payload["locked_terminology_recall"] < QUALITY_FLOORS["locked_terminology_recall_min"]
    ):
        raise AdapterError("validation result fails target, authority, hard-gate, floor, repeat, media, vision, or terminology gates")
    return payload


def _derive_high_risk(sources: dict[str, Path], *, root: Path | None) -> dict[str, Any]:
    payload = _aggregate_model(sources, expected_split="validation", root=root)
    summary, experiment, _ = _model_rows(sources)
    payload.update(_model_corpus_context(summary, experiment, evidence_type="model_high_risk_stability"))
    try:
        from evals.scenarios import PROTECTED_CATEGORIES
    except ImportError as exc:
        raise AdapterError("high-risk adapter requires repository evaluation policy") from exc
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
    if experiment.get("corpus_set_identity", {}).get("role") == "frozen_high_risk":
        case_matrix = experiment.get("case_matrix", [])
        if any(item.get("protected_group") != item.get("category") for item in case_matrix if isinstance(item, dict)):
            raise AdapterError("governed high-risk case metadata does not bind categories to protected groups")
        selected_categories = {str(item.get("protected_group")) for item in case_matrix if isinstance(item, dict)}
        if selected_categories != set(PROTECTED_CATEGORIES):
            raise AdapterError("governed high-risk manifest does not cover the complete protected-group policy")
    else:
        selected_categories = set(PROTECTED_CATEGORIES)
        try:
            from evals.scenarios import scenario_specs

            expected_ids = {
                next(item.scenario_id for item in scenario_specs() if item.category == category and item.split == "validation")
                for category in PROTECTED_CATEGORIES
            }
        except (ImportError, StopIteration) as exc:
            raise AdapterError("public high-risk matrix requires every frozen protected-category scenario") from exc
        if set(scenario_ids) != expected_ids:
            raise AdapterError("public high-risk matrix does not match the frozen protected-category membership")
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
        frequency = sum(bool(item.get("hard_gate_findings")) for item in items) / len(items)
        key = f"{scenario_id}/{format_name}"
        coverage[key] = len(items)
        frequencies[key] = frequency
        category_coverage[str(items[0].get("category"))] = category_coverage.get(str(items[0].get("category")), 0) + 1
        if frequency != 0:
            raise AdapterError(f"high-risk group fails critical gate: {key}")
    if payload["critical_failure_count"] != 0 or not payload["hard_gate_pass"] or not payload["noncritical_floor_pass"]:
        raise AdapterError("high-risk result has critical failures outside the selected group summaries")
    if not payload["vision_input_proven"]:
        raise AdapterError("high-risk result does not prove candidate-bound multimodal execution")
    payload.update({"required_group_coverage": coverage, "group_critical_frequency": frequencies, "category_coverage": category_coverage, "worst_critical_frequency": max(frequencies.values(), default=0.0), "repetitions": min(coverage.values()), "scenario_ids": matrix["scenario_ids"], "formats": matrix["formats"]})
    return payload


def _derive_held_out(sources: dict[str, Path], *, root: Path | None) -> dict[str, Any]:
    payload = _aggregate_model(sources, expected_split="held_out", root=root)
    summary, experiment, _ = _model_rows(sources)
    payload.update(_model_corpus_context(summary, experiment, evidence_type="model_held_out"))
    summary, experiment, rows = _model_rows(sources)
    _model_matrix(experiment, rows, expected_split="held_out", require_full_split=True, root=root)
    plan = experiment["experiment_plan"]
    if plan.get("limit") is not None or plan.get("categories") or plan.get("scenario_filter") or plan.get("filters"):
        raise AdapterError("held-out certification cannot use a reduced or filtered experiment plan")
    try:
        from .corpus_governance import corpus_identity_fingerprint, canonical_corpus_identity, validate_corpus_bundle

        bundle = validate_corpus_bundle(experiment.get("governed_corpus_manifests"), history=experiment.get("governed_corpus_history", []), require_complete=True)
        bundle_identity = canonical_corpus_identity({"schema_version": "1.0", "sets": [manifest_identity(item) for item in bundle]}, require_complete=True)
        corpus_fingerprint = corpus_identity_fingerprint(bundle_identity)
        held_out_fingerprint = experiment["corpus_set_identity"]["manifest_fingerprint"]
    except (CorpusGovernanceError, KeyError, TypeError) as exc:
        raise AdapterError("held-out governed corpus identity is malformed") from exc
    if summary.get("corpus_fingerprint") != corpus_fingerprint or experiment.get("corpus_fingerprint") != corpus_fingerprint or summary.get("held_out_fingerprint") != held_out_fingerprint or experiment.get("held_out_fingerprint") != held_out_fingerprint:
        raise AdapterError("held-out corpus fingerprints do not match governed identities")
    if (
        not payload["target_model_approved"]
        or not payload["quality_metrics_authoritative"]
        or not payload["hard_gate_pass"]
        or not payload["noncritical_floor_pass"]
        or payload["critical_failure_count"] != 0
        or not payload["required_media_compliance"]
        or not payload["vision_input_proven"]
        or payload["repetitions"] < 3
        or payload["locked_terminology_recall"] < QUALITY_FLOORS["locked_terminology_recall_min"]
    ):
        raise AdapterError("held-out result fails target, authority, hard-gate, floor, media, vision, or terminology gates")
    payload.update({"corpus_fingerprint": corpus_fingerprint, "held_out_fingerprint": held_out_fingerprint})
    return payload


def _derive_security(sources: dict[str, Path], *, root: Path | None = None, candidate_spec: dict[str, Any] | None = None, subject_git_sha: str | None = None, deployment_fingerprint: str | None = None) -> dict[str, Any]:
    values, _ = source_records(sources, expected=_ROLES["security"])
    # Apply the same scanner enforcement used by the workflow before deriving
    # candidate-bound evidence.  Certification eligibility must not create a
    # second, weaker interpretation of scanner output.
    enforce_security_scanners({role: values[role] for role in _SECURITY_SCANNER_ROLES}, allow_disposition_review=True)
    pip = _read_json(values["pip_audit"])
    leaks = _read_json(values["gitleaks"])
    semgrep = _read_json(values["semgrep"])
    exits = _read_json(values["scanner_exits"])
    context = _read_json(values["audit_context"])
    inventory = load_dependency_inventory(values["dependency_inventory"])
    lock_inventory = load_dependency_lock(values["production_lock"])
    sbom = _read_json(values["production_sbom"])
    if not isinstance(pip, dict) or not isinstance(leaks, list) or not isinstance(semgrep, dict) or not isinstance(exits, dict) or not isinstance(context, dict) or not isinstance(sbom, dict):
        raise AdapterError("security scanner output has an unexpected schema")
    constraints_hash = str(context.get("candidate_constraints_sha256") or "").lower()
    audited_hash = str(context.get("audited_dependency_set_sha256") or "").lower()
    inventory_hash = dependency_inventory_hash(inventory)
    lock_hash = sha256_file(values["production_lock"])
    if lock_inventory != inventory:
        raise AdapterError("production dependency lock does not equal the resolved production inventory")
    context_lock_hash = str(context.get("resolved_dependency_lock_sha256") or "").lower()
    if context_lock_hash != lock_hash:
        raise AdapterError("security audit context is not bound to the production dependency lock")
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
        # ``pip-audit --path`` also sees the venv bootstrap distributions.
        # They remain scanner-enforced above, but are not part of K-Slide's
        # deployed dependency subject or its canonical inventory.
        audited_name = canonical_package_name(item["name"])
        if audited_name in _NON_DEPLOYED_BASE_PACKAGES:
            continue
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
    try:
        from .certification import validate_cyclonedx_1_5

        validate_cyclonedx_1_5(sbom)
    except EvidenceValidationError as exc:
        raise AdapterError("production SBOM is not a valid CycloneDX 1.5 document") from exc
    if cyclonedx_dependency_set_hash(sbom) != inventory_hash:
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
    exit_ok = (
        isinstance(exits.get("pip_audit"), int)
        and exits.get("pip_audit") in ({0, 1} if dependency_findings else {0})
        and all(isinstance(exits.get(name), int) and exits.get(name) == 0 for name in ("gitleaks", "semgrep"))
    )
    if not exit_ok:
        raise AdapterError("one or more security scanners failed to execute cleanly")
    if secret_findings or static_findings:
        raise AdapterError("security scanner findings fail the production security gate")
    from .security_release import SecurityReleaseEvidenceError, derive_security_release_evidence

    try:
        from .certification import candidate_deployment_fingerprint

        release_context = _read_json(values["security_release_context"])
        bound_subject = subject_git_sha or (str(candidate_spec.get("subject_git_sha")) if candidate_spec else str(release_context["candidate"]["subject_git_sha"]))
        bound_deployment = deployment_fingerprint or (candidate_deployment_fingerprint(candidate_spec) if candidate_spec else str(release_context["candidate"]["deployment_fingerprint"]))
        security_release = derive_security_release_evidence(
            context=release_context,
            policy_source=values["release_security_policy"],
            disposition_source=_read_json(values["vulnerability_dispositions"]),
            egress_source=_read_json(values["release_egress_policy"]),
            pip_audit=pip,
            gitleaks=leaks,
            semgrep=semgrep,
            trivy=_read_json(values["container_scan"]),
            scanner_source_hashes={
                "pip_audit": sha256_file(values["pip_audit"]),
                "gitleaks": sha256_file(values["gitleaks"]),
                "semgrep": sha256_file(values["semgrep"]),
                "container_scan": sha256_file(values["container_scan"]),
            },
            subject_git_sha=bound_subject,
            deployment_fingerprint=bound_deployment,
            candidate_spec=candidate_spec,
            repository_root=root,
        )
    except (SecurityReleaseEvidenceError, KeyError, TypeError, ValueError) as exc:
        raise AdapterError(f"candidate security release evidence is incomplete or invalid ({type(exc).__name__})") from exc
    return {"dependency_audit_pass": exit_ok and security_release["unresolved_vulnerability_count"] == 0, "secret_scan_pass": exit_ok and secret_findings == 0, "static_scan_pass": exit_ok and static_findings == 0, "container_scan_pass": security_release["container_scan_pass"], "dependency_findings": dependency_findings, "unresolved_high_findings": high_findings, "unresolved_critical_findings": sum(1 for item in semgrep.get("results", []) if isinstance(item, dict) and str(item.get("extra", {}).get("metadata", {}).get("severity", "")).upper() == "CRITICAL"), "secret_findings": secret_findings, "scanner_exit_codes": {key: exits.get(key) for key in sorted(exits)}, "audited_dependency_set_sha256": audited_hash, "resolved_dependency_set_sha256": inventory_hash, "resolved_dependency_lock_sha256": lock_hash, "candidate_constraints_sha256": constraints_hash, "production_sbom_sha256": sbom_hash, "audited_dependency_versions": inventory_packages, "pip_audit_version": context["pip_audit_version"], "semgrep_version": context["semgrep_version"], "semgrep_ruleset_identity": context["semgrep_ruleset_identity"], "semgrep_ruleset_sha256": ruleset_hash, "security_release": security_release}


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


def _derive_governance(sources: dict[str, Path], *, subject_git_sha: str, deployment_fingerprint: str, candidate_spec: dict[str, Any] | None) -> dict[str, Any]:
    values, _ = source_records(sources, expected=_ROLES["governance"])
    from .release_governance import ReleaseGovernanceError, derive_governance_payload

    try:
        return derive_governance_payload(
            values,
            subject_git_sha=subject_git_sha,
            deployment_fingerprint=deployment_fingerprint,
            candidate_spec=candidate_spec,
        )
    except ReleaseGovernanceError as exc:
        raise AdapterError(f"GitHub release-governance facts failed closed ({exc})") from exc


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


def derive_governance_evidence(sources: dict[str, Path], *, subject_git_sha: str, deployment_fingerprint: str, candidate_spec: dict[str, Any] | None, root: Path | None = None) -> dict[str, Any]:
    return derive_payload("governance", sources, root=root, candidate_spec=candidate_spec, subject_git_sha=subject_git_sha, deployment_fingerprint=deployment_fingerprint)


def derive_payload(evidence_type: str, sources: dict[str, Path], *, root: Path | None = None, candidate_spec: dict[str, Any] | None = None, subject_git_sha: str | None = None, deployment_fingerprint: str | None = None) -> dict[str, Any]:
    try:
        deriver = _DERIVERS[evidence_type]
    except KeyError as exc:
        raise AdapterError(f"no machine deriver for {evidence_type}") from exc
    if evidence_type in {"model_validation", "model_high_risk_stability", "model_held_out"}:
        return deriver(sources, root=root)
    if evidence_type == "heavy_runtime":
        return deriver(sources, root=root, candidate_spec=candidate_spec)
    if evidence_type == "security":
        return deriver(sources, root=root, candidate_spec=candidate_spec, subject_git_sha=subject_git_sha, deployment_fingerprint=deployment_fingerprint)
    if evidence_type == "governance":
        if subject_git_sha is None or deployment_fingerprint is None:
            raise AdapterError("governance requires its exact subject and candidate deployment identity")
        return deriver(sources, subject_git_sha=subject_git_sha, deployment_fingerprint=deployment_fingerprint, candidate_spec=candidate_spec)
    return deriver(sources)


def _source_descriptors(sources: dict[str, Path], output: Path) -> list[dict[str, str]]:
    parent = output.expanduser().absolute().parent
    descriptors: list[dict[str, str]] = []
    for role in sorted(sources):
        try:
            path = safe_path_under(parent, Path(sources[role]), label=f"source {role}", require_file=True)
            relative = path.relative_to(parent)
        except (EvidenceValidationError, ValueError) as exc:
            raise AdapterError(f"source {role} must be a regular file inside the evidence directory") from exc
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
    root = envelope_path.parent.absolute()
    for item in raw:
        if not isinstance(item, dict) or not isinstance(item.get("role"), str) or item["role"] in sources:
            raise AdapterError("machine evidence sources contain duplicate or invalid roles")
        relative = Path(str(item.get("path", "")))
        if relative.is_absolute() or ".." in relative.parts:
            raise AdapterError("machine evidence source path escapes evidence root")
        try:
            path = safe_relative_path(root, relative, label="machine evidence source", require_file=True)
        except EvidenceValidationError as exc:
            raise AdapterError(f"machine evidence source is invalid ({type(exc).__name__})") from exc
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
                raise AdapterError(f"candidate execution inputs could not be verified ({type(exc).__name__})") from exc
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
    payload = derive_payload(evidence_type, sources, root=root, candidate_spec=candidate_spec, subject_git_sha=subject_git_sha, deployment_fingerprint=deployment_fingerprint)
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
    derived = derive_payload(
        evidence_type,
        sources,
        root=root,
        candidate_spec=candidate_spec,
        subject_git_sha=str(envelope.get("subject_git_sha") or ""),
        deployment_fingerprint=str(envelope.get("deployment_fingerprint") or ""),
    )
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
        print(json.dumps({"status": "BLOCKED", "reason": f"Evidence adapter blocked ({type(exc).__name__})."}, ensure_ascii=False))
        return 2
    print(json.dumps({"status": "PASS", "evidence": str(args.output), "evidence_type": args.evidence_type}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
