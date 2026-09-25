from __future__ import annotations

import copy
import hashlib
import json
import os
import platform
import shutil
import subprocess
import tempfile
import zipfile
import unittest
from urllib.error import HTTPError
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import call, patch

from evals.release import build_production_sbom, build_release_manifest, derive_release_state, main as release_main
from evals.experiments import behavior_configuration_hash, experiment_plan, experiment_plan_hash
from evals.scenarios import PROTECTED_CATEGORIES, scenario_specs
from evals.corpus_governance import public_synthetic_manifest
from k_slide.certification import (
    EvidenceValidationError,
    NOT_APPLICABLE_VALUE,
    NOT_EXPOSED_VALUE,
    build_deployment_factors,
    canonical_dependency_inventory,
    candidate_completeness,
    candidate_deployment_fingerprint,
    canonical_candidate_factors,
    certification_fingerprint,
    dependency_lock_text,
    deployment_fingerprint,
    effective_termbase_identity,
    load_candidate_spec,
    load_evidence,
    resolve_candidate_spec,
    dependency_inventory_hash,
    load_dependency_lock,
    repository_schema_versions,
    paddle_runtime_configuration,
    validate_cyclonedx_1_5,
    write_evidence,
)
from k_slide.evidence_adapters import AdapterError, build_machine_evidence, enforce_security_scanners
from k_slide.corpus_governance import build_manifest, manifest_identity, corpus_identity_fingerprint
from evals.governed_corpus import case_matrix_fingerprint, case_matrix_item_fingerprint
from k_slide.egress_policy import (
    EGRESS_CAPABILITY_DURABLE_JOB_CONTROL,
    EGRESS_CAPABILITY_INFERENCE_ROUTE,
    EGRESS_CAPABILITY_NON_CONTENT_TELEMETRY,
    EGRESS_CAPABILITY_SCOPED_STORAGE,
    EGRESS_DATA_CLASS_NON_CONTENT,
    egress_policy_hash_for_mapping,
    egress_policy_identity_for_mapping,
    opencode_route_identity,
)
from k_slide.model_policy import load_model_policy
from k_slide.quality_policy import QUALITY_POLICY_IDENTITY, policy_identity_record
from k_slide.bilingual_adjudication import build_internal_bilingual_payload
from tests.bilingual_review_fixtures import make_review_contract
from tests.zero_korean_study_fixtures import zero_korean_payload
from tests.ksa32_governance_fixtures import write_governance_sources
from evals.model_results import aggregate_model_results
from k_slide.production import ProductionProfile, _asset_manifest_status, _manifest_and_fingerprint_status


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


TEST_PYTHON_VERSION = platform.python_version()


def _write(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def _write_opencode_bootstrap(root: Path) -> Path:
    """Materialize the managed production OpenCode contract for certification fixtures."""
    from k_slide.opencode_bootstrap import (
        APPROVED_CREDENTIAL_ENV,
        APPROVED_API_ID,
        APPROVED_API_NPM,
        APPROVED_API_URL,
        APPROVED_MODEL,
        APPROVED_MODEL_ID,
        APPROVED_PROVIDER_ID,
        APPROVED_PLUGIN,
        BOOTSTRAP_SCHEMA_VERSION,
        FORBIDDEN_ENVIRONMENT,
        OPENCODE_VERSION,
        REQUIRED_ENVIRONMENT,
    )

    managed_home = root / "managed-opencode-home"
    config_dir = managed_home / ".opencode"
    plugin_dir = config_dir / "plugin"
    xdg_config = root / "managed-xdg-config"
    xdg_data = root / "managed-xdg-data"
    xdg_cache = root / "managed-xdg-cache"
    xdg_state = root / "managed-xdg-state"
    for directory in (plugin_dir, xdg_config, xdg_config / "opencode", xdg_data, xdg_data / "opencode", xdg_cache, xdg_cache / "opencode", xdg_state, xdg_state / "opencode"):
        directory.mkdir(parents=True, exist_ok=True)
    config_file = config_dir / "opencode.json"
    _write(config_file, {
        "plugin": [APPROVED_PLUGIN],
        "agent": {"k-slide": {"model": APPROVED_MODEL}},
        "autoupdate": False,
        "lsp": False,
        "enabled_providers": [APPROVED_PROVIDER_ID],
        "provider": {APPROVED_PROVIDER_ID: {"whitelist": [APPROVED_MODEL_ID]}},
    })
    plugin_file = plugin_dir / "k-slide-host.ts"
    plugin_file.write_bytes((Path.cwd() / ".opencode" / "plugin" / "k-slide-host.ts").read_bytes())
    helper_dir = config_dir / "internal" / "lib"
    helper_dir.mkdir(parents=True, exist_ok=True)
    helper_file = helper_dir / "k-slide-access-key.ts"
    helper_file.write_bytes((Path.cwd() / ".opencode" / "internal" / "lib" / "k-slide-access-key.ts").read_bytes())
    models_file = root / "managed-models.json"
    _write(models_file, {
        APPROVED_PROVIDER_ID: {
            "id": APPROVED_PROVIDER_ID,
            "env": [APPROVED_CREDENTIAL_ENV],
            "npm": APPROVED_API_NPM,
            "api": APPROVED_API_URL,
            "models": {APPROVED_MODEL_ID: {"id": APPROVED_API_ID}},
        }
    })
    ripgrep_file = root / "managed-bin" / "rg"
    ripgrep_file.parent.mkdir()
    ripgrep_file.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    ripgrep_file.chmod(0o555)
    for file_path in (config_file, plugin_file, helper_file, models_file):
        file_path.chmod(0o444)
    config_dir.chmod(0o555)
    plugin_dir.chmod(0o555)
    (config_dir / "internal").chmod(0o555)
    helper_dir.chmod(0o555)
    xdg_config.chmod(0o555)
    (xdg_config / "opencode").chmod(0o555)

    manifest = root / ".k-slide-config" / "opencode-bootstrap.json"
    _write(manifest, {
        "schema_version": BOOTSTRAP_SCHEMA_VERSION,
        "opencode_version": OPENCODE_VERSION,
        "required_environment": REQUIRED_ENVIRONMENT,
        "forbidden_environment": list(FORBIDDEN_ENVIRONMENT),
        "home_dir": str(managed_home),
        "config_dir": str(config_dir),
        "xdg_config_home": str(xdg_config),
        "xdg_data_home": str(xdg_data),
        "xdg_cache_home": str(xdg_cache),
        "xdg_state_home": str(xdg_state),
        "config_file": str(config_file),
        "config_sha256": _sha(config_file),
        "plugin_file": str(plugin_file),
        "plugin_sha256": _sha(plugin_file),
        "access_key_helper_file": str(helper_file),
        "access_key_helper_sha256": _sha(helper_file),
        "ripgrep_path": str(ripgrep_file),
        "ripgrep_sha256": _sha(ripgrep_file),
        "models_catalog": {"mode": "local_path", "path": str(models_file), "sha256": _sha(models_file), "version": "test-local-1"},
        "credential_environment": [APPROVED_CREDENTIAL_ENV],
    })
    return manifest


def _runtime_sources(root: Path, *, provider: str = "google", ocr_provider: str = "none") -> dict[str, Path]:
    _write(root / "diagnostic.json", {"levels": [{"level": name, "status": "PASS"} for name in ("level1a_pure_opencode", "level1_plain_opencode", "level2_explicit_model", "level3_k_slide_agent")], "runtime_provenance": {"opencode_version": "1.3.9", "python_version": TEST_PYTHON_VERSION, "provider": provider, "ocr_provider": ocr_provider}})
    contract = {"status": "PASS", "kslide_complete": True, "run_complete": True, "required_media_compliance": True, "forbidden_tool_attempts": []}
    _write(root / "simple.json", contract)
    _write(root / "three.json", {**contract, "expected_units": 3, "artifact_units": 3})
    _write(root / "five.json", {**contract, "expected_units": 5, "artifact_units": 5})
    return {"diagnostic_ladder": root / "diagnostic.json", "simple_run": root / "simple.json", "three_slide": root / "three.json", "five_slide": root / "five.json"}


def _doctor(networkless: bool = False) -> dict[str, object]:
    value = {key: {"status": "PASS"} for key in ("libreoffice", "pymupdf", "python_pptx", "pillow", "paddleocr", "paddlepaddle", "korean_font", "paddle_load", "libreoffice_roundtrip", "paddle_ocr_roundtrip")}
    value["network"] = {"networkless_asserted": networkless, "network_required": not networkless}
    value["runtime_provenance"] = {"python_version": TEST_PYTHON_VERSION, "paddle_version": "3.0.0", "paddleocr_version": "3.0.3", "libreoffice_version": "25.2.3"}
    return value


def _heavy_sources(root: Path, *, full: bool = False, subject: str | None = None, deployment: str | None = None, ocr_manifest: Path | None = None, ocr_context: dict[str, object] | None = None) -> dict[str, Path]:
    _write(root / "doctor.json", _doctor())
    _write(root / "networkless.json", _doctor(networkless=True))
    engine = {"engine": {"critical_failure_count": 0, "capability_block_count": 0, "artifact_generation_pass_rate": 1.0, "engine_normalization_pass_rate": 1.0, "evidence_generation_pass_rate": 1.0}}
    _write(root / "representative.json", engine)
    packages = canonical_dependency_inventory([{"name": name, "version": "1.0"} for name in ("Pillow", "PyMuPDF", "python-pptx", "paddlepaddle", "paddleocr")])
    _write(root / "production-inventory.json", packages)
    (root / "production.lock").write_text(dependency_lock_text(packages), encoding="utf-8")
    _write(root / "built-image-inventory.json", packages)
    dependency_hash = dependency_inventory_hash(packages)
    context = {"schema_version": "1.0", "dependency_subject": "production-env", "expected_dependency_set_sha256": dependency_hash, "frozen_dependency_set_sha256": dependency_hash, "built_image_dependency_set_sha256": dependency_hash, "production_lock_sha256": _sha(root / "production.lock")}
    if subject is not None:
        context["subject_git_sha"] = subject
    if deployment is not None:
        context["deployment_fingerprint"] = deployment
    _write(root / "dependency-context.json", context)
    sources = {"required_doctor": root / "doctor.json", "networkless_doctor": root / "networkless.json", "representative_engine": root / "representative.json", "production_inventory": root / "production-inventory.json", "production_lock": root / "production.lock", "built_image_inventory": root / "built-image-inventory.json", "dependency_context": root / "dependency-context.json"}
    if full:
        _write(root / "full.json", engine)
        sources["full_engine"] = root / "full.json"
    if ocr_manifest is not None and ocr_context is not None:
        asset_target_root = root / "ocr-assets"
        asset_target_root.mkdir(parents=True, exist_ok=True)
        target_manifest = asset_target_root / "manifest.json"
        target_manifest.write_bytes(ocr_manifest.read_bytes())
        asset_value = json.loads(ocr_manifest.read_text(encoding="utf-8"))
        for item in asset_value.get("files", []):
            relative = Path(item["path"])
            target_asset = asset_target_root / relative
            target_asset.parent.mkdir(parents=True, exist_ok=True)
            target_asset.write_bytes((ocr_manifest.parent / relative).read_bytes())
        target_context = root / "ocr-asset-context.json"
        _write(target_context, ocr_context)
        sources["ocr_asset_manifest"] = target_manifest
        sources["ocr_asset_context"] = target_context
    return sources


def _test_corpus_manifests(evidence_type: str, selected_ids: list[str]) -> tuple[list[dict], dict, str]:
    def fixture_item_id(role: str, source_item_id: str) -> str:
        suffix = hashlib.sha256(source_item_id.encode()).hexdigest()[:16]
        return f"fixture-{role}-{suffix}"

    scenario_values = scenario_specs()
    validation_ids = [fixture_item_id("private_representative", item.scenario_id) for item in scenario_values if item.split == "validation"]
    held_out_ids = [fixture_item_id("sealed_held_out", item.scenario_id) for item in scenario_values if item.split == "held_out"]
    high_risk_ids = [fixture_item_id("frozen_high_risk", next(item.scenario_id for item in scenario_values if item.category == category and item.split == "validation")) for category in PROTECTED_CATEGORIES]
    public = public_synthetic_manifest()
    roles = (
        ("private_representative", "active", validation_ids, "private_evaluation"),
        ("frozen_high_risk", "frozen", high_risk_ids, "comparison"),
        ("sealed_held_out", "sealed", held_out_ids, "promotion"),
    )
    manifests = [public]
    for role, state, item_ids, _purpose in roles:
        authority = "approved_private_evaluation" if role == "private_representative" else "evaluation_governance"
        records = [
            {
                "item_id": item_id,
                "source_sha256": hashlib.sha256(f"test-only:{role}:{item_id}:source".encode()).hexdigest(),
                "gold_sha256": hashlib.sha256(f"test-only:{role}:{item_id}:gold".encode()).hexdigest(),
                "state": "active",
            }
            for item_id in item_ids
        ]
        manifests.append(build_manifest(
            set_id=f"test-only-{role}", role=role, version="fixture-v1", state=state, items=records,
            provenance={"authority": authority, "record_sha256": hashlib.sha256(f"test-only:{role}:authority".encode()).hexdigest()},
        ))
    target_role, purpose = {
        "model_validation": ("private_representative", "private_evaluation"),
        "model_high_risk_stability": ("frozen_high_risk", "comparison"),
        "model_held_out": ("sealed_held_out", "promotion"),
    }[evidence_type]
    selected_manifest = next(item for item in manifests if item["role"] == target_role)
    normalized_selected_ids = {
        fixture_item_id(target_role, item_id) if item_id.startswith("scenario-") else item_id
        for item_id in selected_ids
    }
    if not normalized_selected_ids <= {item["item_id"] for item in selected_manifest["items"]}:
        raise AssertionError("test fixture selected IDs are outside governed corpus membership")
    identity = manifest_identity(selected_manifest)
    return manifests, identity, purpose


def _model_result_row(*, scenario_id: str, category: str, split: str, repeat: int, item_identity: str, subject: str, deployment: str, critical: bool = False) -> dict:
    code = "CRITICAL_NUMERIC_MISMATCH" if critical else None
    gate_evidence = {
        "missing_required_region_ids": [],
        "numeric_mismatch_fact_ids": (["fact-1"] if critical else []),
        "modality_score": 1.0,
        "modality_source_binding_failure": False,
        "hangul_violation_count": 0,
        "unsupported_claim_count": 0,
        "executive_claim_failure_codes": [],
        "duplicate_region_ids": [],
        "table_cardinality_mismatch": False,
        "table_failure_codes": [],
        "table_header_failure_ids": [],
        "chart_failure_codes": [],
        "process_failure_codes": [],
        "material_unresolved_required_ids": [],
        "material_unresolved_observed_ids": [],
        "noncritical_semantic_source_binding_failure": False,
    }
    unit_semantic = {
        "coverage": 1.0, "numeric_fidelity": 1.0, "modality": 1.0,
        "table_cell_fidelity": 1.0, "visual_relation_recall": 1.0,
        "critical_axis_minimum_diagnostic": 1.0,
        "noncritical_semantic_observations": [], "noncritical_semantic_required_count": 0,
        "noncritical_semantic_correct_count": 0, "noncritical_semantic_equivalence": 1.0,
        "critical_failures": ([code] if code else []),
        "hard_gate_evidence": gate_evidence, "unresolved_ids": [], "unresolved_count": 0,
        "material_unresolved_required_ids": [], "material_unresolved_observed_ids": [],
        "material_unresolved_false_negative_ids": [], "unresolved_false_positive_ids": [],
        "material_unresolved_recall": 1.0, "unresolved_precision": 1.0,
    }
    media_trace = {
        "required_context_image_read": True, "required_crop_recall": 1.0,
        "media_sequence_valid": True, "submit_observed": True,
        "items": [{"id": "context_image", "read_observed": True, "read_before_submit": True}],
    }
    semantic = {
        "coverage": 1.0, "numeric_fidelity": 1.0, "modality": 1.0,
        "table_cell_fidelity": 1.0, "visual_relation_recall": 1.0,
        "critical_axis_minimum_diagnostic": 1.0,
        "noncritical_semantic_assertion_ids": [], "noncritical_semantic_observations": [],
        "noncritical_semantic_required_count": 0, "noncritical_semantic_correct_count": 0,
        "noncritical_semantic_equivalence": 1.0, "critical_failures": ([code] if code else []),
        "inconsistent_alternate_count": 0, "term_consistency_recall": 1.0,
        "unresolved_region_rate": 0.0, "unexpected_unresolved_rate": 0.0,
        "material_unresolved_required_count": 0, "material_unresolved_true_positive_count": 0,
        "unresolved_observed_count": 0, "unresolved_false_positive_count": 0,
        "material_unresolved_recall": 1.0, "unresolved_precision": 1.0,
    }
    return {
        "scenario_id": scenario_id, "case_identity_sha256": item_identity, "category": category,
        "split": split, "format": "png", "repeat": repeat, "subject_git_sha": subject,
        "deployment_fingerprint": deployment, "effective_model": "google/gemma-4-31b-it",
        "semantic_scored": True, "quality_metrics_authoritative": True, "engine_gate": "PASS",
        "status": "PASS", "semantic": semantic,
        "units": [{"work_unit_id": "u1", "semantic": unit_semantic}],
        "work_unit_contract": {"pass": True, "failures": [], "work_unit_states": {"u1": "VERIFIED"}},
        "persisted_execution": {
            "available": True, "run_phase": "COMPLETE", "run_complete": True,
            "false_done_recovery_violation": False, "verification_contract_failure": False,
            "reported_run_complete": True, "verification_status": "PASS", "verification_critical_count": 0,
            "work_unit_states": {"u1": "VERIFIED"}, "material_unresolved_required_count": 0,
            "material_unresolved_recall": 1.0, "unresolved_precision": 1.0,
            "conflict_assessment_status": "NOT_REQUIRED", "conflict_count": 0,
            "unresolved_conflict_count": 0, "conflict_failure_codes": [],
            "conflict_resolution_failure": False, "execution_contract_pass": True,
        },
        "model_identity": {"requested_model": "google/gemma-4-31b-it", "effective_model": "google/gemma-4-31b-it", "proven": True, "approved": True, "mixed": False, "executed": True},
        "media_by_work_unit": {"u1": {"required_context_image_read": True, "required_count": 1, "read_count": 1, "required_crop_recall": 1.0, "media_sequence_valid": True}},
        "opencode": {
            "status": "PASS", "mode": "quality", "model": "google/gemma-4-31b-it", "kslide_complete": True,
            "runtime_version": "1.3.9", "event_count": 2, "tool_call_count": 0, "tool_calls": [],
            "forbidden_attempt_count": 0, "forbidden_attempts": [],
            "media_compliance": {"planned": True, "required_count": 1, "read_count": 1,
                "required_context_image_read": True, "required_crop_recall": 1.0,
                "media_sequence_valid": True, "work_units": {"u1": media_trace}},
            "diagnostics": {"effective_model": "google/gemma-4-31b-it", "model_identity_proven": True,
                "mixed_effective_model_ids": False, "read_policy_violation_count": 0},
        },
        "quality_policy": policy_identity_record(), "quality_policy_identity": QUALITY_POLICY_IDENTITY,
    }


def _model_sources(root: Path, split: str = "validation", critical: int = 0, repeats: int = 3, *, subject: str = "a" * 40, deployment: str = "b" * 64, evidence_type: str | None = None) -> dict[str, Path]:
    rows = []
    frozen = scenario_specs()
    evidence_type = evidence_type or ("model_held_out" if split == "held_out" else "model_high_risk_stability" if repeats >= 4 else "model_validation")
    high_risk = evidence_type == "model_high_risk_stability"
    if high_risk:
        selected = []
        for category in PROTECTED_CATEGORIES:
            selected.append(next(item for item in frozen if item.category == category and item.split == split))
    else:
        selected = [item for item in frozen if item.split == split]
    target_role = {
        "model_validation": "private_representative",
        "model_high_risk_stability": "frozen_high_risk",
        "model_held_out": "sealed_held_out",
    }[evidence_type]
    scenario_to_item_id = {
        item.scenario_id: f"fixture-{target_role}-{hashlib.sha256(item.scenario_id.encode()).hexdigest()[:16]}"
        for item in selected
    }
    scenario_ids = [scenario_to_item_id[item.scenario_id] for item in selected]
    corpus_manifests, corpus_set_identity, evaluation_purpose = _test_corpus_manifests(evidence_type, scenario_ids)
    selected_manifest = next(item for item in corpus_manifests if item["role"] == corpus_set_identity["role"])
    formats = ["png"]
    manifest_items = {item["item_id"]: item for item in selected_manifest["items"]}
    case_matrix = []
    for scenario in selected:
        member = manifest_items[scenario_to_item_id[scenario.scenario_id]]
        case_matrix.append({
            "item_id": scenario_to_item_id[scenario.scenario_id],
            "category": scenario.category,
            "protected_group": scenario.category if high_risk else None,
            "split": split,
            "source_sha256": member["source_sha256"],
            "gold_sha256": member["gold_sha256"],
            "gold_contract_sha256": hashlib.sha256(f"test-only-governed-gold:{evidence_type}:{scenario.scenario_id}".encode()).hexdigest(),
            "noncritical_semantic_assertion_ids": [],
            "formats": formats,
        })
    case_matrix.sort(key=lambda item: item["item_id"])
    descriptor_identity = {
        "schema_version": "1.0",
        "role": corpus_set_identity["role"],
        "set_id": corpus_set_identity["set_id"],
        "version": corpus_set_identity["version"],
        "manifest_fingerprint": corpus_set_identity["manifest_fingerprint"],
        "case_matrix_sha256": case_matrix_fingerprint(case_matrix),
    }
    for scenario_index, scenario in enumerate(selected):
        for repeat in range(1, repeats + 1):
            item_id = scenario_to_item_id[scenario.scenario_id]
            matrix_item = next(item for item in case_matrix if item["item_id"] == item_id)
            rows.append(_model_result_row(
                scenario_id=item_id, category=scenario.category, split=split, repeat=repeat,
                item_identity=case_matrix_item_fingerprint(matrix_item), subject=subject,
                deployment=deployment, critical=bool(critical and scenario_index == 0 and repeat == 1),
            ))
    behavior = {"model": "google/gemma-4-31b-it", "ocr_provider": "none", "prompt_version": "test-v1", "generation_settings": {"temperature": 0}}
    behavior_hash = behavior_configuration_hash(behavior)
    categories = list(PROTECTED_CATEGORIES) if high_risk else []
    plan = experiment_plan(split=split, scenario_ids=scenario_ids, formats=formats, repetitions=repeats, categories=categories, timeout=180, mode="quality")
    plan_hash = experiment_plan_hash(plan)
    corpus_identity = {"schema_version": "1.0", "sets": [manifest_identity(item) for item in corpus_manifests]}
    corpus_fingerprint = corpus_identity_fingerprint(corpus_identity)
    held_out_fingerprint = corpus_set_identity["manifest_fingerprint"] if evidence_type == "model_held_out" else None
    expected_matrix = [(scenario_id, format_name, repeat) for scenario_id in scenario_ids for format_name in formats for repeat in range(1, repeats + 1)]
    summary = aggregate_model_results(rows, model="google/gemma-4-31b-it", split=split, expected_matrix=expected_matrix)
    summary.update({"model": "google/gemma-4-31b-it", "requested_model": "google/gemma-4-31b-it", "effective_model": "google/gemma-4-31b-it", "locked_terminology_recall": 1.0, "required_media_compliance": True, "case_count": len(rows), "semantic_scored_case_count": len(rows), "repetitions": repeats, "subject_git_sha": subject, "deployment_fingerprint": deployment, "behavior_configuration_hash": behavior_hash, "configuration_hash": behavior_hash, "experiment_plan_hash": plan_hash, "corpus_fingerprint": corpus_fingerprint, "held_out_fingerprint": held_out_fingerprint, "corpus_set_identity": corpus_set_identity, "evaluation_purpose": evaluation_purpose, "case_matrix_sha256": case_matrix_fingerprint(case_matrix), "case_descriptor_identity": descriptor_identity})
    (root / "results.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    _write(root / "summary.json", summary)
    experiment = {"model": "google/gemma-4-31b-it", "effective_model": "google/gemma-4-31b-it", "split": split, "repetitions": repeats, "scenario_ids": scenario_ids, "formats": formats, "categories": categories, "configuration": behavior, "behavior_configuration": behavior, "behavior_configuration_hash": behavior_hash, "configuration_hash": behavior_hash, "experiment_plan": plan, "experiment_plan_hash": plan_hash, "subject_git_sha": subject, "deployment_fingerprint": deployment, "corpus_fingerprint": summary["corpus_fingerprint"], "held_out_fingerprint": summary["held_out_fingerprint"], "corpus_set_identity": corpus_set_identity, "corpus_manifest": selected_manifest, "governed_corpus_manifests": corpus_manifests, "evaluation_purpose": evaluation_purpose, "case_matrix": case_matrix, "case_matrix_sha256": summary["case_matrix_sha256"], "case_descriptor_identity": descriptor_identity, "quality_policy": policy_identity_record(), "quality_policy_identity": QUALITY_POLICY_IDENTITY}
    if evidence_type == "model_held_out":
        experiment["contamination_report"] = {"schema_version": "1.0", "set_id": corpus_set_identity["set_id"], "version": corpus_set_identity["version"], "items": []}
    if high_risk:
        experiment["high_risk_categories"] = list(PROTECTED_CATEGORIES)
    _write(root / "experiment.json", experiment)
    return {"model_summary": root / "summary.json", "experiment_manifest": root / "experiment.json", "results_jsonl": root / "results.jsonl"}


def _security_sources(root: Path, *, vulnerable: bool = False, constraints_hash: str = "c" * 64) -> dict[str, Path]:
    packages = [{"name": name, "version": "1.0"} for name in ("Pillow", "PyMuPDF", "python-pptx", "paddlepaddle", "paddleocr")]
    inventory = canonical_dependency_inventory(packages)
    _write(root / "dependency-inventory.json", inventory)
    (root / "production-requirements.lock").write_text(dependency_lock_text(inventory), encoding="utf-8")
    build_production_sbom(root, root / "production-sbom.json", inventory_path=root / "dependency-inventory.json")
    validate_cyclonedx_1_5(json.loads((root / "production-sbom.json").read_text(encoding="utf-8")))
    _write(root / "pip-audit.json", {"dependencies": [{"name": name, "version": "1.0", "vulns": ([{"id": "CVE-TEST"}] if vulnerable and name == "Pillow" else [])} for name in ("Pillow", "PyMuPDF", "python-pptx", "paddlepaddle", "paddleocr")]})
    _write(root / "gitleaks.json", [])
    _write(root / "semgrep.json", {"results": [], "errors": []})
    _write(root / "scanner-exits.json", {"pip_audit": 0, "gitleaks": 0, "semgrep": 0})
    versions = {"Pillow": "1.0", "PyMuPDF": "1.0", "python-pptx": "1.0", "paddlepaddle": "1.0", "paddleocr": "1.0"}
    ruleset = Path.cwd() / "security" / "semgrep-production.yml"
    ruleset_hash = _sha(ruleset) if ruleset.is_file() else "a" * 64
    staged_ruleset = root / "semgrep-production.yml"
    if ruleset.is_file():
        staged_ruleset.write_bytes(ruleset.read_bytes())
    else:
        staged_ruleset.write_text("rules: []\n", encoding="utf-8")
    inventory_sha = dependency_inventory_hash(inventory)
    _write(root / "audit-context.json", {"schema_version": "1.0", "audited_dependency_subject": "production-env", "audited_dependency_set_sha256": inventory_sha, "resolved_dependency_set_sha256": inventory_sha, "resolved_dependency_lock_sha256": _sha(root / "production-requirements.lock"), "production_sbom_sha256": _sha(root / "production-sbom.json"), "candidate_constraints_sha256": constraints_hash, "audited_dependency_names": list(versions), "constraint_versions": versions, "pip_audit_version": "pip-audit 2.9.0", "semgrep_version": "semgrep 1.89.0", "semgrep_ruleset_identity": "security/semgrep-production.yml", "semgrep_ruleset_sha256": ruleset_hash})
    return {"pip_audit": root / "pip-audit.json", "gitleaks": root / "gitleaks.json", "semgrep": root / "semgrep.json", "scanner_exits": root / "scanner-exits.json", "audit_context": root / "audit-context.json", "semgrep_ruleset": staged_ruleset, "dependency_inventory": root / "dependency-inventory.json", "production_lock": root / "production-requirements.lock", "production_sbom": root / "production-sbom.json"}


def _reliability_sources(root: Path) -> dict[str, Path]:
    _write(root / "failure.json", {"status": "PASS", "timeout_recovery_pass": True, "resume_pass": True})
    _write(root / "concurrency.json", {"status": "PASS", "concurrency_pass": True, "concurrent_runs": 5})
    _write(root / "large.json", {"status": "PASS", "fifty_slide_pass": True})
    _write(root / "slo.json", {"status": "PASS", "slo_pass": True})
    return {"failure_injection": root / "failure.json", "concurrency": root / "concurrency.json", "large_deck": root / "large.json", "performance_slo": root / "slo.json"}


def _candidate_spec(subject: str, *, ocr_provider: str = "none", effective_model: str = "google/gemma-4-31b-it", asset_manifest: str = "UNSET", asset_hash: str = "UNSET", root: Path | None = None) -> dict[str, object]:
    target = "google/gemma-4-31b-it"
    behavior = {
        "model": target,
        "ocr_provider": ocr_provider,
        "prompt_version": "translation/v1",
        "generation_settings": {"temperature": 0.1},
        "normalization_behavior": {"render_dpi": 220},
        "repair_policy": {"max_auto_repairs_per_unit": 2},
    }
    endpoint_identity = opencode_route_identity(provider_id="google", model_id="gemma-4-31b-it", api_id="gemma-4-31b-it", api_npm="@ai-sdk/google", api_url="https://generativelanguage.googleapis.com/v1beta")
    egress_capabilities = [
        {"capability_class": EGRESS_CAPABILITY_INFERENCE_ROUTE, "purpose": "model_inference", "service_identity": "test-inference-service", "route_identity": "test-inference-route", "endpoint_identity": endpoint_identity, "data_class": "source_content"},
        {"capability_class": EGRESS_CAPABILITY_DURABLE_JOB_CONTROL, "purpose": "job_control", "service_identity": "test-job-service", "route_identity": None, "endpoint_identity": None, "data_class": "operational_metadata"},
        {"capability_class": EGRESS_CAPABILITY_SCOPED_STORAGE, "purpose": "scoped_storage", "service_identity": "test-storage-service", "route_identity": None, "endpoint_identity": None, "data_class": "source_content"},
        {"capability_class": EGRESS_CAPABILITY_NON_CONTENT_TELEMETRY, "purpose": "non_content_telemetry", "service_identity": "test-telemetry-service", "route_identity": None, "endpoint_identity": None, "data_class": EGRESS_DATA_CLASS_NON_CONTENT},
    ]
    egress_version = "test-1"
    egress_hash = egress_policy_hash_for_mapping(policy_version=egress_version, capabilities=egress_capabilities)
    egress_policy = {
        "schema_version": "1.0",
        "policy_version": egress_version,
        "policy_hash": egress_hash,
        "policy_identity": egress_policy_identity_for_mapping(policy_version=egress_version, policy_hash=egress_hash),
        "default_action": "deny",
        "capabilities": egress_capabilities,
    }
    if root is not None and (root / ".k-slide-config").is_dir():
        config = root / ".k-slide-config"
        _write(config / "egress-policy.json", egress_policy)
    candidate = {
        "candidate_spec_version": "1.1",
        "subject_git_sha": subject,
        "kslide_version": "0.3.5",
        "opencode_version": "1.3.9",
        "requested_model": target,
        "effective_model": effective_model,
        "provider": "google",
        "provider_backend": NOT_EXPOSED_VALUE,
        "model_revision": NOT_EXPOSED_VALUE,
        "quantization_or_dtype": NOT_EXPOSED_VALUE,
        "vision_settings": {"enabled": True},
        "context_configuration": {"bounded_work_unit": True},
        "image_preprocessing_settings": {"dpi": 220},
        "prompt_identity": {"version": "translation/v1", "hash": "UNSET"},
        "generation_settings": {"temperature": 0.1},
        "ocr_provider": ocr_provider,
        "ocr_asset_manifest": asset_manifest,
        "ocr_asset_manifest_sha256": asset_hash,
        "normalization_behavior": {"render_dpi": 220},
        "repair_policy": {"max_auto_repairs_per_unit": 2},
        "python_version": TEST_PYTHON_VERSION,
        "paddle_version": "3.0.0",
        "paddleocr_version": "3.0.3",
        "libreoffice_version": "25.2.3",
        "termbase_identity": {"version": "1.0", "hash": "UNSET"},
        "termbase_version": "1.0",
        "termbase_hash": "UNSET",
        "model_policy": load_model_policy().as_dict(),
        "schema_versions": {"evidence_ir": "1.0", "translation_patch": "1.0", "slide_ir": "1.0"},
        "retention_policy": {"schema_version": "1.0", "content_retention_days": 30, "operational_metadata_retention_days": 60},
        "tenant_isolation": "workspace_per_session",
        "network_egress": "default_deny",
        "corpus_identity": {"schema_version": "1.0", "sets": [manifest_identity(item) for item in _test_corpus_manifests("model_validation", [scenario.scenario_id for scenario in scenario_specs() if scenario.split == "validation"])[0]]},
        "constraints_sha256": "UNSET",
        "behavior_configuration": behavior,
    }
    if root is not None:
        candidate.update({
            "egress_policy_version": egress_version,
            "egress_policy_hash": egress_hash,
            "egress_policy_identity": egress_policy["policy_identity"],
            "inference_route_identity": "test-inference-route",
            "inference_endpoint_identity": endpoint_identity,
        })
    return resolve_candidate_spec(candidate, root=root or Path.cwd(), subject_git_sha=subject, model_policy=load_model_policy(), corpus=candidate["corpus_identity"])  # type: ignore[arg-type]


def _candidate_model_sources(root: Path, *, split: str, repeats: int, subject: str, deployment: str, candidate: dict[str, object]) -> dict[str, Path]:
    sources = _model_sources(root, split=split, repeats=repeats, subject=subject, deployment=deployment)
    behavior = candidate["behavior_configuration"]
    behavior_hash = behavior_configuration_hash(behavior)  # type: ignore[arg-type]
    factors = canonical_candidate_factors(candidate)  # type: ignore[arg-type]
    summary_path = sources["model_summary"]
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary.update({"candidate_spec": factors, "effective_model": candidate["effective_model"], "behavior_configuration_hash": behavior_hash, "configuration_hash": behavior_hash})
    _write(summary_path, summary)
    experiment_path = sources["experiment_manifest"]
    experiment = json.loads(experiment_path.read_text(encoding="utf-8"))
    experiment.update({"candidate_spec": factors, "candidate_identity_status": "FINAL", "effective_model": candidate["effective_model"], "behavior_configuration": behavior, "configuration": behavior, "behavior_configuration_hash": behavior_hash, "configuration_hash": behavior_hash, "execution_runtime_provenance": {"opencode_version": candidate["opencode_version"], "provider": candidate["provider"], "ocr_provider": candidate["ocr_provider"]}})
    _write(experiment_path, experiment)
    rows_path = sources["results_jsonl"]
    rows = [json.loads(line) for line in rows_path.read_text(encoding="utf-8").splitlines()]
    for row in rows:
        row.update({"subject_git_sha": subject, "deployment_fingerprint": deployment, "effective_model": candidate["effective_model"]})
    rows_path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    return sources


class CertificationClosureTests(unittest.TestCase):
    def test_repository_execution_binding_rejects_wrong_material_behavior(self):
        base = _candidate_spec("a" * 40)
        cases = (
            ("generation_settings", {"temperature": 0.2}),
            ("image_preprocessing_settings", {"dpi": 221}),
            ("vision_settings", {"enabled": False}),
            ("repair_policy", {"max_auto_repairs_per_unit": 3}),
            ("normalization_behavior", {"render_dpi": 221}),
            ("prompt_version", "translation/v2"),
            ("termbase_version", "2.0"),
        )
        for field, value in cases:
            with self.subTest(field=field):
                candidate = json.loads(json.dumps(base))
                candidate[field] = value
                if field in {"generation_settings", "repair_policy", "normalization_behavior"}:
                    candidate["behavior_configuration"][field] = value
                with self.assertRaises(EvidenceValidationError):
                    resolve_candidate_spec(candidate, root=Path.cwd(), subject_git_sha="a" * 40, model_policy=load_model_policy(), corpus=candidate["corpus_identity"], require_sources=True)
        metadata_only = json.loads(json.dumps(base))
        metadata_only["behavior_configuration"]["provider_defaults_frozen"] = True
        with self.assertRaises(EvidenceValidationError):
            resolve_candidate_spec(metadata_only, root=Path.cwd(), subject_git_sha="a" * 40, model_policy=load_model_policy(), corpus=metadata_only["corpus_identity"], require_sources=True)
        metadata_only = json.loads(json.dumps(base))
        metadata_only["behavior_configuration"]["thinking"] = True
        with self.assertRaises(EvidenceValidationError):
            resolve_candidate_spec(metadata_only, root=Path.cwd(), subject_git_sha="a" * 40, model_policy=load_model_policy(), corpus=metadata_only["corpus_identity"], require_sources=True)
        unresolved_image = json.loads(json.dumps(base))
        unresolved_image["image_preprocessing_settings"] = {"source": "not_yet_configured"}
        with self.assertRaises(EvidenceValidationError):
            resolve_candidate_spec(unresolved_image, root=Path.cwd(), subject_git_sha="a" * 40, model_policy=load_model_policy(), corpus=unresolved_image["corpus_identity"], require_sources=True)

    def test_schema_identity_is_derived_and_explicit_drift_is_rejected(self):
        candidate = _candidate_spec("a" * 40)
        candidate["schema_versions"] = {}
        resolved = resolve_candidate_spec(candidate, root=Path.cwd(), subject_git_sha="a" * 40, model_policy=load_model_policy(), corpus=candidate["corpus_identity"])
        self.assertEqual(resolved["schema_versions"], repository_schema_versions())
        for value in ({"evidence_ir": "9.0", "translation_patch": "1.0", "slide_ir": "1.0"}, {"evidence_ir": "1.0", "translation_patch": "1.0"}):
            with self.subTest(value=value), self.assertRaises(EvidenceValidationError):
                resolve_candidate_spec({**candidate, "schema_versions": value}, root=Path.cwd(), subject_git_sha="a" * 40, model_policy=load_model_policy(), corpus=candidate["corpus_identity"])

    def test_effective_termbase_identity_includes_private_semantics_and_is_path_independent(self):
        core = {"version": "1.0", "records": [{"term_id": "core", "source": "검토", "preferred": {"default": "under review"}, "status": "PREFERRED", "scope": ["modality"]}]}
        overlay = {"version": "1.0", "records": [{"term_id": "private", "source": "고도화", "preferred": {"default": "enhancement"}, "status": "LOCKED", "scope": ["corporate"]}]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "termbase").mkdir()
            _write(root / "termbase" / "core.json", core)
            (root / "termbase" / "overlays").mkdir()
            overlay_path = root / "termbase" / "overlays" / "corporate.json"
            _write(overlay_path, overlay)
            authority = {
                "governance_identity": "test-governance-v1",
                "policy_identity": "test-policy-v1",
                "authorization_identity": "test-authority-v1",
                "core": {"identity": "core-test-v1", "version": "1.0", "sha256": _sha(root / "termbase" / "core.json"), "path": "termbase/core.json"},
                "overlays": [{"identity": "corporate-test-v1", "version": "1.0", "sha256": _sha(overlay_path), "path": "termbase/overlays/corporate.json", "scope": "BU", "scope_ref": "corporate", "authorization_identity": "corporate-authority-v1"}],
                "overlay_order": ["corporate-test-v1"],
                "order_identity": "single",
            }
            first = effective_termbase_identity(root, termbase_authority=authority)
            self.assertIsNotNone(first)
            moved = root / "moved"
            (moved / "termbase").mkdir(parents=True)
            _write(moved / "termbase" / "core.json", core)
            (moved / "termbase" / "overlays").mkdir()
            _write(moved / "termbase" / "overlays" / "corporate.json", overlay)
            self.assertEqual(first, effective_termbase_identity(moved, termbase_authority=authority))
            overlay["records"][0]["preferred"]["default"] = "upgrade"
            _write(overlay_path, overlay)
            authority["overlays"][0]["sha256"] = _sha(overlay_path)
            changed = effective_termbase_identity(root, termbase_authority=authority)
            self.assertNotEqual(first, changed)
            overlay["records"][0]["status"] = "PREFERRED"
            _write(overlay_path, overlay)
            authority["overlays"][0]["sha256"] = _sha(overlay_path)
            self.assertNotEqual(changed, effective_termbase_identity(root, termbase_authority=authority))
            overlay_path.unlink()
            with self.assertRaises(EvidenceValidationError):
                effective_termbase_identity(root, termbase_authority=authority)
            conflicting = {"version": "1.0", "records": [{"source": "검토", "preferred": {"default": "review"}, "status": "LOCKED"}]}
            _write(overlay_path, conflicting)
            authority["overlays"][0]["sha256"] = _sha(overlay_path)
            _write(root / "termbase" / "core.json", {**core, "records": [{**core["records"][0], "status": "LOCKED"}]})
            authority["core"]["sha256"] = _sha(root / "termbase" / "core.json")
            with self.assertRaises(EvidenceValidationError):
                effective_termbase_identity(root, termbase_authority=authority)

    def test_effective_termbase_hash_is_bound_by_candidate_resolution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "termbase").mkdir()
            (root / "termbase" / "core.json").write_bytes((Path.cwd() / "termbase" / "core.json").read_bytes())
            candidate = _candidate_spec("a" * 40, root=root)
            before = effective_termbase_identity(root)
            self.assertEqual(candidate["termbase_hash"], before["hash"])
            (root / ".k-slide-config").mkdir()
            _write(root / ".k-slide-config" / "termbase.local.json", {"version": "1.0", "records": [{"source": "비공개", "preferred": {"default": "private"}, "status": "PREFERRED"}]})
            with self.assertRaises(EvidenceValidationError):
                effective_termbase_identity(root)
            candidate["termbase_hash"] = "a" * 64
            with self.assertRaises(EvidenceValidationError):
                resolve_candidate_spec(candidate, root=root, subject_git_sha="a" * 40, model_policy=load_model_policy(), corpus=candidate["corpus_identity"])

    def test_production_completeness_rejects_unset_fields_even_with_valid_shape(self):
        candidate = _candidate_spec("a" * 40, ocr_provider="paddle")
        candidate.update({
            "egress_policy_version": "test-1",
            "egress_policy_hash": "a" * 64,
            "egress_policy_identity": "b" * 64,
            "inference_endpoint_identity": "c" * 64,
        })
        candidate["ocr_asset_manifest"] = "ocr/manifest.json"
        candidate["ocr_asset_manifest_sha256"] = "a" * 64
        candidate["resolved_dependency_set_sha256"] = "b" * 64
        candidate["behavior_configuration"]["ocr_provider"] = "paddle"
        self.assertEqual(candidate_completeness(candidate, "PRODUCTION_CERTIFIED"), [])
        for field in ("opencode_version", "effective_model", "paddle_version", "paddleocr_version", "libreoffice_version", "prompt_identity", "termbase_hash", "constraints_sha256", "resolved_dependency_set_sha256"):
            mutated = json.loads(json.dumps(candidate))
            if field == "prompt_identity":
                mutated[field]["hash"] = "UNSET"
            else:
                mutated[field] = "UNSET"
            self.assertIn(field, candidate_completeness(mutated, "PRODUCTION_CERTIFIED"), field)

    def test_exact_runtime_versions_and_libreoffice_parser(self):
        from k_slide.certification import canonical_exact_version, parse_libreoffice_version

        with self.assertRaises(EvidenceValidationError):
            canonical_exact_version("3.11", "python_version")
        self.assertEqual(canonical_exact_version(TEST_PYTHON_VERSION, "python_version"), TEST_PYTHON_VERSION)
        self.assertEqual(parse_libreoffice_version("LibreOffice 25.2.3.1 40(Build:1)"), "25.2.3.1")
        self.assertIsNone(parse_libreoffice_version("LibreOffice 25.2"))
        from k_slide.runtime import _version as runtime_version
        with patch("k_slide.runtime.subprocess.run", return_value=SimpleNamespace(returncode=0, stdout="OpenCode 1.3.9.1\n", stderr="")):
            runtime_version.cache_clear()
            self.assertEqual(runtime_version("/usr/bin/opencode"), "1.3.9.1")
            runtime_version.cache_clear()

    def test_security_binds_inventory_sbom_and_production_subject(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _security_sources(root)
            evidence = root / "security.json"
            build_machine_evidence(evidence, evidence_type="security", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources)
            self.assertEqual(load_evidence(evidence, expected_type="security")["payload"]["resolved_dependency_set_sha256"], dependency_inventory_hash(json.loads((root / "dependency-inventory.json").read_text(encoding="utf-8"))))
            inventory = json.loads((root / "dependency-inventory.json").read_text(encoding="utf-8"))
            inventory["packages"][0]["version"] = "2.0"
            _write(root / "dependency-inventory.json", inventory)
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "changed-inventory.json", evidence_type="security", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources)
            sources = _security_sources(root)
            sbom = json.loads((root / "production-sbom.json").read_text(encoding="utf-8"))
            sbom["components"][0]["version"] = "2.0"
            _write(root / "production-sbom.json", sbom)
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "changed-sbom.json", evidence_type="security", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources)
            sources = _security_sources(root)
            context = json.loads((root / "audit-context.json").read_text(encoding="utf-8"))
            context["audited_dependency_subject"] = "scanner-environment"
            _write(root / "audit-context.json", context)
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "scanner-only.json", evidence_type="security", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources)
            context["audited_dependency_subject"] = "runner-environment"
            _write(root / "audit-context.json", context)
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "runner-only.json", evidence_type="security", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources)

    def test_security_workflow_layout_is_portable_and_all_sources_are_reverified(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            sources = _security_sources(root)
            evidence = root / "security.evidence.json"
            build_machine_evidence(evidence, evidence_type="security", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources)
            loaded = load_evidence(evidence, expected_type="security", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64)
            self.assertEqual(loaded["payload"]["resolved_dependency_lock_sha256"], _sha(root / "production-requirements.lock"))
            self.assertEqual(load_dependency_lock(root / "production-requirements.lock")["packages"], json.loads((root / "dependency-inventory.json").read_text(encoding="utf-8"))["packages"])
            outside = root.parent / "outside.json"
            outside.write_text((root / "production-requirements.lock").read_text(encoding="utf-8"), encoding="utf-8")
            unsafe = dict(sources)
            unsafe["production_lock"] = outside
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "unsafe.json", evidence_type="security", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=unsafe)

    def test_reloaded_evidence_rejects_symlinked_source_even_inside_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            evidence = root / "security.evidence.json"
            build_machine_evidence(evidence, evidence_type="security", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=_security_sources(root))
            source = root / "production-lock-link"
            source.symlink_to(root / "production-requirements.lock")
            value = json.loads(evidence.read_text(encoding="utf-8"))
            for item in value["sources"]:
                if item["role"] == "production_lock":
                    item["path"] = source.name
            evidence.write_text(json.dumps(value) + "\n", encoding="utf-8")
            with self.assertRaises(EvidenceValidationError):
                load_evidence(evidence, expected_type="security")

    def test_security_rejects_empty_audit_lock_drift_and_nonstandard_sbom(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _security_sources(root)
            _write(root / "pip-audit.json", {"dependencies": []})
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "empty-audit.json", evidence_type="security", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources)
            sources = _security_sources(root)
            _write(root / "scanner-exits.json", {"pip_audit": 0, "gitleaks": 0, "semgrep": 0, "unexpected": 0})
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "extra-exit.json", evidence_type="security", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources)
            sources = _security_sources(root)
            (root / "production-requirements.lock").write_text("Pillow==2.0\n", encoding="utf-8")
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "lock-drift.json", evidence_type="security", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources)
            sources = _security_sources(root)
            sbom = json.loads((root / "production-sbom.json").read_text(encoding="utf-8"))
            sbom["complete"] = True
            _write(root / "production-sbom.json", sbom)
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "invalid-sbom.json", evidence_type="security", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources)

    def test_dependency_inventory_rejects_scanner_environment_tools(self):
        with self.assertRaises(EvidenceValidationError):
            canonical_dependency_inventory([{"name": "pip-audit", "version": "2.9.0"}, {"name": "semgrep", "version": "1.89.0"}, {"name": "Pillow", "version": "1.0"}])
        inventory = canonical_dependency_inventory([{"name": "pip", "version": "24.0"}, {"name": "setuptools", "version": "70.0"}, {"name": "Pillow", "version": "1.0"}])
        self.assertEqual(inventory["packages"], [{"name": "pillow", "version": "1.0"}])

    def test_security_subject_binding_reconciles_safe_venv_tools_but_keeps_them_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _security_sources(root)
            audit = json.loads((root / "pip-audit.json").read_text(encoding="utf-8"))
            audit["dependencies"].extend([
                {"name": "pip", "version": "26.2.1", "vulns": []},
                {"name": "setuptools", "version": "83.0.0", "vulns": []},
            ])
            _write(root / "pip-audit.json", audit)
            build_machine_evidence(root / "safe-base-tools.json", evidence_type="security", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources)
            audit["dependencies"][-2]["vulns"] = [{"id": "PYSEC-TEST-BASE-TOOL"}]
            _write(root / "pip-audit.json", audit)
            with self.assertRaises(AdapterError):
                enforce_security_scanners({key: sources[key] for key in ("pip_audit", "gitleaks", "semgrep", "scanner_exits")})

    def test_security_constraints_identity_mismatch_is_rejected(self):
        candidate = _candidate_spec("a" * 40)
        deployment = candidate_deployment_fingerprint(candidate)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _security_sources(root, constraints_hash=str(candidate["constraints_sha256"]))
            context = json.loads((root / "audit-context.json").read_text(encoding="utf-8"))
            context["candidate_constraints_sha256"] = "d" * 64
            _write(root / "audit-context.json", context)
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "security.json", evidence_type="security", subject_git_sha="a" * 40, deployment_fingerprint=deployment, sources=sources, candidate_spec=candidate)

    def test_candidate_completeness_resolves_repository_inputs_and_keeps_states_practical(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "prompts").mkdir()
            (root / "prompts" / "system.txt").write_text("prompt-v1\n", encoding="utf-8")
            (root / "termbase").mkdir()
            (root / "termbase" / "terms.json").write_text("{}\n", encoding="utf-8")
            (root / "constraints-production.txt").write_bytes((Path.cwd() / "constraints-production.txt").read_bytes())
            candidate = {
                "subject_git_sha": "a" * 40,
                "kslide_version": "UNSET",
                "opencode_version": "1.0.0",
                "prompt_identity": {"hash": "UNSET"},
                "termbase_identity": {"hash": "UNSET"},
                "termbase_hash": "UNSET",
                "constraints_sha256": "UNSET",
                "model_policy": {},
                "corpus_identity": {},
            }
            from k_slide.certification import resolve_candidate_spec
            resolved = resolve_candidate_spec(candidate, root=root, subject_git_sha=candidate["subject_git_sha"], model_policy=load_model_policy(), corpus={"version": "v1", "corpus_fingerprint": "c" * 64, "held_out_fingerprint": "d" * 64})
            self.assertNotEqual(resolved["prompt_identity"]["hash"], "UNSET")
            self.assertNotEqual(resolved["termbase_identity"]["hash"], "UNSET")
            self.assertEqual(resolved["constraints_sha256"], _sha(root / "constraints-production.txt"))
            self.assertEqual(candidate_completeness(resolved, "RUNTIME_READY"), [])
            self.assertIn("effective_model", candidate_completeness(resolved, "SYNTHETIC_PRODUCTION_CANDIDATE"))
            mismatched = {**candidate, "constraints_sha256": "a" * 64}
            with self.assertRaises(EvidenceValidationError):
                resolve_candidate_spec(mismatched, root=root, subject_git_sha=candidate["subject_git_sha"], model_policy=load_model_policy(), corpus={"version": "v1", "corpus_fingerprint": "c" * 64, "held_out_fingerprint": "d" * 64})
            resolved.update({"provider_backend": NOT_EXPOSED_VALUE, "model_revision": NOT_APPLICABLE_VALUE, "quantization_or_dtype": NOT_EXPOSED_VALUE})
            self.assertNotIn("provider_backend", candidate_completeness(resolved, "PRODUCTION_CERTIFIED"))

    def test_incomplete_candidate_blocks_before_certified_manifest_for_each_required_field(self):
        production_fields = ("opencode_version", "effective_model", "paddle_version", "libreoffice_version", "constraints_sha256", "ocr_asset_manifest_sha256", "prompt_identity", "termbase_hash")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "manifest.json").write_text("{}\n", encoding="utf-8")
            base = _candidate_spec("a" * 40, ocr_provider="paddle", asset_manifest="manifest.json", asset_hash=_sha(root / "manifest.json"), root=root)
            for field in production_fields:
                candidate = json.loads(json.dumps(base))
                if field == "prompt_identity":
                    candidate[field]["hash"] = "UNSET"
                else:
                    candidate[field] = "UNSET"
                candidate_path = root / f"candidate-{field}.json"
                _write(candidate_path, candidate)
                output = root / f"release-{field}.json"
                profile = root / f"profile-{field}.json"
                result = release_main(["--root", str(root), "--output", str(output), "--requested-state", "PRODUCTION_CERTIFIED", "--candidate-profile", str(candidate_path), "--certified-profile-output", str(profile)])
                self.assertEqual(result, 2, field)
                self.assertFalse(output.exists(), field)
                self.assertFalse(profile.exists(), field)

    def test_machine_evidence_is_derived_and_exactly_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _runtime_sources(root)
            envelope = root / "runtime.evidence.json"
            build_machine_evidence(envelope, evidence_type="runtime", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources)
            loaded = load_evidence(envelope, expected_type="runtime", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64)
            self.assertEqual(loaded["evidence_type"], "runtime")
            self.assertEqual(len(loaded["sources"]), 4)
            with self.assertRaises(EvidenceValidationError):
                load_evidence(envelope, expected_type="heavy_runtime", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64)

    def test_contradictory_machine_payload_fails_even_with_correct_source_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            envelope = root / "runtime.evidence.json"
            build_machine_evidence(envelope, evidence_type="runtime", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=_runtime_sources(root))
            value = json.loads(envelope.read_text(encoding="utf-8"))
            value["payload"]["runtime_pass"] = False
            envelope.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(EvidenceValidationError):
                load_evidence(envelope, expected_type="runtime", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64)

    def test_result_tamper_and_envelope_tamper_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            envelope = root / "runtime.evidence.json"
            build_machine_evidence(envelope, evidence_type="runtime", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=_runtime_sources(root))
            (root / "simple.json").write_text("{}", encoding="utf-8")
            with self.assertRaises(EvidenceValidationError):
                load_evidence(envelope, expected_type="runtime", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64)
            build_machine_evidence(envelope, evidence_type="runtime", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=_runtime_sources(root))
            value = json.loads(envelope.read_text(encoding="utf-8"))
            value["payload"]["five_slide_pass"] = False
            envelope.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(EvidenceValidationError):
                load_evidence(envelope, expected_type="runtime", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64)

    def test_wrong_result_type_and_missing_sources_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "runtime.json", evidence_type="runtime", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources={"model_summary": root / "missing"})

    def test_heavy_evidence_requires_networkless_and_representation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "heavy.json"
            build_machine_evidence(path, evidence_type="heavy_runtime", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=_heavy_sources(root))
            self.assertTrue(load_evidence(path, expected_type="heavy_runtime")["payload"]["networkless_pass"])

    def test_model_validation_rejects_critical_result(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "validation.json", evidence_type="model_validation", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=_model_sources(root, critical=1), root=Path.cwd())

    def test_model_validation_rejects_wrong_split_and_non_target_model(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "wrong-split.json", evidence_type="model_validation", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=_model_sources(root, split="held_out"), root=Path.cwd())
            sources = _model_sources(root)
            for path in sources.values():
                text = path.read_text(encoding="utf-8")
                path.write_text(text.replace("google/gemma-4-31b-it", "qwen/qwen3"), encoding="utf-8")
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "wrong-model.json", evidence_type="model_validation", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources, root=Path.cwd())

    def test_public_synthetic_held_out_split_cannot_be_model_held_out_evidence(self):
        from evals.scenarios import split_manifest

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _model_sources(root, split="held_out", repeats=3)
            public = public_synthetic_manifest()
            identity = manifest_identity(public)
            fingerprints = split_manifest()
            summary_path = sources["model_summary"]
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            summary.update({
                "corpus_set_identity": identity,
                "evaluation_purpose": "regression",
                "corpus_fingerprint": fingerprints["corpus_fingerprint"],
                "held_out_fingerprint": fingerprints["held_out_fingerprint"],
            })
            _write(summary_path, summary)
            experiment_path = sources["experiment_manifest"]
            experiment = json.loads(experiment_path.read_text(encoding="utf-8"))
            experiment.update({
                "corpus_set_identity": identity,
                "evaluation_purpose": "regression",
                "corpus_fingerprint": fingerprints["corpus_fingerprint"],
                "held_out_fingerprint": fingerprints["held_out_fingerprint"],
                "corpus_manifest": public,
            })
            _write(experiment_path, experiment)
            with self.assertRaises(AdapterError):
                build_machine_evidence(
                    root / "public-held-out.json",
                    evidence_type="model_held_out",
                    subject_git_sha="a" * 40,
                    deployment_fingerprint="b" * 64,
                    sources=sources,
                    root=Path.cwd(),
                )

    def test_high_risk_insufficient_repeats_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "high-risk.json", evidence_type="model_high_risk_stability", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=_model_sources(root, repeats=4), root=Path.cwd())

    def test_reliability_missing_substantive_proof_fails_closed(self):
        cases = (
            ("failure.json", "timeout_recovery_pass", None),
            ("failure.json", "resume_pass", None),
            ("concurrency.json", "concurrency_pass", None),
            ("concurrency.json", "concurrent_runs", 4),
            ("large.json", "fifty_slide_pass", None),
            ("slo.json", "slo_pass", None),
        )
        for filename, key, replacement in cases:
            with self.subTest(filename=filename, key=key), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                sources = _reliability_sources(root)
                value = json.loads((root / filename).read_text(encoding="utf-8"))
                if replacement is None:
                    value.pop(key, None)
                else:
                    value[key] = replacement
                _write(root / filename, value)
                with self.assertRaises(AdapterError):
                    build_machine_evidence(root / "reliability.json", evidence_type="reliability", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources)

    def test_reliability_false_substantive_proof_fails_closed(self):
        for filename, key in (("failure.json", "timeout_recovery_pass"), ("failure.json", "resume_pass"), ("concurrency.json", "concurrency_pass"), ("large.json", "fifty_slide_pass"), ("slo.json", "slo_pass")):
            with self.subTest(filename=filename, key=key), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                sources = _reliability_sources(root)
                value = json.loads((root / filename).read_text(encoding="utf-8"))
                value[key] = False
                _write(root / filename, value)
                with self.assertRaises(AdapterError):
                    build_machine_evidence(root / "reliability.json", evidence_type="reliability", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources)

    def test_high_risk_does_not_cherry_pick_best_format(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _model_sources(root, repeats=5)
            rows = [json.loads(line) for line in (root / "results.jsonl").read_text(encoding="utf-8").splitlines()]
            failing = dict(rows[0])
            failing["format"] = "pdf"
            failing["semantic"] = {**failing["semantic"], "critical_failures": ["CRITICAL"]}
            rows.extend([{**failing, "repeat": repeat} for repeat in range(1, 6)])
            (root / "results.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
            experiment = json.loads((root / "experiment.json").read_text(encoding="utf-8"))
            experiment["formats"] = ["png", "pdf"]
            _write(root / "experiment.json", experiment)
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "high-risk.json", evidence_type="model_high_risk_stability", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources, root=Path.cwd())

    def test_high_risk_declared_group_missing_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _model_sources(root, repeats=5)
            experiment = json.loads((root / "experiment.json").read_text(encoding="utf-8"))
            experiment["formats"] = ["png", "pdf"]
            _write(root / "experiment.json", experiment)
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "high-risk.json", evidence_type="model_high_risk_stability", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources, root=Path.cwd())

    def test_validation_and_held_out_safety_metrics_are_gated(self):
        for split, evidence_type, field, value in (
            ("validation", "model_validation", "locked_terminology_recall", 0.994),
            ("held_out", "model_held_out", "locked_terminology_recall", 0.994),
        ):
            with self.subTest(split=split, field=field), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                sources = _model_sources(root, split=split, repeats=3)
                rows = [json.loads(line) for line in (root / "results.jsonl").read_text(encoding="utf-8").splitlines()]
                for row in rows:
                    row["semantic"][field] = value
                (root / "results.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
                summary = json.loads((root / "summary.json").read_text(encoding="utf-8"))
                summary[field] = value
                _write(root / "summary.json", summary)
                with self.assertRaises(AdapterError):
                    build_machine_evidence(root / "model.json", evidence_type=evidence_type, subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources, root=Path.cwd())

    def test_unexpected_unresolved_rate_is_descriptive_above_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _model_sources(root, split="validation", repeats=3)
            rows = [json.loads(line) for line in (root / "results.jsonl").read_text(encoding="utf-8").splitlines()]
            for row in rows:
                row["semantic"]["unexpected_unresolved_rate"] = 0.01
            (root / "results.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
            summary = json.loads((root / "summary.json").read_text(encoding="utf-8"))
            summary["unexpected_unresolved_rate"] = 0.01
            _write(root / "summary.json", summary)
            path = root / "validation.json"
            build_machine_evidence(path, evidence_type="model_validation", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources, root=Path.cwd())
            self.assertAlmostEqual(load_evidence(path, expected_type="model_validation")["payload"]["unexpected_unresolved_rate"], 0.01)

    def test_validation_locked_terminology_boundary_is_inclusive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _model_sources(root, repeats=3)
            rows = [json.loads(line) for line in (root / "results.jsonl").read_text(encoding="utf-8").splitlines()]
            for row in rows:
                row["semantic"]["term_consistency_recall"] = 0.995
            (root / "results.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
            summary = json.loads((root / "summary.json").read_text(encoding="utf-8"))
            summary["locked_terminology_recall"] = 0.995
            _write(root / "summary.json", summary)
            path = root / "validation.json"
            build_machine_evidence(path, evidence_type="model_validation", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources, root=Path.cwd())
            self.assertEqual(load_evidence(path, expected_type="model_validation")["payload"]["locked_terminology_recall"], 0.995)

    def test_model_summary_and_rows_safety_metrics_must_agree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _model_sources(root, repeats=3)
            summary = json.loads((root / "summary.json").read_text(encoding="utf-8"))
            summary["locked_terminology_recall"] = 0.995
            _write(root / "summary.json", summary)
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "validation.json", evidence_type="model_validation", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources, root=Path.cwd())

    def test_security_evidence_is_derived_from_scanner_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "security.json"
            build_machine_evidence(path, evidence_type="security", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=_security_sources(root))
            self.assertTrue(load_evidence(path, expected_type="security")["payload"]["secret_scan_pass"])
            _security_sources(root, vulnerable=True)
            with self.assertRaises(EvidenceValidationError):
                load_evidence(path, expected_type="security")

    def test_security_evidence_binds_the_production_dependency_subject(self):
        subject = "a" * 40
        candidate = _candidate_spec(subject)
        deployment = candidate_deployment_fingerprint(candidate)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _security_sources(root, constraints_hash=str(candidate["constraints_sha256"]))
            evidence = root / "security.json"
            build_machine_evidence(evidence, evidence_type="security", subject_git_sha=subject, deployment_fingerprint=deployment, sources=sources, candidate_spec=candidate)
            self.assertEqual(load_evidence(evidence, expected_type="security", candidate_spec=candidate, subject_git_sha=subject, deployment_fingerprint=deployment)["payload"]["audited_dependency_set_sha256"], dependency_inventory_hash(json.loads((root / "dependency-inventory.json").read_text(encoding="utf-8"))))
            context = json.loads((root / "audit-context.json").read_text(encoding="utf-8"))
            context["audited_dependency_set_sha256"] = "d" * 64
            _write(root / "audit-context.json", context)
            with self.assertRaises(EvidenceValidationError):
                load_evidence(evidence, expected_type="security", candidate_spec=candidate, subject_git_sha=subject, deployment_fingerprint=deployment)
            context["audited_dependency_set_sha256"] = str(candidate["constraints_sha256"])
            context.pop("semgrep_ruleset_sha256")
            _write(root / "audit-context.json", context)
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "missing-ruleset.json", evidence_type="security", subject_git_sha=subject, deployment_fingerprint=deployment, sources=sources, candidate_spec=candidate)

    def test_release_rejects_external_evidence_paths_and_keeps_relative_paths(self):
        subject = "a" * 40
        candidate = _candidate_spec(subject)
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside_directory:
            root = Path(directory)
            candidate_path = root / "candidate.json"
            _write(candidate_path, candidate)
            outside = Path(outside_directory)
            sources = _runtime_sources(outside)
            evidence = outside / "runtime.evidence.json"
            deployment = candidate_deployment_fingerprint(candidate)
            build_machine_evidence(evidence, evidence_type="runtime", subject_git_sha=subject, deployment_fingerprint=deployment, sources=sources, candidate_spec=candidate)
            with self.assertRaises(EvidenceValidationError):
                build_release_manifest(root, requested_state="DEVELOPMENT", subject_sha=subject, candidate_profile=candidate_path, evidence_paths={"runtime": evidence})
            inside = root / "evidence"
            inside.mkdir()
            inside_sources = _runtime_sources(inside)
            inside_evidence = inside / "runtime.evidence.json"
            build_machine_evidence(inside_evidence, evidence_type="runtime", subject_git_sha=subject, deployment_fingerprint=deployment, sources=inside_sources, candidate_spec=candidate)
            manifest = build_release_manifest(root, requested_state="DEVELOPMENT", subject_sha=subject, candidate_profile=candidate_path, evidence_paths={"runtime": inside_evidence})
            self.assertEqual(manifest["evidence_paths"]["runtime"], "evidence/runtime.evidence.json")

    def test_model_policy_requires_explicit_alias_targets_and_exact_canonical_ids(self):
        from k_slide.model_policy import ModelPolicy
        target = "google/gemma-4-31b-it"
        alternate = "provider/gemma-4-31b-it-r2"
        policy = ModelPolicy.from_mapping({"approved_model_ids": [target, alternate], "approved_aliases": ["private/gemma"], "approved_alias_targets": {"private/gemma": [target]}})
        self.assertTrue(policy.approved(requested=target, effective=target))
        self.assertFalse(policy.approved(requested=target, effective=alternate))
        self.assertTrue(policy.approved(requested="private/gemma", effective=target))
        self.assertFalse(policy.approved(requested="private/gemma", effective=alternate))
        self.assertFalse(policy.approved(requested="missing/gemma", effective=target))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".k-slide-config").mkdir()
            (root / ".k-slide-config" / "model-policy.local.yaml").write_text(
                "approved_model_ids:\n  - google/gemma-4-31b-it\napproved_aliases:\n  - private/gemma\napproved_alias_targets:\n  private/gemma:\n    - google/gemma-4-31b-it\n",
                encoding="utf-8",
            )
            yaml_policy = __import__("k_slide.model_policy", fromlist=["load_model_policy"]).load_model_policy(root)
            self.assertTrue(yaml_policy.approved(requested="private/gemma", effective=target))

    def test_isolated_opencode_runner_keeps_outer_authoritative_policy(self):
        from evals.opencode_runner import OpenCodeEvalRunner
        from k_slide.model_policy import ModelPolicy

        target = "google/gemma-4-31b-it"
        policy = ModelPolicy.from_mapping({"approved_model_ids": [target], "approved_aliases": ["private/gemma"], "approved_alias_targets": {"private/gemma": [target]}})
        runner = OpenCodeEvalRunner(model="private/gemma", opencode="/missing/opencode", policy=policy, policy_root=Path("/missing/isolated-policy"))
        self.assertIs(runner.policy, policy)
        self.assertTrue(runner.policy.approved(requested="private/gemma", effective=target))

    def test_certifying_model_runner_requires_frozen_policy_approved_effective_model(self):
        from evals.model_eval import ModelEvaluationRunner
        from k_slide.model_policy import ModelPolicy

        target = "google/gemma-4-31b-it"
        alternate = "provider/gemma-4-31b-it-r2"
        policy = ModelPolicy.from_mapping({"approved_model_ids": [target, alternate]})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate_path = root / "candidate.json"
            candidate = _candidate_spec("a" * 40, effective_model=alternate)
            candidate["model_policy"] = policy.as_dict()
            _write(candidate_path, candidate)
            result = ModelEvaluationRunner(
                model=target,
                output=root / "run",
                split="validation",
                repeats=3,
                candidate_profile=candidate_path,
                model_policy=policy,
            ).run()
            self.assertEqual(result["status"], "CANDIDATE_PROFILE_BLOCKED")

    def test_security_scanner_failure_is_not_a_clean_scan(self):
        for scanner in ("pip_audit", "gitleaks", "semgrep"):
            with self.subTest(scanner=scanner), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                sources = _security_sources(root)
                exits = {**json.loads((root / "scanner-exits.json").read_text(encoding="utf-8")), scanner: 1}
                _write(root / "scanner-exits.json", exits)
                with self.assertRaises(AdapterError):
                    build_machine_evidence(root / "security.json", evidence_type="security", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources)

    def test_security_missing_gitleaks_report_is_not_an_empty_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _security_sources(root)
            (root / "gitleaks.json").unlink()
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "security.json", evidence_type="security", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources)

    def test_security_scanner_enforcement_is_independent_from_candidate_eligibility(self):
        from evals.enforce_security import main as enforce_main

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _security_sources(root)
            args = [f"--{role.replace('_', '-') if role != 'scanner_exits' else 'scanner-exits'}" for role in ("pip_audit", "gitleaks", "semgrep", "scanner_exits")]
            paths = [str(sources[role]) for role in ("pip_audit", "gitleaks", "semgrep", "scanner_exits")]
            self.assertEqual(enforce_main(sum(([arg, path] for arg, path in zip(args, paths)), [])), 0)
            _write(root / "pip-audit.json", {"dependencies": [{"name": "Pillow", "version": "1.0", "vulns": [{"id": "CVE-TEST"}]}]})
            with self.assertRaises(AdapterError):
                enforce_security_scanners({key: sources[key] for key in ("pip_audit", "gitleaks", "semgrep", "scanner_exits")})
            (root / "gitleaks.json").unlink()
            with self.assertRaises(AdapterError):
                enforce_security_scanners({key: sources[key] for key in ("pip_audit", "gitleaks", "semgrep", "scanner_exits")})

    def test_private_certification_bundle_materializes_bytes_and_rejects_unsafe_layout(self):
        from evals.materialize_certification_bundle import materialize

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "bundle"
            target = root / "checkout"
            bundle.mkdir()
            subject = "a" * 40
            candidate_path = bundle / "candidate.json"
            lock_path = bundle / "production.lock"
            candidate = {"candidate_spec_version": "1.1", "subject_git_sha": subject, "requested_model": "google/gemma-4-31b-it"}
            _write(candidate_path, candidate)
            inventory = canonical_dependency_inventory([{"name": "Pillow", "version": "1.0"}])
            lock_path.write_text(dependency_lock_text(inventory), encoding="utf-8")
            manifest = {"schema_version": "1.1", "target_subject_git_sha": subject, "files": [{"role": "candidate_profile", "path": "candidate.json", "target": ".k-slide-config/production-candidate.json", "sha256": _sha(candidate_path)}, {"role": "production_dependency_lock", "path": "production.lock", "target": ".k-slide-config/production-requirements.lock", "sha256": _sha(lock_path)}]}
            manifest_path = _write(bundle / "certification-bundle.json", manifest)
            result = materialize(bundle_root=bundle, manifest_path=manifest_path, output_root=target, subject_git_sha=subject)
            self.assertEqual(result["status"], "PASS")
            self.assertEqual(_sha(target / ".k-slide-config" / "production-candidate.json"), _sha(candidate_path))
            manifest["target_subject_git_sha"] = "b" * 40
            _write(bundle / "certification-bundle.json", manifest)
            with self.assertRaises(EvidenceValidationError):
                materialize(bundle_root=bundle, manifest_path=manifest_path, output_root=root / "wrong-subject", subject_git_sha=subject)
            manifest["target_subject_git_sha"] = subject
            _write(bundle / "certification-bundle.json", manifest)
            manifest["files"][0]["path"] = "../candidate.json"
            _write(bundle / "certification-bundle.json", manifest)
            with self.assertRaises(EvidenceValidationError):
                materialize(bundle_root=bundle, manifest_path=manifest_path, output_root=root / "unsafe", subject_git_sha=subject)

    def test_isolated_model_runner_materializes_and_verifies_private_termbase_before_inference(self):
        from evals.opencode_runner import OpenCodeEvalRunner
        from k_slide.installer import install

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "termbase").mkdir()
            (root / "termbase" / "core.json").write_bytes((Path.cwd() / "termbase" / "core.json").read_bytes())
            (root / "termbase" / "overlays").mkdir()
            overlay = {"version": "1.0", "records": [{"term_id": "private-1", "source": "사내어", "preferred": {"default": "internal term"}, "status": "LOCKED", "scope": ["corporate"]}]}
            overlay_path = root / "termbase" / "overlays" / "corporate.json"
            _write(overlay_path, overlay)
            authority = {"governance_identity": "test-governance-v1", "policy_identity": "test-policy-v1", "authorization_identity": "test-authority-v1", "core": {"identity": "core-test-v1", "version": "1.0", "sha256": _sha(root / "termbase" / "core.json"), "path": "termbase/core.json"}, "overlays": [{"identity": "corporate-test-v1", "version": "1.0", "sha256": _sha(overlay_path), "path": "termbase/overlays/corporate.json", "scope": "BU", "scope_ref": "corporate", "authorization_identity": "corporate-authority-v1"}], "overlay_order": ["corporate-test-v1"], "order_identity": "single"}
            identity = effective_termbase_identity(root, termbase_authority=authority)
            self.assertIsNotNone(identity)
            runner = OpenCodeEvalRunner(model="google/gemma-4-31b-it", candidate_spec={"termbase_identity": identity}, candidate_root=root, termbase_authority=authority, opencode="/missing/opencode")
            workspace = root / "workspace"
            install(Path.cwd(), workspace, scope="project")
            copied = runner._prepare_candidate_termbase(workspace)
            self.assertIsNotNone(copied)
            self.assertEqual(effective_termbase_identity(workspace, termbase_authority=authority), identity)
            copied.unlink()
            _write(overlay_path, {**overlay, "records": [{**overlay["records"][0], "preferred": {"default": "changed"}}]})
            with self.assertRaises(EvidenceValidationError):
                runner._prepare_candidate_termbase(workspace)

    def test_isolated_model_runner_blocks_termbase_mismatch_before_opencode_process(self):
        from evals.opencode_runner import OpenCodeEvalRunner
        from k_slide.installer import install

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "termbase").mkdir()
            (root / "termbase" / "core.json").write_bytes((Path.cwd() / "termbase" / "core.json").read_bytes())
            (root / "termbase" / "overlays").mkdir()
            overlay = {"version": "1.0", "records": [{"term_id": "private-2", "source": "계약", "preferred": {"default": "agreement"}, "status": "PREFERRED"}]}
            overlay_path = root / "termbase" / "overlays" / "corporate.json"
            _write(overlay_path, overlay)
            authority = {"governance_identity": "test-governance-v1", "policy_identity": "test-policy-v1", "authorization_identity": "test-authority-v1", "core": {"identity": "core-test-v1", "version": "1.0", "sha256": _sha(root / "termbase" / "core.json"), "path": "termbase/core.json"}, "overlays": [{"identity": "corporate-test-v1", "version": "1.0", "sha256": _sha(overlay_path), "path": "termbase/overlays/corporate.json", "scope": "BU", "scope_ref": "corporate", "authorization_identity": "corporate-authority-v1"}], "overlay_order": ["corporate-test-v1"], "order_identity": "single"}
            identity = effective_termbase_identity(root, termbase_authority=authority)
            _write(overlay_path, {**overlay, "records": [{**overlay["records"][0], "preferred": {"default": "contract"}}]})
            fake = root / "opencode"
            fake.write_text("#!/bin/sh\nprintf '1.3.9\\n'\n", encoding="utf-8")
            fake.chmod(0o755)
            runner = OpenCodeEvalRunner(model="google/gemma-4-31b-it", opencode=str(fake), candidate_spec={"termbase_identity": identity}, candidate_root=root, termbase_authority=authority)
            workspace = root / "workspace"
            install(Path.cwd(), workspace, scope="project")
            with patch("k_slide.installer.install"), patch("evals.opencode_runner._version", return_value="1.3.9"), patch("evals.opencode_runner.subprocess.Popen") as popen:
                result = runner.run(workspace=workspace)
            self.assertEqual(result.status, "CANDIDATE_CONFIG_BLOCKED")
            popen.assert_not_called()

    def test_security_workflow_captures_exit_codes_without_text_mutation_or_clean_fallback(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github" / "workflows" / "k-slide-security.yml").read_text(encoding="utf-8")
        self.assertIn("pip-audit.exit", workflow)
        self.assertIn("gitleaks.exit", workflow)
        self.assertIn("semgrep.exit", workflow)
        self.assertIn("Assemble scanner exit codes", workflow)
        self.assertIn("Enforce scanner results", workflow)
        self.assertIn("certification_bundle_run_id", workflow)
        self.assertNotIn("actions/download-artifact@v4", workflow)
        self.assertIn("validate_certification_bundle_provenance", workflow)
        self.assertIn("KSLIDE_PRIVATE_CERTIFICATION_TOKEN", workflow)
        self.assertIn("certification_bundle_sha256", workflow)
        self.assertIn("materialize_certification_bundle", workflow)
        self.assertIn("download_certification_bundle", workflow)
        self.assertIn("source-repository.json", workflow)
        self.assertIn("target-subject-sha", workflow)
        self.assertIn("-r constraints-production.txt", workflow)
        self.assertIn("security/semgrep-production.yml", workflow)
        self.assertIn("audit_context", workflow)
        self.assertIn("candidate_profile", workflow)

    def test_security_subject_uses_ocr_core_and_fixed_bootstrap_versions(self):
        root = Path(__file__).resolve().parents[1]
        constraints = (root / "constraints-production.txt").read_text(encoding="utf-8")
        workflow = (root / ".github" / "workflows" / "k-slide-security.yml").read_text(encoding="utf-8")
        self.assertIn("paddleocr==3.7.0", constraints)
        self.assertNotIn("paddleocr==3.0.3", constraints)
        self.assertIn("pip==26.2.1", workflow)
        self.assertIn("setuptools==83.0.0", workflow)
        self.assertIn('pip-audit --strict --format json --output "$RUNNER_TEMP/k-slide-security/evidence/pip-audit.json" --path "$production_site"', workflow)
        self.assertNotIn("--ignore-vuln", workflow)
        self.assertIn("production_site", workflow)
        self.assertIn("evidence/production-requirements.lock", workflow)
        self.assertNotIn("--path \"$RUNNER_TEMP/k-slide-security/production-env\"", workflow)
        self.assertIn("production_evidence_eligible", workflow)
        self.assertIn("NOT_CERTIFYING", workflow)
        self.assertNotIn('description: "Private resolved candidate profile path', workflow)
        self.assertNotIn("production_dependency_lock:\n", workflow)
        self.assertNotIn("sed -i", workflow)
        self.assertNotIn("printf '[]\\n'", workflow)

    def test_heavy_evidence_rederives_retained_dependency_subject(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _heavy_sources(root)
            build_machine_evidence(root / "heavy.json", evidence_type="heavy_runtime", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources)
            _write(root / "built-image-inventory.json", canonical_dependency_inventory([{"name": "Pillow", "version": "2.0"}]))
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "changed-heavy.json", evidence_type="heavy_runtime", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources)

    def test_heavy_evidence_rejects_candidate_bound_ocr_manifest_mismatch(self):
        subject = "a" * 40
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            asset_root = root / "candidate-assets"
            asset_root.mkdir()
            asset = asset_root / "weights.bin"
            asset.write_bytes(b"candidate-weights")
            config = asset_root / "PaddleOCR.yaml"
            config.write_text("pipeline: candidate\n", encoding="utf-8")
            manifest = {"provider": "paddle", "paddlex_config": "PaddleOCR.yaml", "files": [{"path": "PaddleOCR.yaml", "sha256": _sha(config)}, {"path": "weights.bin", "sha256": _sha(asset)}]}
            candidate_manifest = asset_root / "candidate-manifest.json"
            _write(candidate_manifest, manifest)
            runtime_manifest = asset_root / "runtime-manifest.json"
            asset.write_bytes(b"different-runtime-weights")
            _write(runtime_manifest, {"provider": "paddle", "paddlex_config": "PaddleOCR.yaml", "files": [{"path": "PaddleOCR.yaml", "sha256": _sha(config)}, {"path": "weights.bin", "sha256": _sha(asset)}]})
            candidate = _candidate_spec(subject, ocr_provider="paddle")
            candidate["ocr_asset_manifest"] = "ocr/manifest.json"
            candidate["ocr_asset_manifest_sha256"] = _sha(candidate_manifest)
            packages = canonical_dependency_inventory([{"name": name, "version": "1.0"} for name in ("Pillow", "PyMuPDF", "python-pptx", "paddlepaddle", "paddleocr")])
            candidate["resolved_dependency_set_sha256"] = dependency_inventory_hash(packages)
            deployment = candidate_deployment_fingerprint(candidate)
            sources = _heavy_sources(root, subject=subject, deployment=deployment, ocr_manifest=runtime_manifest, ocr_context={"status": "PASS", "runtime_verified": True, "after_engine": True, "manifest_sha256": _sha(runtime_manifest), "files": [{"path": "weights.bin", "sha256": _sha(asset)}]})
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "heavy.json", evidence_type="heavy_runtime", subject_git_sha=subject, deployment_fingerprint=deployment, sources=sources, candidate_spec=candidate)

    def test_heavy_evidence_rejects_runtime_selected_paddle_config_mismatch(self):
        from k_slide.certification import validate_ocr_asset_manifest

        subject = "a" * 40
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assets = root / "assets"
            assets.mkdir()
            config = assets / "PaddleOCR.yaml"
            alternate = assets / "alternate.yaml"
            weights = assets / "weights.bin"
            config.write_text("pipeline: canonical\n", encoding="utf-8")
            alternate.write_text("pipeline: alternate\n", encoding="utf-8")
            weights.write_bytes(b"weights")
            manifest = assets / "manifest.json"
            _write(manifest, {"provider": "paddle", "paddlex_config": "PaddleOCR.yaml", "files": [{"path": name, "sha256": _sha(assets / name), "bytes": (assets / name).stat().st_size} for name in ("PaddleOCR.yaml", "alternate.yaml", "weights.bin")]})
            identity = validate_ocr_asset_manifest(manifest, asset_root=assets)
            candidate = _candidate_spec(subject, ocr_provider="paddle")
            candidate["ocr_asset_manifest"] = "ocr/manifest.json"
            candidate["ocr_asset_manifest_sha256"] = identity["sha256"]
            packages = canonical_dependency_inventory([{"name": name, "version": "1.0"} for name in ("Pillow", "PyMuPDF", "python-pptx", "paddlepaddle", "paddleocr")])
            candidate["resolved_dependency_set_sha256"] = dependency_inventory_hash(packages)
            deployment = candidate_deployment_fingerprint(candidate)
            evidence_root = root / "evidence"
            evidence_root.mkdir()
            context = {"status": "PASS", "runtime_verified": True, "after_engine": True, "manifest_sha256": identity["sha256"], "files": identity["entries"], "paddlex_config": "alternate.yaml", "paddlex_config_sha256": _sha(alternate), "offline_assets_required": True}
            sources = _heavy_sources(evidence_root, subject=subject, deployment=deployment, ocr_manifest=manifest, ocr_context=context)
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "heavy.json", evidence_type="heavy_runtime", subject_git_sha=subject, deployment_fingerprint=deployment, sources=sources, candidate_spec=candidate)

    def test_heavy_dependency_context_is_retained_from_lock_and_image_inventory(self):
        from evals.freeze_production_dependencies import retain_heavy_dependency_context

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _heavy_sources(root)
            context_path = root / "retained-context.json"
            context = retain_heavy_dependency_context(inventory_path=sources["production_inventory"], lock_path=sources["production_lock"], built_image_inventory_path=sources["built_image_inventory"], output=context_path, subject_git_sha="a" * 40, deployment_fingerprint="b" * 64)
            self.assertEqual(context["expected_dependency_set_sha256"], dependency_inventory_hash(json.loads(sources["production_inventory"].read_text(encoding="utf-8"))))
            self.assertEqual(json.loads(context_path.read_text(encoding="utf-8"))["dependency_subject"], "production-env")

    def test_heavy_workflow_sequence_retains_frozen_subject_without_ambient_refreeze(self):
        from evals.freeze_production_dependencies import freeze, main as freeze_main
        from k_slide.io import atomic_write_json

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory_path = root / "production-inventory.json"
            lock_path = root / "production.lock"
            built_path = root / "built-image-inventory.json"
            context_path = root / "dependency-context.json"
            original = canonical_dependency_inventory([{"name": "Pillow", "version": "1.0"}, {"name": "PyMuPDF", "version": "1.0"}])
            with patch("evals.freeze_production_dependencies.installed_dependency_inventory", return_value=original):
                freeze(inventory_output=inventory_path, lock_output=lock_path)
            inventory_bytes = inventory_path.read_bytes()
            lock_bytes = lock_path.read_bytes()
            built_path.write_bytes(inventory_bytes)
            with patch("evals.freeze_production_dependencies.installed_dependency_inventory", side_effect=AssertionError("ambient interpreter must not be consulted")), patch("evals.freeze_production_dependencies.atomic_write_json", wraps=atomic_write_json) as write_json:
                self.assertEqual(freeze_main(["--retain-only", "--inventory-input", str(inventory_path), "--lock-input", str(lock_path), "--built-image-inventory", str(built_path), "--dependency-context-output", str(context_path), "--subject-sha", "a" * 40]), 0)
            self.assertEqual([call.args[0] for call in write_json.call_args_list], [context_path])
            self.assertEqual(inventory_path.read_bytes(), inventory_bytes)
            self.assertEqual(lock_path.read_bytes(), lock_bytes)
            self.assertEqual(json.loads(context_path.read_text(encoding="utf-8"))["package_count"], 2)
            _write(built_path, canonical_dependency_inventory([{"name": "Pillow", "version": "2.0"}, {"name": "PyMuPDF", "version": "1.0"}]))
            self.assertEqual(freeze_main(["--retain-only", "--inventory-input", str(inventory_path), "--lock-input", str(lock_path), "--built-image-inventory", str(built_path), "--dependency-context-output", str(context_path), "--subject-sha", "a" * 40]), 2)
            self.assertEqual(inventory_path.read_bytes(), inventory_bytes)
            self.assertEqual(lock_path.read_bytes(), lock_bytes)

    def test_trusted_path_rejects_ancestor_symlink_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence"
            evidence.mkdir()
            target = evidence / "real"
            target.mkdir()
            sources = _runtime_sources(target)
            envelope = evidence / "evidence.json"
            link = evidence / "inside-link"
            link.symlink_to(target, target_is_directory=True)
            linked_sources = {role: link / path.name for role, path in sources.items()}
            with self.assertRaises(AdapterError):
                build_machine_evidence(envelope, evidence_type="runtime", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=linked_sources)
            outside = root / "outside"
            outside.mkdir()
            outside_sources = _runtime_sources(outside)
            outside_link = evidence / "outside-link"
            outside_link.symlink_to(outside, target_is_directory=True)
            linked_outside = {role: outside_link / path.name for role, path in outside_sources.items()}
            with self.assertRaises(AdapterError):
                build_machine_evidence(envelope, evidence_type="runtime", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=linked_outside)

    def test_private_bundle_builder_and_materializer_support_repeatable_ocr_assets(self):
        from evals.build_certification_bundle import build
        from evals.materialize_certification_bundle import materialize

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            candidate_path = source / "candidate.json"
            subject = "a" * 40
            _write(candidate_path, {"candidate_spec_version": "1.1", "subject_git_sha": subject, "requested_model": "google/gemma-4-31b-it", "ocr_provider": "paddle", "ocr_asset_manifest": "ocr/manifest.json"})
            (source / "production.lock").write_text("Pillow==1.0\n", encoding="utf-8")
            (source / "ocr").mkdir()
            (source / "ocr" / "PaddleOCR.yaml").write_text("pipeline: test\n", encoding="utf-8")
            (source / "ocr" / "det.bin").write_bytes(b"det")
            (source / "ocr" / "rec.bin").write_bytes(b"rec")
            manifest = {"provider": "paddle", "paddlex_config": "PaddleOCR.yaml", "files": [{"path": "PaddleOCR.yaml", "sha256": _sha(source / "ocr" / "PaddleOCR.yaml"), "bytes": 15}, {"path": "det.bin", "sha256": _sha(source / "ocr" / "det.bin"), "bytes": 3}, {"path": "rec.bin", "sha256": _sha(source / "ocr" / "rec.bin"), "bytes": 3}]}
            manifest_path = source / "ocr" / "manifest.json"
            _write(manifest_path, manifest)
            candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
            candidate["ocr_asset_manifest_sha256"] = _sha(manifest_path)
            _write(candidate_path, candidate)
            bundle = root / "bundle"
            result = build(output=bundle, subject_git_sha=subject, candidate_profile=candidate_path, production_dependency_lock=source / "production.lock", ocr_asset_manifest=manifest_path)
            self.assertEqual(result["status"], "PASS")
            output = root / "checkout"
            materialize(bundle_root=bundle, manifest_path=bundle / "certification-bundle.json", output_root=output, subject_git_sha=subject)
            self.assertEqual((output / "ocr" / "det.bin").read_bytes(), b"det")
            self.assertEqual((output / "ocr" / "rec.bin").read_bytes(), b"rec")
            archive = root / "bundle.zip"
            with zipfile.ZipFile(archive, "w") as package:
                for item in bundle.rglob("*"):
                    if item.is_file():
                        package.write(item, item.relative_to(bundle).as_posix())
            extracted = root / "archive-checkout"
            from evals.materialize_certification_bundle import main as materialize_main
            self.assertEqual(materialize_main(["--archive", str(archive), "--archive-sha256", _sha(archive), "--output-root", str(extracted), "--subject-sha", subject]), 0)

    def test_private_bundle_transport_requires_authoritative_private_run_provenance(self):
        from evals.validate_certification_bundle_provenance import BundleProvenanceError, validate_provenance

        subject = "a" * 40
        digest = "b" * 64
        producer_sha = "c" * 40
        run = {"id": 17, "repository": {"full_name": "private-org/certification"}, "workflow_id": 23, "path": ".github/workflows/prepare.yml", "status": "completed", "conclusion": "success", "head_sha": producer_sha}
        artifacts = {"artifacts": [{"id": 31, "name": "bundle", "digest": f"sha256:{digest}", "workflow_run": {"id": 17}, "expired": False, "expires_at": "2099-01-01T00:00:00Z"}]}
        source_repository = {"full_name": "private-org/certification", "private": True, "visibility": "private"}
        result = validate_provenance(run=run, artifacts=artifacts, expected_run_id="17", expected_artifact_name="bundle", expected_source_repository="private-org/certification", expected_workflow_id="23", expected_workflow_path=".github/workflows/prepare.yml", target_subject_git_sha=subject, expected_digest=digest, public_repository="kimhw8084/agent-skills", source_repository_metadata=source_repository)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["producer_head_sha"], producer_sha)
        self.assertEqual(result["target_subject_git_sha"], subject)
        for mutation in (
            {"repository": {"full_name": "kimhw8084/agent-skills"}},
            {"path": ".github/workflows/other.yml"},
            {"status": "completed", "conclusion": "cancelled"},
        ):
            changed = dict(run)
            changed.update(mutation)
            with self.assertRaises(BundleProvenanceError):
                validate_provenance(run=changed, artifacts=artifacts, expected_run_id="17", expected_artifact_name="bundle", expected_source_repository="private-org/certification", expected_workflow_id="23", expected_workflow_path=".github/workflows/prepare.yml", target_subject_git_sha=subject, expected_digest=digest, public_repository="kimhw8084/agent-skills", source_repository_metadata=source_repository)
        wrong_artifacts = {"artifacts": [{"id": 31, "name": "bundle", "digest": "sha256:" + "d" * 64, "workflow_run": {"id": 99}}]}
        with self.assertRaises(BundleProvenanceError):
            validate_provenance(run=run, artifacts=wrong_artifacts, expected_run_id="17", expected_artifact_name="bundle", expected_source_repository="private-org/certification", expected_workflow_id="23", expected_workflow_path=".github/workflows/prepare.yml", target_subject_git_sha=subject, expected_digest=digest, public_repository="kimhw8084/agent-skills", source_repository_metadata=source_repository)

    def test_private_bundle_producer_and_target_subjects_are_distinct(self):
        from evals.validate_certification_bundle_provenance import BundleProvenanceError, validate_provenance

        target = "a" * 40
        producer = "b" * 40
        digest = "c" * 64
        run = {"id": 17, "repository": {"full_name": "private-org/certification"}, "workflow_id": 23, "path": ".github/workflows/prepare.yml", "status": "completed", "conclusion": "success", "head_sha": producer}
        artifacts = {"artifacts": [{"id": 31, "name": "bundle", "digest": f"sha256:{digest}", "workflow_run": {"id": 17}, "expired": False, "expires_at": "2099-01-01T00:00:00Z"}]}
        private_repo = {"full_name": "private-org/certification", "private": True, "visibility": "private"}
        result = validate_provenance(run=run, artifacts=artifacts, expected_run_id="17", expected_artifact_name="bundle", expected_source_repository="private-org/certification", expected_workflow_id="23", expected_workflow_path=".github/workflows/prepare.yml", target_subject_git_sha=target, expected_digest=digest, public_repository="kimhw8084/agent-skills", source_repository_metadata=private_repo)
        self.assertEqual(result["producer_head_sha"], producer)
        self.assertEqual(result["target_subject_git_sha"], target)
        for metadata in ({"full_name": "private-org/certification", "private": False}, {"full_name": "kimhw8084/agent-skills", "private": True}):
            with self.assertRaises(BundleProvenanceError):
                validate_provenance(run=run, artifacts=artifacts, expected_run_id="17", expected_artifact_name="bundle", expected_source_repository="private-org/certification", expected_workflow_id="23", expected_workflow_path=".github/workflows/prepare.yml", target_subject_git_sha=target, expected_digest=digest, public_repository="kimhw8084/agent-skills", source_repository_metadata=metadata)

    def test_private_bundle_download_follows_redirect_without_forwarding_token(self):
        from evals.download_certification_bundle import download_artifact_archive

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "transport" / "bundle.zip"
            body = b"PK\x03\x04synthetic-bundle"
            expected = hashlib.sha256(body).hexdigest()
            endpoint = "https://api.example.test"
            redirect = "https://objects.example.test/signed/bundle.zip"

            class Response:
                def __init__(self, value: bytes):
                    self.value = value

                def read(self, _size: int = -1) -> bytes:
                    value, self.value = self.value, b""
                    return value

                def close(self) -> None:
                    return None

            class Opener:
                def __init__(self):
                    self.requests = []

                def open(self, request, timeout=0):
                    self.requests.append(request)
                    if request.full_url.endswith("/actions/artifacts/31/zip"):
                        raise HTTPError(request.full_url, 302, "redirect", {"Location": redirect}, None)
                    if request.full_url == redirect:
                        return Response(body)
                    raise AssertionError(request.full_url)

            opener = Opener()
            result = download_artifact_archive(repository="private-org/certification", artifact_id=31, output=output, expected_sha256=expected, token="private-token", api_base_url=endpoint, opener_factory=lambda: opener)
            self.assertEqual(result["sha256"], expected)
            self.assertEqual(output.read_bytes(), body)
            self.assertEqual(opener.requests[0].headers.get("Authorization"), "Bearer private-token")
            self.assertNotIn("Authorization", opener.requests[1].headers)

    def test_private_bundle_download_rejects_digest_and_workflows_avoid_unsupported_output_flag(self):
        from evals.download_certification_bundle import CertificationBundleDownloadError, download_artifact_archive

        help_result = subprocess.run(["gh", "api", "--help"], capture_output=True, text=True, check=False)
        self.assertEqual(help_result.returncode, 0)
        self.assertNotIn("--output", help_result.stdout)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            class Response:
                def __init__(self):
                    self.value = b"wrong"

                def read(self, _size: int = -1) -> bytes:
                    value, self.value = self.value, b""
                    return value

                def close(self) -> None:
                    return None

            class Opener:
                def open(self, request, timeout=0):
                    return Response()

            with self.assertRaises(CertificationBundleDownloadError):
                download_artifact_archive(repository="private-org/certification", artifact_id=31, output=root / "bundle.zip", expected_sha256="a" * 64, token="token", api_base_url="https://api.example.test", opener_factory=Opener)
        for workflow in (Path(__file__).resolve().parents[1] / ".github" / "workflows" / "k-slide-phase32.yml", Path(__file__).resolve().parents[1] / ".github" / "workflows" / "k-slide-security.yml"):
            text = workflow.read_text(encoding="utf-8")
            self.assertNotIn("gh api --output", text)
            self.assertIn("download_certification_bundle", text)

    def test_paddle_selected_config_is_canonical_and_runtime_bound(self):
        from k_slide.certification import validate_ocr_asset_manifest

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "PaddleOCR.yaml"
            alternate = root / "alternate.yaml"
            config.write_text("pipeline: canonical\n", encoding="utf-8")
            alternate.write_text("pipeline: alternate\n", encoding="utf-8")
            assets = [{"path": name, "sha256": _sha(root / name), "bytes": (root / name).stat().st_size} for name in ("PaddleOCR.yaml", "alternate.yaml")]
            manifest = root / "manifest.json"
            _write(manifest, {"provider": "paddle", "paddlex_config": "PaddleOCR.yaml", "files": assets})
            identity = validate_ocr_asset_manifest(manifest, asset_root=root)
            self.assertEqual(identity["paddlex_config"], "PaddleOCR.yaml")
            self.assertEqual(paddle_runtime_configuration(asset_root=root, manifest_path=manifest)["paddlex_config_sha256"], _sha(config))
            with patch.dict("os.environ", {"KSLIDE_PADDLEX_CONFIG": str(alternate), "KSLIDE_PADDLE_REQUIRE_LOCAL_ASSETS": "1"}):
                with self.assertRaises(EvidenceValidationError):
                    paddle_runtime_configuration(asset_root=root, manifest_path=manifest)
            config.write_text("pipeline: changed\n", encoding="utf-8")
            with self.assertRaises(EvidenceValidationError):
                paddle_runtime_configuration(asset_root=root, manifest_path=manifest)

    def test_reliability_requires_actual_concurrency_result(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "reliability.json"
            build_machine_evidence(path, evidence_type="reliability", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=_reliability_sources(root))
            self.assertEqual(load_evidence(path, expected_type="reliability")["payload"]["concurrent_runs"], 5)

    def test_governance_requires_authoritative_api_not_codeowners_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "governance.json"
            _write(source, {"source_kind": "codeowners", "codeowners_pass": True, "branch_protection_pass": True, "required_ci_pass": True, "review_required": True})
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "governance-envelope.json", evidence_type="governance", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources={"governance_api": source})

    def test_temporary_runtime_heavy_chain_derives_gemma_eval_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subject = "a" * 40
            candidate = _candidate_spec(subject, ocr_provider="paddle", asset_manifest="manifest.json", asset_hash="a" * 64)
            deployment = deployment_fingerprint(build_deployment_factors(root, subject_git_sha=subject, model_policy=load_model_policy(root)))
            runtime_path = root / "runtime-envelope.json"
            heavy_path = root / "heavy-envelope.json"
            build_machine_evidence(runtime_path, evidence_type="runtime", subject_git_sha=subject, deployment_fingerprint=deployment, sources=_runtime_sources(root))
            build_machine_evidence(heavy_path, evidence_type="heavy_runtime", subject_git_sha=subject, deployment_fingerprint=deployment, sources=_heavy_sources(root))
            records = {"runtime": load_evidence(runtime_path, expected_type="runtime", subject_git_sha=subject, deployment_fingerprint=deployment), "heavy_runtime": load_evidence(heavy_path, expected_type="heavy_runtime", subject_git_sha=subject, deployment_fingerprint=deployment)}
            state, blockers = derive_release_state("GEMMA_EVAL_READY", records=records, root=root, policy=load_model_policy(root), deployment_fp=deployment, candidate_spec=candidate)
            self.assertEqual(state, "GEMMA_EVAL_READY")
            self.assertEqual(blockers, [])

    def test_temporary_machine_and_attestation_chain_derives_pilot_without_production_policy(self):
        from k_slide.recertification import build_champion_promotion, champion_document_from_promotion

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subject = "a" * 40
            candidate = _candidate_spec(subject, ocr_provider="paddle", asset_manifest="manifest.json", asset_hash="a" * 64)
            candidate["inference_route_identity"] = "test-inference-route"
            candidate["inference_endpoint_identity"] = "f" * 64
            candidate["resolved_dependency_set_sha256"] = "d" * 64
            candidate["constraints_sha256"] = _sha(Path.cwd() / "constraints-production.txt")
            deployment = candidate_deployment_fingerprint(candidate)
            records = {}
            for evidence_type, source_factory in (("runtime", _runtime_sources), ("heavy_runtime", _heavy_sources)):
                folder = root / evidence_type
                folder.mkdir()
                sources = source_factory(folder, full=evidence_type == "heavy_runtime") if evidence_type == "heavy_runtime" else source_factory(folder)
                envelope = folder / "evidence.json"
                build_machine_evidence(envelope, evidence_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, sources=sources)
                records[evidence_type] = load_evidence(envelope, expected_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, repository_root=root)
            model_records = {}
            bilingual_manifest = None
            for evidence_type, split, repeats in (("model_validation", "validation", 3), ("model_high_risk_stability", "validation", 5), ("model_held_out", "held_out", 3)):
                folder = root / evidence_type
                folder.mkdir()
                source = _candidate_model_sources(folder, split=split, repeats=repeats, subject=subject, deployment=deployment, candidate=candidate)
                if evidence_type == "model_validation":
                    bilingual_manifest = json.loads(source["experiment_manifest"].read_text(encoding="utf-8"))["corpus_manifest"]
                envelope = folder / "evidence.json"
                build_machine_evidence(envelope, evidence_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, sources=source, candidate_spec=candidate)
                model_records[evidence_type] = load_evidence(envelope, expected_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, repository_root=Path.cwd(), candidate_spec=candidate, require_candidate_spec=True)
            (root / "evals").mkdir()
            promotion = build_champion_promotion(candidate, model_records, policy=load_model_policy(root), root=Path.cwd(), state="FROZEN_PROMOTED")
            _write(root / "evals" / "champion.json", champion_document_from_promotion(promotion, reason="synthetic test fixture"))
            records.update(model_records)
            bilingual_payload = build_internal_bilingual_payload(make_review_contract(subject=subject, deployment=deployment, manifest=bilingual_manifest))
            payloads = {
                "internal_bilingual": bilingual_payload,
                "zero_korean_comprehension": zero_korean_payload(candidate, bilingual_payload),
                "model_data_policy": {"attestation_id": "policy-test", "approved_for_internal_artifacts": True},
            }
            for evidence_type, payload in payloads.items():
                folder = root / evidence_type
                folder.mkdir()
                path = folder / "evidence.json"
                candidate_binding = candidate if evidence_type in {"internal_bilingual", "zero_korean_comprehension"} else None
                write_evidence(path, evidence_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, payload=payload, generated_at="2026-09-09T00:00:00Z", candidate_spec=candidate_binding)
                records[evidence_type] = load_evidence(path, expected_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, repository_root=root, candidate_spec=candidate_binding)
            state, blockers = derive_release_state("INTERNAL_VALIDATED", records=records, root=root, policy=load_model_policy(root), deployment_fp=deployment, candidate_spec=candidate)
            self.assertEqual(state, "INTERNAL_VALIDATED", msg=str(blockers))
            self.assertEqual(blockers, [])

            for evidence_type, source_factory in (("security", _security_sources), ("reliability", _reliability_sources)):
                folder = root / evidence_type
                folder.mkdir()
                source = source_factory(folder)
                path = folder / "evidence.json"
                build_machine_evidence(path, evidence_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, sources=source, root=Path.cwd())
                records[evidence_type] = load_evidence(path, expected_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, repository_root=Path.cwd())
            governance_folder = root / "governance"
            governance_folder.mkdir()
            governance_sources = write_governance_sources(governance_folder, subject=subject)
            governance_path = governance_folder / "evidence.json"
            build_machine_evidence(governance_path, evidence_type="governance", subject_git_sha=subject, deployment_fingerprint=deployment, sources=governance_sources, candidate_spec=candidate)
            records["governance"] = load_evidence(governance_path, expected_type="governance", subject_git_sha=subject, deployment_fingerprint=deployment, repository_root=Path.cwd(), candidate_spec=candidate, require_candidate_spec=True)
            pilot_path = root / "pilot.json"
            write_evidence(pilot_path, evidence_type="pilot_canary", subject_git_sha=subject, deployment_fingerprint=deployment, payload={"attestation_id": "pilot-test", "users": 5, "artifacts": 50, "critical_confirmed_errors": 0, "cross_user_exposure": 0, "security_incidents": 0, "silent_incomplete_output": 0}, generated_at="2026-09-09T00:00:00Z")
            records["pilot_canary"] = load_evidence(pilot_path, expected_type="pilot_canary", subject_git_sha=subject, deployment_fingerprint=deployment, repository_root=root)
            (root / ".k-slide-config").mkdir()
            _write(root / ".k-slide-config" / "production-sbom.json", {"bomFormat": "CycloneDX", "complete": True, "metadata": {}, "components": [{"name": "k-slide"}]})
            state, blockers = derive_release_state("PRODUCTION_CERTIFIED", records=records, root=root, policy=load_model_policy(root), deployment_fp=deployment, candidate_spec=candidate)
            self.assertEqual(state, "PILOT_APPROVED", msg=str(blockers))
            self.assertTrue(any("authoritative default-deny egress policy" in item for item in blockers))

    def test_deterministic_evidence_identity_excludes_generated_at(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _runtime_sources(root)
            first = root / "first.json"
            second = root / "second.json"
            build_machine_evidence(first, evidence_type="runtime", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources, generated_at="2026-01-01T00:00:00Z")
            build_machine_evidence(second, evidence_type="runtime", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources, generated_at="2026-01-02T00:00:00Z")
            self.assertEqual(load_evidence(first)["evidence_identity"], load_evidence(second)["evidence_identity"])

    def test_deployment_and_certification_fingerprints_change_with_material_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = build_deployment_factors(root, subject_git_sha="a" * 40, model_policy=load_model_policy(root))
            second = build_deployment_factors(root, subject_git_sha="b" * 40, model_policy=load_model_policy(root))
            self.assertNotEqual(deployment_fingerprint(first), deployment_fingerprint(second))
            deployment = deployment_fingerprint(first)
            self.assertNotEqual(certification_fingerprint(deployment=deployment, evidence_hashes={"runtime": "a" * 64}, release_state="RUNTIME_READY"), certification_fingerprint(deployment=deployment, evidence_hashes={"runtime": "b" * 64}, release_state="RUNTIME_READY"))

    def test_deployment_identity_excludes_certification_metadata_and_experiment_controls(self):
        from evals.experiments import behavior_configuration_hash, experiment_plan, experiment_plan_hash

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            behavior = {"model": "google/gemma-4-31b-it", "ocr_provider": "none", "prompt_version": "test-v1", "generation_settings": {"temperature": 0}}
            self.assertEqual(behavior_configuration_hash(behavior), behavior_configuration_hash({**behavior, "repetitions": 99, "split": "held_out", "limit": 1}))
            plan3 = experiment_plan(split="validation", scenario_ids=["scenario-0022"], formats=["png"], repetitions=3, categories=["modality_decision_state"], timeout=180, mode="quality")
            plan5 = experiment_plan(split="validation", scenario_ids=["scenario-0022"], formats=["png"], repetitions=5, categories=["modality_decision_state"], timeout=180, mode="quality")
            self.assertNotEqual(experiment_plan_hash(plan3), experiment_plan_hash(plan5))
            base = {"requested_model": behavior["model"], "effective_model": behavior["model"], "ocr_provider": "none", "behavior_configuration": behavior, "release_state": "DEVELOPMENT", "model_data_attestation": "UNSET", "release_manifest": "candidate.json", "release_manifest_sha256": "a" * 64}
            changed_metadata = {**base, "release_state": "PRODUCTION_CERTIFIED", "model_data_attestation": "policy-1", "release_manifest": "other.json", "release_manifest_sha256": "b" * 64}
            first = deployment_fingerprint(build_deployment_factors(root, subject_git_sha="a" * 40, profile=base, model_policy=load_model_policy(root), corpus={"version": "1.0", "corpus_fingerprint": "c" * 64, "held_out_fingerprint": "d" * 64}))
            second = deployment_fingerprint(build_deployment_factors(root, subject_git_sha="a" * 40, profile=changed_metadata, model_policy=load_model_policy(root), corpus={"version": "1.0", "corpus_fingerprint": "c" * 64, "held_out_fingerprint": "d" * 64}))
            self.assertEqual(first, second)
            material = {**base, "behavior_configuration": {**behavior, "prompt_version": "test-v2"}}
            self.assertNotEqual(first, deployment_fingerprint(build_deployment_factors(root, subject_git_sha="a" * 40, profile=material, model_policy=load_model_policy(root), corpus={"version": "1.0", "corpus_fingerprint": "c" * 64, "held_out_fingerprint": "d" * 64})))

    def test_candidate_spec_allowlist_aliases_and_material_behavior(self):
        subject = "a" * 40
        base = _candidate_spec(subject)
        first = candidate_deployment_fingerprint(base)
        metadata = {**base, "release_state": "PRODUCTION_CERTIFIED", "certification_fingerprint": "c" * 64, "release_manifest": "/tmp/release.json", "release_manifest_sha256": "d" * 64, "generated_at": "now", "split": "held_out", "repetitions": 99, "limit": 1}
        self.assertEqual(first, candidate_deployment_fingerprint(metadata))
        ambient_a = SimpleNamespace(as_dict=lambda: {"provider": "github", "reported_model_id": "runner-a"})
        ambient_b = SimpleNamespace(as_dict=lambda: {"provider": "local", "reported_model_id": "runner-b"})
        self.assertEqual(
            candidate_deployment_fingerprint(build_deployment_factors(Path.cwd(), candidate_spec=base, runtime=ambient_a)),
            candidate_deployment_fingerprint(build_deployment_factors(Path.cwd(), candidate_spec=base, runtime=ambient_b)),
        )
        changed_repair = {**base, "repair_policy": {"max_auto_repairs_per_unit": 3}, "behavior_configuration": {**base["behavior_configuration"], "repair_policy": {"max_auto_repairs_per_unit": 3}}}
        changed_normalization = {**base, "normalization_behavior": {"render_dpi": 221}, "behavior_configuration": {**base["behavior_configuration"], "normalization_behavior": {"render_dpi": 221}}}
        changed_prompt = {**base, "prompt_identity": {"version": "translation/v2", "hash": "q" * 64}, "behavior_configuration": {**base["behavior_configuration"], "prompt_identity": {"version": "translation/v2", "hash": "q" * 64}}}
        changed_generation = {**base, "generation_settings": {"temperature": 0.2}, "behavior_configuration": {**base["behavior_configuration"], "generation_settings": {"temperature": 0.2}}}
        changed_ocr = {**base, "ocr_provider": "paddle", "behavior_configuration": {**base["behavior_configuration"], "ocr_provider": "paddle"}}
        self.assertNotEqual(first, candidate_deployment_fingerprint(changed_repair))
        self.assertNotEqual(first, candidate_deployment_fingerprint(changed_normalization))
        self.assertNotEqual(first, candidate_deployment_fingerprint(changed_prompt))
        self.assertNotEqual(first, candidate_deployment_fingerprint(changed_generation))
        self.assertNotEqual(first, candidate_deployment_fingerprint(changed_ocr))
        alias = {**base}
        alias.pop("repair_policy")
        alias["repair"] = {"max_auto_repairs_per_unit": 2}
        alias_behavior = {**base["behavior_configuration"]}
        alias_behavior.pop("repair_policy")
        alias_behavior["repair"] = {"max_auto_repairs_per_unit": 2}
        alias["behavior_configuration"] = alias_behavior
        self.assertEqual(first, candidate_deployment_fingerprint(alias))
        self.assertNotEqual(behavior_configuration_hash({"repair": {"max_auto_repairs_per_unit": 2}}), behavior_configuration_hash({"repair": {"max_auto_repairs_per_unit": 3}}))

    def test_candidate_profile_absent_malformed_and_unknown_fields_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(EvidenceValidationError):
                load_candidate_spec(root / "missing.json", root=root, require_identity=True)
            malformed = root / "malformed.json"
            malformed.write_text("{", encoding="utf-8")
            with self.assertRaises(EvidenceValidationError):
                load_candidate_spec(malformed, root=root, require_identity=True)
            unknown = root / "unknown.json"
            _write(unknown, {**_candidate_spec("a" * 40), "behavior_configuration": {"unclassified_runtime_switch": True}})
            with self.assertRaises(EvidenceValidationError):
                load_candidate_spec(unknown, root=root, require_identity=True)
            top_level_unknown = root / "top-level-unknown.json"
            _write(top_level_unknown, {**_candidate_spec("a" * 40), "new_runtime_switch": True})
            with self.assertRaises(EvidenceValidationError):
                load_candidate_spec(top_level_unknown, root=root, require_identity=True)

    def test_certification_engine_split_requires_candidate_profile(self):
        from evals.run_engine_eval import main as engine_main

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "engine"
            self.assertEqual(engine_main(["--output", str(output), "--split", "validation", "--limit", "0"]), 2)
            self.assertEqual(json.loads((output / "summary.json").read_text(encoding="utf-8"))["status"], "CANDIDATE_PROFILE_BLOCKED")

    def test_effective_model_identity_is_required_and_mixed_models_are_rejected(self):
        from k_slide.model_policy import ModelPolicy

        target = "google/gemma-4-31b-it"
        alternate = "provider/gemma-4-31b-it-r2"
        alias_policy = ModelPolicy(approved_model_ids=(target,), approved_aliases=("private/gemma",), approved_alias_targets=(("private/gemma", (target,)),))
        self.assertTrue(alias_policy.approved(requested="private/gemma", effective=target))
        self.assertEqual(alias_policy.canonical_effective(requested="private/gemma", effective=target), target)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".k-slide-config").mkdir()
            _write(root / ".k-slide-config" / "model-policy.local.json", {"approved_model_ids": [target, alternate]})
            sources = _model_sources(root, repeats=3)
            rows = [json.loads(line) for line in (root / "results.jsonl").read_text(encoding="utf-8").splitlines()]
            rows[0]["opencode"]["diagnostics"]["effective_model"] = alternate
            (root / "results.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "mixed.json", evidence_type="model_validation", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources, root=root)
            rows[0]["opencode"]["diagnostics"].pop("effective_model")
            (root / "results.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "missing-effective.json", evidence_type="model_validation", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources, root=root)
            candidate = _candidate_spec("a" * 40)
            candidate["model_policy"] = {"approved_model_ids": [target, alternate]}
            changed = {**candidate, "effective_model": alternate}
            self.assertNotEqual(candidate_deployment_fingerprint(candidate), candidate_deployment_fingerprint(changed))

    def test_validation_and_high_risk_effective_models_must_match(self):
        from evals.release import _champion

        target = "google/gemma-4-31b-it"
        alternate = "provider/gemma-4-31b-it-r2"
        subject = "a" * 40
        deployment = "b" * 64
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".k-slide-config").mkdir()
            _write(root / ".k-slide-config" / "model-policy.local.json", {"approved_model_ids": [target, alternate]})
            records = {}
            for evidence_type, repeats in (("model_validation", 3), ("model_high_risk_stability", 5)):
                folder = root / evidence_type
                folder.mkdir()
                sources = _model_sources(folder, repeats=repeats, subject=subject, deployment=deployment)
                if evidence_type == "model_high_risk_stability":
                    rows = [json.loads(line) for line in sources["results_jsonl"].read_text(encoding="utf-8").splitlines()]
                    for row in rows:
                        row["effective_model"] = alternate
                        row["opencode"]["diagnostics"]["effective_model"] = alternate
                    sources["results_jsonl"].write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
                    for name in ("summary.json", "experiment.json"):
                        path = folder / name
                        value = json.loads(path.read_text(encoding="utf-8"))
                        value["effective_model"] = alternate
                        _write(path, value)
                envelope = folder / "evidence.json"
                if evidence_type == "model_high_risk_stability":
                    with self.assertRaises(AdapterError):
                        build_machine_evidence(envelope, evidence_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, sources=sources, root=root)
                    return
                build_machine_evidence(envelope, evidence_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, sources=sources, root=root)
                records[evidence_type] = load_evidence(envelope, expected_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, repository_root=root)
            (root / "evals").mkdir()
            _write(root / "evals" / "champion.json", {"status": "FROZEN", "model": target, "effective_model": target, "deployment_fingerprint": deployment, "config_hash": records["model_validation"]["payload"]["behavior_configuration_hash"]})
            _champ, _hash, blockers = _champion(root, records=records, policy=load_model_policy(root), deployment_fp=deployment)
            self.assertIn("model evidence effective identities disagree", blockers)

    def test_public_synthetic_high_risk_output_cannot_become_certification_evidence(self):
        from evals.model_eval import ModelEvaluationRunner

        target = "google/gemma-4-31b-it"
        subject = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = _candidate_spec(subject)
            candidate_path = root / "candidate.json"
            _write(candidate_path, candidate)

            class FakeOpenCode:
                def run(self, **_kwargs):
                    return SimpleNamespace(
                        status="PASS",
                        reason=None,
                        runtime_version="1.3.9",
                        kslide_complete=True,
                        events=[{"type": "tool_result", "tool": "kslide_submit"}],
                        media_compliance={"work_units": {"u1": {"media_sequence_valid": True}}},
                        diagnostics={"effective_model": target, "model_identity_proven": True},
                        as_dict=lambda: {"status": "PASS", "mode": "quality", "model": target, "runtime_version": "1.3.9", "kslide_complete": True, "event_count": 1, "tool_calls": [], "forbidden_attempts": [], "media_compliance": {"planned": True, "required_count": 1, "read_count": 1, "required_context_image_read": True, "media_sequence_valid": True, "work_units": {"u1": {"required_context_image_read": True, "required_crop_recall": 1.0, "media_sequence_valid": True, "submit_observed": True, "items": [{"id": "context_image", "read_observed": True, "read_before_submit": True}]}}}, "diagnostics": {"effective_model": target, "model_identity_proven": True, "mixed_effective_model_ids": False, "read_policy_violations": []}},
                    )

            scored = {"coverage": 1.0, "numeric_fidelity": 1.0, "modality": 1.0, "table_cell_fidelity": 1.0, "visual_relation_recall": 1.0, "critical_failures": [], "unresolved_region_rate": 0.0, "unexpected_unresolved_rate": 0.0}
            consistency = {"term_consistency_recall": 1.0, "inconsistent_alternate_count": 0, "critical_failures": []}
            runtime = SimpleNamespace(as_dict=lambda: {"opencode_version": "1.3.9", "python_version": TEST_PYTHON_VERSION, "provider": "google", "ocr_provider": "none"})
            with patch("evals.model_eval.generate_artifacts"), patch("evals.model_eval.OpenCodeEvalRunner", return_value=FakeOpenCode()), patch("evals.model_eval.discover_runtime", return_value=runtime), patch("evals.model_eval._latest_run", return_value=None), patch("evals.model_eval.collect_run_artifacts", return_value=[{"work_unit_id": "u1", "evidence": {}, "patch": {}, "slide_ir": None}]), patch("evals.model_eval._engine_gate", return_value=("PASS", [])), patch("evals.model_eval._work_unit_contract", return_value=(True, [])), patch("evals.model_eval.score_translation_patch", return_value=scored), patch("evals.model_eval.score_deck_consistency", return_value=consistency):
                output = root / "high-risk"
                result = ModelEvaluationRunner(model=target, output=output, split="validation", repeats=5, mode="quality", candidate_profile=candidate_path, high_risk=True).run()
            self.assertEqual(result.get("effective_model"), target, msg=json.dumps(result, sort_keys=True))
            experiment = json.loads((output / "experiment.json").read_text(encoding="utf-8"))
            self.assertEqual(set(experiment["high_risk_categories"]), set(PROTECTED_CATEGORIES))
            self.assertEqual(experiment["corpus_set_identity"]["role"], "public_synthetic_regression")
            self.assertEqual(experiment["quality_policy_identity"], QUALITY_POLICY_IDENTITY)
            self.assertTrue(all(row["quality_policy_identity"] == QUALITY_POLICY_IDENTITY for row in (json.loads(line) for line in (output / "results.jsonl").read_text(encoding="utf-8").splitlines())))
            self.assertEqual(experiment["evaluation_purpose"], "regression")
            self.assertEqual(experiment["governed_corpus_manifests"], [public_synthetic_manifest()])
            evidence = output / "evidence.json"
            loaded_candidate = load_candidate_spec(candidate_path, root=Path.cwd(), require_identity=True)
            finalized_candidate = {**loaded_candidate, **experiment["candidate_spec"]}
            self.assertEqual(candidate_deployment_fingerprint(finalized_candidate), experiment["deployment_fingerprint"], msg=json.dumps({"loaded": canonical_candidate_factors(loaded_candidate), "runner": experiment["candidate_spec"]}, sort_keys=True))
            with self.assertRaises(AdapterError):
                build_machine_evidence(evidence, evidence_type="model_high_risk_stability", subject_git_sha=subject, deployment_fingerprint=experiment["deployment_fingerprint"], sources={"model_summary": output / "summary.json", "experiment_manifest": output / "experiment.json", "results_jsonl": output / "results.jsonl"}, root=Path.cwd(), candidate_spec=loaded_candidate)

    def test_runtime_engine_security_model_release_share_candidate_fingerprint(self):
        from evals.opencode_diagnostics import run_diagnostic_ladder
        from evals.run_engine_eval import main as engine_main

        subject = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = _candidate_spec(subject)
            candidate_path = root / "candidate.json"
            _write(candidate_path, candidate)
            loaded = load_candidate_spec(candidate_path, root=Path.cwd(), require_identity=True)
            expected = candidate_deployment_fingerprint(loaded)
            diagnostic = run_diagnostic_ladder(model=loaded["requested_model"], output=root / "diagnostic", opencode="/missing/opencode", candidate_profile=candidate_path)
            self.assertEqual(diagnostic["deployment_fingerprint"], expected)
            engine_output = root / "engine"
            self.assertEqual(engine_main(["--output", str(engine_output), "--split", "development", "--limit", "0", "--candidate-profile", str(candidate_path)]), 0)
            self.assertEqual(json.loads((engine_output / "summary.json").read_text(encoding="utf-8"))["deployment_fingerprint"], expected)
            security_folder = root / "security"
            security_folder.mkdir()
            security_sources = _security_sources(security_folder, constraints_hash=str(loaded["constraints_sha256"]))
            security_path = security_folder / "evidence.json"
            build_machine_evidence(security_path, evidence_type="security", subject_git_sha=subject, deployment_fingerprint=expected, sources=security_sources, root=Path.cwd(), candidate_spec=loaded)
            self.assertEqual(json.loads(security_path.read_text(encoding="utf-8"))["deployment_fingerprint"], expected)
            release = build_release_manifest(Path.cwd(), requested_state="DEVELOPMENT", subject_sha=subject, candidate_profile=candidate_path)
            self.assertEqual(release["deployment_fingerprint"], expected)
            self.assertEqual(release["quality_policy_identity"], QUALITY_POLICY_IDENTITY)
            self.assertEqual(release["quality_policy"], policy_identity_record())
            self.assertEqual(release["dataset"]["corpus_identity"], loaded["corpus_identity"])

    def test_complete_release_materializes_profile_and_detects_candidate_staleness(self):
        from k_slide.recertification import build_champion_promotion, champion_document_from_promotion

        subject = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
        target = "google/gemma-4-31b-it"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            asset_dir = root / "ocr"
            asset_dir.mkdir()
            (asset_dir / "PaddleOCR.yaml").write_text("pipeline: test\n", encoding="utf-8")
            (asset_dir / "alternate.yaml").write_text("pipeline: alternate\n", encoding="utf-8")
            (asset_dir / "weights.bin").write_bytes(b"local-paddle-weights")
            asset_hash = _sha(asset_dir / "weights.bin")
            asset_manifest = asset_dir / "manifest.json"
            _write(asset_manifest, {"provider": "paddle", "paddlex_config": "PaddleOCR.yaml", "files": [{"path": name, "sha256": _sha(asset_dir / name)} for name in ("PaddleOCR.yaml", "alternate.yaml", "weights.bin")]})
            (root / "prompts").mkdir()
            (root / "prompts" / "translation").mkdir()
            (root / "prompts" / "translation" / "v1.md").write_bytes((Path.cwd() / "prompts" / "translation" / "v1.md").read_bytes())
            (root / ".opencode" / "agents").mkdir(parents=True)
            (root / ".opencode" / "agents" / "k-slide.md").write_bytes((Path.cwd() / ".opencode" / "agents" / "k-slide.md").read_bytes())
            (root / "termbase").mkdir()
            (root / "termbase" / "core.json").write_bytes((Path.cwd() / "termbase" / "core.json").read_bytes())
            (root / "constraints-production.txt").write_bytes((Path.cwd() / "constraints-production.txt").read_bytes())
            inventory = canonical_dependency_inventory([{"name": name, "version": "1.0"} for name in ("Pillow", "PyMuPDF", "python-pptx", "paddlepaddle", "paddleocr")])
            (root / ".k-slide-config").mkdir()
            _write_opencode_bootstrap(root)
            _write(root / ".k-slide-config" / "production-dependency-inventory.json", inventory)
            candidate = _candidate_spec(subject, ocr_provider="paddle", asset_manifest="ocr/manifest.json", asset_hash=_sha(asset_manifest), root=root)
            from k_slide.classification_policy import (
                DEFAULT_CLASSIFICATION,
                INFERENCE_DATA_USE_POLICY_FILENAME,
                policy_hash_for_mapping,
                policy_identity_for_mapping,
            )
            route_identity = str(candidate["inference_route_identity"])
            policy_version = "test-1"
            classification_rules = {DEFAULT_CLASSIFICATION: True, "restricted": False, "internal_only": True}
            policy_hash = policy_hash_for_mapping(
                inference_route_identity=route_identity,
                policy_version=policy_version,
                classification_rules=classification_rules,
            )
            candidate["inference_data_use_policy"] = {
                "schema_version": "1.0",
                "inference_route_identity": route_identity,
                "policy_version": policy_version,
                "policy_hash": policy_hash,
                "policy_identity": policy_identity_for_mapping(
                    inference_route_identity=route_identity,
                    policy_version=policy_version,
                    policy_hash=policy_hash,
                ),
                "classification_rules": classification_rules,
            }
            _write(root / ".k-slide-config" / INFERENCE_DATA_USE_POLICY_FILENAME, candidate["inference_data_use_policy"])
            candidate_dir = root / ".k-slide-config"
            candidate_dir.mkdir(exist_ok=True)
            candidate_path = candidate_dir / "production-candidate.json"
            _write(candidate_path, candidate)
            candidate = load_candidate_spec(candidate_path, root=root, require_identity=True)
            deployment = candidate_deployment_fingerprint(candidate)
            records: dict[str, dict[str, object]] = {}
            for evidence_type, factory, full in (("runtime", _runtime_sources, False), ("heavy_runtime", _heavy_sources, True)):
                folder = root / evidence_type
                folder.mkdir()
                sources = factory(folder, full=full, subject=subject, deployment=deployment, ocr_manifest=asset_manifest, ocr_context={"status": "PASS", "runtime_verified": True, "after_engine": True, "manifest_sha256": _sha(asset_manifest), "files": [{"path": name, "sha256": _sha(asset_manifest.parent / name)} for name in ("PaddleOCR.yaml", "alternate.yaml", "weights.bin")], "paddlex_config": "PaddleOCR.yaml", "paddlex_config_sha256": _sha(asset_manifest.parent / "PaddleOCR.yaml"), "offline_assets_required": True}) if evidence_type == "heavy_runtime" else factory(folder, provider=str(candidate["provider"]), ocr_provider=str(candidate["ocr_provider"]))
                path = folder / "evidence.json"
                build_machine_evidence(path, evidence_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, sources=sources, root=root, candidate_spec=candidate)
                records[evidence_type] = load_evidence(path, expected_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, repository_root=root, candidate_spec=candidate, require_candidate_spec=True)
            bilingual_manifest = None
            for evidence_type, split, repeats in (("model_validation", "validation", 3), ("model_high_risk_stability", "validation", 5), ("model_held_out", "held_out", 3)):
                folder = root / evidence_type
                folder.mkdir()
                sources = _candidate_model_sources(folder, split=split, repeats=repeats, subject=subject, deployment=deployment, candidate=candidate)
                if evidence_type == "model_validation":
                    bilingual_manifest = json.loads(sources["experiment_manifest"].read_text(encoding="utf-8"))["corpus_manifest"]
                path = folder / "evidence.json"
                build_machine_evidence(path, evidence_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, sources=sources, root=root, candidate_spec=candidate)
                records[evidence_type] = load_evidence(path, expected_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, repository_root=root, candidate_spec=candidate, require_candidate_spec=True)
            (root / "evals").mkdir()
            promotion = build_champion_promotion(candidate, {key: value for key, value in records.items() if key.startswith("model_")}, policy=load_model_policy(root), root=root, state="FROZEN_PROMOTED")
            _write(root / "evals" / "champion.json", champion_document_from_promotion(promotion, reason="synthetic test fixture"))
            bilingual_payload = build_internal_bilingual_payload(make_review_contract(subject=subject, deployment=deployment, manifest=bilingual_manifest))
            attestations = {
                "internal_bilingual": bilingual_payload,
                "zero_korean_comprehension": zero_korean_payload(candidate, bilingual_payload),
                "model_data_policy": {"attestation_id": "policy-test", "approved_for_internal_artifacts": True},
            }
            for evidence_type, payload in attestations.items():
                folder = root / evidence_type
                folder.mkdir()
                path = folder / "evidence.json"
                write_evidence(path, evidence_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, payload=payload, generated_at="2026-09-10T00:00:00Z", candidate_spec=candidate)
                records[evidence_type] = load_evidence(path, expected_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, repository_root=root, candidate_spec=candidate, require_candidate_spec=True)
            for evidence_type, factory in (("security", _security_sources), ("reliability", _reliability_sources)):
                folder = root / evidence_type
                folder.mkdir()
                path = folder / "evidence.json"
                source_values = factory(folder, constraints_hash=str(candidate["constraints_sha256"])) if evidence_type == "security" else factory(folder)
                build_machine_evidence(path, evidence_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, sources=source_values, root=root, candidate_spec=candidate)
                records[evidence_type] = load_evidence(path, expected_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, repository_root=root, candidate_spec=candidate, require_candidate_spec=True)
            governance_folder = root / "governance"
            governance_folder.mkdir()
            governance_sources = write_governance_sources(governance_folder, subject=subject)
            governance_path = governance_folder / "evidence.json"
            build_machine_evidence(governance_path, evidence_type="governance", subject_git_sha=subject, deployment_fingerprint=deployment, sources=governance_sources, root=root, candidate_spec=candidate)
            records["governance"] = load_evidence(governance_path, expected_type="governance", subject_git_sha=subject, deployment_fingerprint=deployment, repository_root=root, candidate_spec=candidate, require_candidate_spec=True)
            pilot_folder = root / "pilot_canary"
            pilot_folder.mkdir()
            pilot_path = pilot_folder / "evidence.json"
            write_evidence(pilot_path, evidence_type="pilot_canary", subject_git_sha=subject, deployment_fingerprint=deployment, payload={"attestation_id": "pilot-test", "users": 5, "artifacts": 50, "critical_confirmed_errors": 0, "cross_user_exposure": 0, "security_incidents": 0, "silent_incomplete_output": 0}, generated_at="2026-09-10T00:00:00Z", candidate_spec=candidate)
            records["pilot_canary"] = load_evidence(pilot_path, expected_type="pilot_canary", subject_git_sha=subject, deployment_fingerprint=deployment, repository_root=root, candidate_spec=candidate, require_candidate_spec=True)
            sbom_folder = root / ".k-slide-config"
            security_sbom = json.loads((root / "security" / "production-sbom.json").read_text(encoding="utf-8"))
            _write(sbom_folder / "production-sbom.json", security_sbom)
            evidence_paths = {key: root / key / "evidence.json" for key in records}
            manifest_path = root / "release" / "manifest.json"
            profile_path = sbom_folder / "production-profile.json"
            release_args = ["--root", str(root), "--output", str(manifest_path), "--requested-state", "PRODUCTION_CERTIFIED", "--require-certified", "--candidate-profile", str(candidate_path), "--certified-profile-output", str(profile_path)]
            for option, evidence_type in (("--runtime-evidence", "runtime"), ("--heavy-runtime-evidence", "heavy_runtime"), ("--validation-evidence", "model_validation"), ("--high-risk-evidence", "model_high_risk_stability"), ("--held-out-evidence", "model_held_out")):
                release_args.extend([option, str(evidence_paths[evidence_type])])
            for option, evidence_type in (("--internal-bilingual-attestation", "internal_bilingual"), ("--zero-korean-attestation", "zero_korean_comprehension"), ("--model-data-policy-attestation", "model_data_policy"), ("--security-attestation", "security"), ("--reliability-attestation", "reliability"), ("--governance-attestation", "governance"), ("--pilot-attestation", "pilot_canary")):
                release_args.extend([option, str(evidence_paths[evidence_type])])
            self.assertEqual(release_main(release_args), 0)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["release_state"], "PRODUCTION_CERTIFIED")
            self.assertEqual(manifest["deployment_fingerprint"], deployment)
            self.assertNotIn("blocking_reasons", manifest)
            profile = json.loads(profile_path.read_text(encoding="utf-8"))
            self.assertEqual(profile["release_manifest_sha256"], _sha(manifest_path))
            self.assertEqual(profile["retention_policy"], candidate["retention_policy"])
            self.assertEqual(ProductionProfile.from_mapping(profile).deployment_fingerprint, deployment)
            from k_slide.installer import install
            install(Path.cwd(), root, scope="project")
            shutil.rmtree(root / "prompts")
            shutil.rmtree(root / "termbase")
            (root / "constraints-production.txt").unlink()
            (root / ".k-slide-runs").mkdir(exist_ok=True)
            (root / ".k-slide-runs").chmod(0o700)
            (root / ".opencode" / "opencode.json").write_text(json.dumps({"model": target}) + "\n", encoding="utf-8")
            (root / ".k-slide-config" / "ocr.local.json").write_text(json.dumps({"ocr_provider": "paddle"}) + "\n", encoding="utf-8")
            from k_slide.runtime import discover_runtime
            from k_slide.doctor import diagnose
            from k_slide.production import production_checks
            from k_slide.opencode_bootstrap import load_bootstrap_manifest
            package_versions = {"paddlepaddle": "3.0.0", "paddleocr": "3.0.3"}
            production_inventory = canonical_dependency_inventory([{"name": name, "version": version} for name, version in {"Pillow": "1.0", "PyMuPDF": "1.0", "python-pptx": "1.0", "paddlepaddle": "1.0", "paddleocr": "1.0"}.items()])
            bootstrap = load_bootstrap_manifest(root / ".k-slide-config" / "opencode-bootstrap.json")
            bootstrap_environment = {
                "GOOGLE_GENERATIVE_AI_API_KEY": "synthetic-google-key",
                "OPENCODE_DISABLE_MODELS_FETCH": "1",
                "OPENCODE_DISABLE_AUTOUPDATE": "1",
                "OPENCODE_DISABLE_LSP_DOWNLOAD": "1",
                "OPENCODE_DISABLE_PROJECT_CONFIG": "1",
                "OPENCODE_MODELS_PATH": bootstrap.models_path,
                "HOME": str(bootstrap.home_dir),
                "USERPROFILE": str(bootstrap.home_dir),
                "XDG_CONFIG_HOME": str(bootstrap.xdg_config_home),
                "XDG_DATA_HOME": str(bootstrap.xdg_data_home),
                "XDG_CACHE_HOME": str(bootstrap.xdg_cache_home),
                "XDG_STATE_HOME": str(bootstrap.xdg_state_home),
                "OPENCODE_CONFIG_DIR": str(bootstrap.config_dir),
                "PATH": str(bootstrap.ripgrep_path.parent) + os.pathsep + os.environ.get("PATH", ""),
            }
            inventory_patch = patch("k_slide.production.installed_dependency_inventory", return_value=production_inventory)
            inventory_patch.start()
            self.addCleanup(inventory_patch.stop)
            with patch("k_slide.runtime.shutil.which", side_effect=lambda name: f"/usr/bin/{name}"), patch("k_slide.runtime._config_path", return_value=root / ".opencode" / "opencode.json"), patch("k_slide.runtime._effective_config", return_value={"model": target}), patch("k_slide.runtime._version", return_value="1.3.9"), patch("k_slide.runtime._command_product_version", return_value="25.2.3"), patch("k_slide.runtime._package_version", side_effect=lambda name: package_versions.get(name)), patch("k_slide.doctor.importlib.util.find_spec", return_value=object()), patch("k_slide.doctor.create_ocr_provider", return_value=SimpleNamespace(requested="paddle", effective="paddle", version="3.0.3", reason=None)), patch("k_slide.production.shutil.which", return_value="/usr/bin/libreoffice"), patch("k_slide.production.importlib.util.find_spec", return_value=object()), patch("k_slide.production.importlib.metadata.version", side_effect=lambda name: package_versions[name]), patch("k_slide.production._version_from_command", return_value="25.2.3"), patch("k_slide.production.create_ocr_provider", return_value=SimpleNamespace(effective="paddle", version="3.0.3")), patch.dict("os.environ", {"AccessKey": "synthetic-doctor-key", "KSLIDE_PADDLE_REQUIRE_LOCAL_ASSETS": "1", **bootstrap_environment}):
                runtime = discover_runtime(root)
                doctor_result = diagnose(root, production=True)
            self.assertEqual(doctor_result["overall"], "WARN", msg=json.dumps([item for item in doctor_result["checks"] if item["status"] != "PASS"], indent=2))
            self.assertEqual(
                [item["label"] for item in doctor_result["checks"] if item["status"] == "WARN"],
                ["Live deployment network enforcement"],
            )
            alternate_config = asset_dir / "alternate.yaml"
            with patch("k_slide.runtime.shutil.which", side_effect=lambda name: f"/usr/bin/{name}"), patch("k_slide.runtime._config_path", return_value=root / ".opencode" / "opencode.json"), patch("k_slide.runtime._effective_config", return_value={"model": target}), patch("k_slide.runtime._version", return_value="1.3.9"), patch("k_slide.runtime._command_product_version", return_value="25.2.3"), patch("k_slide.runtime._package_version", side_effect=lambda name: package_versions.get(name)), patch("k_slide.doctor.importlib.util.find_spec", return_value=object()), patch("k_slide.doctor.create_ocr_provider", return_value=SimpleNamespace(requested="paddle", effective="paddle", version="3.0.3", reason=None)), patch("k_slide.production.shutil.which", return_value="/usr/bin/libreoffice"), patch("k_slide.production.importlib.util.find_spec", return_value=object()), patch("k_slide.production.importlib.metadata.version", side_effect=lambda name: package_versions[name]), patch("k_slide.production._version_from_command", return_value="25.2.3"), patch("k_slide.production.create_ocr_provider", return_value=SimpleNamespace(effective="paddle", version="3.0.3")), patch.dict("os.environ", {"KSLIDE_PADDLE_REQUIRE_LOCAL_ASSETS": "1", "KSLIDE_PADDLEX_CONFIG": str(alternate_config)}):
                mismatched_config_doctor = diagnose(root, production=True)
            self.assertEqual(mismatched_config_doctor["overall"], "FAIL")
            self.assertEqual(next(item for item in mismatched_config_doctor["checks"] if item["label"] == "OCR selected configuration")["status"], "FAIL")
            from dataclasses import replace
            with patch("k_slide.production.shutil.which", return_value="/usr/bin/libreoffice"), patch("k_slide.production.importlib.util.find_spec", return_value=object()), patch("k_slide.production.importlib.metadata.version", side_effect=lambda name: {"paddlepaddle": "3.0.0", "paddleocr": "3.0.3"}[name]), patch("k_slide.production._version_from_command", return_value="25.2.3"), patch("k_slide.production.create_ocr_provider", return_value=SimpleNamespace(effective="paddle", version="3.0.3")), patch.dict("os.environ", {"KSLIDE_PADDLE_REQUIRE_LOCAL_ASSETS": "1"}):
                wrong_model_checks = production_checks(root, replace(runtime, reported_model_id="google/gemma-4-31b-it-other"))
            self.assertEqual(next(item for item in wrong_model_checks if item["label"] == "Vision capability")["status"], "FAIL")
            changed_results: list[tuple[Path, str]] = []
            for model_folder in ("model_validation", "model_high_risk_stability", "model_held_out"):
                result_path = root / model_folder / "results.jsonl"
                original_results = result_path.read_text(encoding="utf-8")
                rows = [json.loads(line) for line in original_results.splitlines()]
                rows[0]["opencode"]["media_compliance"]["required_context_image_read"] = False
                result_path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
                changed_results.append((result_path, original_results))
            with patch("k_slide.production.shutil.which", return_value="/usr/bin/libreoffice"), patch("k_slide.production.importlib.util.find_spec", return_value=object()), patch("k_slide.production.importlib.metadata.version", side_effect=lambda name: {"paddlepaddle": "3.0.0", "paddleocr": "3.0.3"}[name]), patch("k_slide.production._version_from_command", return_value="25.2.3"), patch("k_slide.production.create_ocr_provider", return_value=SimpleNamespace(effective="paddle", version="3.0.3")), patch.dict("os.environ", {"KSLIDE_PADDLE_REQUIRE_LOCAL_ASSETS": "1"}):
                missing_vision_checks = production_checks(root, runtime)
            self.assertEqual(next(item for item in missing_vision_checks if item["label"] == "Vision capability")["status"], "FAIL")
            for result_path, original_results in changed_results:
                result_path.write_text(original_results, encoding="utf-8")
            with patch("k_slide.production.shutil.which", return_value="/usr/bin/libreoffice"), patch("k_slide.production.importlib.util.find_spec", return_value=object()), patch("k_slide.production.importlib.metadata.version", side_effect=lambda name: {"paddlepaddle": "3.0.4", "paddleocr": "3.0.3"}[name]), patch("k_slide.production._version_from_command", return_value="25.2.3"), patch("k_slide.production.create_ocr_provider", return_value=SimpleNamespace(effective="paddle", version="3.0.3")), patch.dict("os.environ", {"KSLIDE_PADDLE_REQUIRE_LOCAL_ASSETS": "1"}):
                dependency_checks = production_checks(root, replace(runtime, paddle_version="3.0.4"))
            self.assertEqual(next(item for item in dependency_checks if item["label"] == "Paddle version")["status"], "FAIL")
            asset_path = asset_dir / "weights.bin"
            original_asset = asset_path.read_bytes()
            asset_path.write_bytes(b"tampered-weights")
            with patch("k_slide.production.shutil.which", return_value="/usr/bin/libreoffice"), patch("k_slide.production.importlib.util.find_spec", return_value=object()), patch("k_slide.production.importlib.metadata.version", side_effect=lambda name: {"paddlepaddle": "3.0.0", "paddleocr": "3.0.3"}[name]), patch("k_slide.production._version_from_command", return_value="25.2.3"), patch("k_slide.production.create_ocr_provider", return_value=SimpleNamespace(effective="paddle", version="3.0.3")), patch.dict("os.environ", {"KSLIDE_PADDLE_REQUIRE_LOCAL_ASSETS": "1"}):
                asset_checks = production_checks(root, runtime)
            self.assertEqual(next(item for item in asset_checks if item["label"] == "OCR asset manifest")["status"], "FAIL")
            asset_path.write_bytes(original_asset)
            manifest_bytes = manifest_path.read_bytes()
            manifest_path.write_bytes(manifest_bytes + b"\n")
            with patch("k_slide.production.shutil.which", return_value="/usr/bin/libreoffice"), patch("k_slide.production.importlib.util.find_spec", return_value=object()), patch("k_slide.production.importlib.metadata.version", side_effect=lambda name: {"paddlepaddle": "3.0.0", "paddleocr": "3.0.3"}[name]), patch("k_slide.production._version_from_command", return_value="25.2.3"), patch("k_slide.production.create_ocr_provider", return_value=SimpleNamespace(effective="paddle", version="3.0.3")), patch.dict("os.environ", {"KSLIDE_PADDLE_REQUIRE_LOCAL_ASSETS": "1"}):
                manifest_checks = production_checks(root, runtime)
            self.assertEqual(next(item for item in manifest_checks if item["label"] == "Release manifest hash")["status"], "FAIL")
            manifest_path.write_bytes(manifest_bytes)
            evidence_file = root / "model_validation" / "evidence.json"
            evidence_bytes = evidence_file.read_bytes()
            evidence_file.write_bytes(evidence_bytes + b"\n")
            with patch("k_slide.production.shutil.which", return_value="/usr/bin/libreoffice"), patch("k_slide.production.importlib.util.find_spec", return_value=object()), patch("k_slide.production.importlib.metadata.version", side_effect=lambda name: {"paddlepaddle": "3.0.0", "paddleocr": "3.0.3"}[name]), patch("k_slide.production._version_from_command", return_value="25.2.3"), patch("k_slide.production.create_ocr_provider", return_value=SimpleNamespace(effective="paddle", version="3.0.3")), patch.dict("os.environ", {"KSLIDE_PADDLE_REQUIRE_LOCAL_ASSETS": "1"}):
                evidence_checks = production_checks(root, runtime)
            self.assertEqual(next(item for item in evidence_checks if item["label"] == "Evidence model_validation envelope hash")["status"], "FAIL")
            evidence_file.write_bytes(evidence_bytes)
            fingerprint_checks = _manifest_and_fingerprint_status(root, ProductionProfile.from_mapping(profile), SimpleNamespace())
            self.assertEqual(next(item for item in fingerprint_checks if item["label"] == "Deployment fingerprint")["status"], "PASS")
            self.assertEqual(next(item for item in fingerprint_checks if item["label"] == "Certification freshness")["status"], "PASS")
            stale_candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
            stale_candidate["repair_policy"]["max_auto_repairs_per_unit"] = 3
            stale_candidate["behavior_configuration"]["repair_policy"]["max_auto_repairs_per_unit"] = 3
            _write(candidate_path, stale_candidate)
            stale_checks = _manifest_and_fingerprint_status(root, ProductionProfile.from_mapping(profile), SimpleNamespace())
            self.assertEqual(next(item for item in stale_checks if item["label"] == "Candidate source identity")["status"], "FAIL")
            self.assertEqual(next(item for item in stale_checks if item["label"] == "Certification freshness")["status"], "FAIL")
            subject_changed_source = copy.deepcopy(candidate)
            subject_changed_source["subject_git_sha"] = "f" * 40
            _write(candidate_path, subject_changed_source)
            subject_stale_checks = _manifest_and_fingerprint_status(root, ProductionProfile.from_mapping(profile), SimpleNamespace())
            self.assertEqual(next(item for item in subject_stale_checks if item["label"] == "Candidate source identity")["status"], "FAIL")
            self.assertEqual(next(item for item in subject_stale_checks if item["label"] == "Certification freshness")["status"], "FAIL")

    def test_model_identity_composes_across_validation_high_risk_and_held_out(self):
        subject = "a" * 40
        deployment = "b" * 64
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            records = {}
            for evidence_type, split, repeats in (("model_validation", "validation", 3), ("model_high_risk_stability", "validation", 5), ("model_held_out", "held_out", 3)):
                folder = root / evidence_type
                folder.mkdir()
                sources = _model_sources(folder, split=split, repeats=repeats, subject=subject, deployment=deployment)
                envelope = folder / "evidence.json"
                build_machine_evidence(envelope, evidence_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, sources=sources, root=Path.cwd())
                records[evidence_type] = load_evidence(envelope, expected_type=evidence_type, subject_git_sha=subject, deployment_fingerprint=deployment, repository_root=Path.cwd())
            payloads = [records[item]["payload"] for item in ("model_validation", "model_high_risk_stability", "model_held_out")]
            self.assertEqual({item["behavior_configuration_hash"] for item in payloads}, {payloads[0]["behavior_configuration_hash"]})
            self.assertEqual(len({item["experiment_plan_hash"] for item in payloads}), 3)

    def test_actual_model_runner_separates_behavior_and_experiment_identity(self):
        from evals.model_eval import ModelEvaluationRunner

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "n3"
            second = root / "n5"
            ModelEvaluationRunner(model="ollama/qwen3:14b", output=first, split="validation", repeats=3, limit=0).run()
            ModelEvaluationRunner(model="ollama/qwen3:14b", output=second, split="validation", repeats=5, limit=0).run()
            left = json.loads((first / "experiment.json").read_text(encoding="utf-8"))
            right = json.loads((second / "experiment.json").read_text(encoding="utf-8"))
            self.assertEqual(left["deployment_fingerprint"], right["deployment_fingerprint"])
            self.assertEqual(left["behavior_configuration_hash"], right["behavior_configuration_hash"])
            self.assertNotEqual(left["experiment_plan_hash"], right["experiment_plan_hash"])

    def test_validation_and_held_out_partial_matrices_are_rejected(self):
        for split, evidence_type in (("validation", "model_validation"), ("held_out", "model_held_out")):
            with self.subTest(split=split), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                sources = _model_sources(root, split=split, repeats=3)
                rows = [json.loads(line) for line in (root / "results.jsonl").read_text(encoding="utf-8").splitlines()]
                (root / "results.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows[:-1]), encoding="utf-8")
                with self.assertRaises(AdapterError):
                    build_machine_evidence(root / "partial.json", evidence_type=evidence_type, subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources, root=Path.cwd())

    def test_high_risk_real_ids_require_exact_declared_groups_and_repeats(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _model_sources(root, repeats=5)
            rows = [json.loads(line) for line in (root / "results.jsonl").read_text(encoding="utf-8").splitlines()]
            rows[0]["repeat"] = 2
            (root / "results.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "duplicate-repeat.json", evidence_type="model_high_risk_stability", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources, root=Path.cwd())

    def test_high_risk_failing_group_cannot_be_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _model_sources(root, repeats=5)
            rows = [json.loads(line) for line in (root / "results.jsonl").read_text(encoding="utf-8").splitlines()]
            target = next(row for row in rows if row["category"] == "financial_table")
            target["semantic"]["critical_failures"] = ["NUMERIC"]
            summary = json.loads((root / "summary.json").read_text(encoding="utf-8"))
            summary["critical_failure_count"] = 1
            _write(root / "summary.json", summary)
            (root / "results.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "failing-group.json", evidence_type="model_high_risk_stability", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources, root=Path.cwd())

    def test_approved_prefix_is_not_model_policy_approval(self):
        self.assertFalse(load_model_policy(Path.cwd()).approved(requested="approved:internal", effective="approved:internal"))

    def test_production_checks_reject_wrong_model_identity(self):
        from k_slide.production import production_checks
        from k_slide.runtime import RuntimeMetadata

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".k-slide-config").mkdir()
            _write(root / ".k-slide-config" / "production-profile.json", {"schema_version": "1.1", "release_state": "PRODUCTION_CERTIFIED", "opencode_version": "1.3.9", "requested_model": "approved:internal", "effective_model": "approved:internal", "ocr_provider": "paddle", "ocr_asset_manifest": "manifest.json", "python_version": "3.11", "paddle_version": "3.0.0", "paddleocr_version": "3.0.3", "libreoffice_version": "25", "retention_policy": {"schema_version": "1.0", "content_retention_days": 30, "operational_metadata_retention_days": 60}, "tenant_isolation": "workspace_per_session", "network_egress": "default_deny", "subject_git_sha": "a" * 40, "deployment_fingerprint": "b" * 64, "certification_fingerprint": "c" * 64, "release_manifest": "manifest.json", "release_manifest_sha256": "d" * 64, "model_data_attestation": "attestation-1"})
            runtime = RuntimeMetadata(kslide_version="0.3.5", opencode_version="1.3.9", opencode_path=None, opencode_config_path=None, provider="internal", reported_model_id="approved:internal", model_family=None, model_size=None, instruction_tuned_status="unknown", vision_support=True, thinking_support=None, provider_backend=None, quantization_or_dtype=None, context_configuration={}, image_preprocessing_settings={}, model_compatibility="production_candidate", discovery_warnings=[])
            policy_check = next(item for item in production_checks(root, runtime) if item["label"] == "Requested/effective model policy")
            self.assertEqual(policy_check["status"], "FAIL")

    def test_asset_manifest_requires_content_hash_and_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            asset = root / "weights.bin"
            asset.write_bytes(b"weights-v1")
            manifest = root / "manifest.json"
            config = root / "PaddleOCR.yaml"
            config.write_text("pipeline: test\n", encoding="utf-8")
            _write(manifest, {"provider": "paddle", "paddlex_config": "PaddleOCR.yaml", "files": [{"path": "PaddleOCR.yaml", "sha256": _sha(config)}, {"path": "weights.bin", "sha256": _sha(asset)}]})
            self.assertTrue(_asset_manifest_status(manifest)[0])
            asset.write_bytes(b"tampered")
            self.assertFalse(_asset_manifest_status(manifest)[0])
            target = Path(outside) / "private.bin"
            target.write_bytes(b"private")
            asset.unlink()
            asset.symlink_to(target)
            self.assertFalse(_asset_manifest_status(manifest)[0])

    def test_release_cli_blocks_requested_certified_without_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "manifest.json"
            result = release_main(["--root", str(root), "--output", str(output), "--requested-state", "PRODUCTION_CERTIFIED", "--require-certified"])
            self.assertEqual(result, 2)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
