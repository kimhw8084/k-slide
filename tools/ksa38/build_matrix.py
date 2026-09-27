#!/usr/bin/env python3
"""Build the fixed KSA-38 matrix from the pinned subject and reviewed row map."""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from traceability import (
    CHANGE_BASE_SHA,
    EXPECTED_FAMILIES,
    EXPECTED_KSA_CLOSURE,
    EXPECTED_OPEN_REPOSITORY_KSAS,
    KSA_SCOPE_REGISTRY_PATH,
    PRODUCT_SUBJECT_SHA,
    PROJECT_OS_SNAPSHOT_PROVENANCE,
    compute_summary,
    render_report,
)


ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "traceability/ksa38/traceability.v1.json"
REPORT = ROOT / "traceability/ksa38/README.md"
DECISION_FIELDS = [
    "meaning", "number", "date", "unit", "table", "cardinality", "trend",
    "owner", "status", "dependency", "risk", "timing", "uncertainty",
    "terminology", "modality",
]
SYMBOL_LOCATORS = {
    "src/k_slide/host_adapter.py": "validate_host_inputs",
    "src/k_slide/ingest.py": "prepare_run",
    "src/k_slide/normalization.py": "normalize_run",
    "src/k_slide/extraction.py": "extract_run",
    "src/k_slide/evidence_ir.py": "EvidenceIR",
    "src/k_slide/translation.py": "parse_translation_patch",
    "src/k_slide/verify.py": "verify_run",
    "src/k_slide/rendering/reports.py": "render_run",
    "src/k_slide/runtime_artifact.py": "verify_runtime_artifact",
    "src/k_slide/runtime.py": "discover_runtime",
    "src/k_slide/opencode_bootstrap.py": "bootstrap_environment",
    "src/k_slide/execution.py": "ExecutionJob",
    "src/k_slide/paas.py": "PaaSController",
    "src/k_slide/worker.py": "main",
    "src/k_slide/resource_budget.py": "ResourceBudget",
    "src/k_slide/environment.py": "RunEnvironmentIdentity",
    "src/k_slide/session.py": "bind_session",
    "src/k_slide/storage.py": "StorageLayout",
    "src/k_slide/retention_policy.py": "RetentionPolicy",
    "src/k_slide/retention.py": "cleanup_expired_runs",
    "src/k_slide/deletion.py": "DeletionCoordinator",
    "src/k_slide/authentication.py": "authenticated_company_service_call",
    "src/k_slide/classification_policy.py": "InferenceDataUsePolicy",
    "src/k_slide/egress_policy.py": "EgressPolicy",
    "src/k_slide/governed_terminology.py": "resolve_governed_termbase",
    "src/k_slide/content_support.py": "ControlledSupportRequest",
    "src/k_slide/security.py": "validate_input",
    "src/k_slide/conflicts.py": "ConflictRegistry",
    "src/k_slide/modality.py": "decision_bearing_status",
    "src/k_slide/zero_korean_study.py": "build_zero_korean_study_payload",
    "src/k_slide/corpus_governance.py": "canonical_manifest",
    "src/k_slide/quality_policy.py": "quality_policy_identity",
    "src/k_slide/bilingual_adjudication.py": "build_internal_bilingual_payload",
    "src/k_slide/recertification.py": "build_champion_promotion",
    "src/k_slide/release_governance.py": "derive_governance_payload",
    "src/k_slide/security_release.py": "candidate_tree_sha256",
    "src/k_slide/rollout.py": "transition_reference_rollout_control",
    "src/k_slide/telemetry.py": "TelemetryWriter",
    "src/k_slide/candidate_revocation.py": "apply_reference_candidate_event",
    "src/k_slide/production.py": "production_checks",
    "src/k_slide/certification.py": "resolve_candidate_spec",
    "src/k_slide/evidence_adapters.py": "derive_payload",
    "evals/model_eval.py": "ModelEvaluationRunner",
    "evals/model_results.py": "aggregate_model_results",
    "evals/performance_load.py": "run_measurement",
    "evals/release.py": "derive_release_state",
    "evals/capture_governance.py": "capture_and_derive",
    "evals/governed_corpus.py": "load_governed_external_cases",
    "evals/corpus_governance.py": "public_synthetic_manifest",
    "evals/security_reports.py": "sanitize_reports",
    "scripts/build_runtime_artifact.py": "build",
    "scripts/verify_runtime_reproducibility.py": "compare",
}
HISTORICAL_PATHS = {
    ".opencode/commands/k-slide-safe.md": "Retired duplicate command surface; the canonical employee entrypoint remains /k-slide.",
    ".opencode/commands/k-slide-strict.md": "Retired duplicate command surface; the canonical employee entrypoint remains /k-slide.",
    "evals/heavy/Dockerfile": "Historical duplicate heavy image definition removed in favor of the canonical pinned deploy/runtime image.",
}


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def read_subject(path: str) -> str:
    return subprocess.check_output(
        ["git", "show", f"{PRODUCT_SUBJECT_SHA}:{path}"], cwd=ROOT, text=True
    )


def first_test_symbol(path: str, tokens: tuple[str, ...]) -> str:
    source = read_subject(path)
    if path.endswith(".py"):
        tree = ast.parse(source)
        names = sorted(
            node.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name.startswith("test_")
        )
    else:
        import re
        names = sorted(set(re.findall(r"\bfunction\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(", source)))
        if "capture" in names:
            names.remove("capture")
            names.insert(0, "capture")
    if not names:
        raise ValueError(f"no decisive test function found in {path}")
    return next((name for name in names if all(token in name for token in tokens)), names[0])


def loc(path: str, symbol: str | None = None) -> dict[str, str]:
    value = {"path": path}
    symbol = symbol or SYMBOL_LOCATORS.get(path)
    if symbol:
        value["symbol"] = symbol
    return value


def test(path: str, *tokens: str) -> dict[str, str]:
    return {"path": path, "symbol": first_test_symbol(path, tuple(tokens))}


def row(
    family: str,
    clause: str,
    summary: str,
    ownership: str,
    ksas: tuple[int, ...],
    implementation_state: str,
    implementation_paths: tuple[str, ...] = (),
    schema_paths: tuple[str, ...] = (),
    tests: tuple[tuple[str, tuple[str, ...]], ...] = (),
    *,
    evidence: str = "REPOSITORY_TESTED_ONLY",
    gaps: tuple[str, ...] = (),
    next_owner: str | None = None,
) -> dict[str, Any]:
    return {
        "trace_id": "",
        "source_section": f"Rounds 1–8 Production Contract / {family} / {clause}",
        "contract_family": family,
        "clause_ids": [clause],
        "requirement_summary": summary,
        "ownership": ownership,
        "linked_ksa_items": [f"KSA-{value:02d}" for value in ksas],
        "project_os_closure": [
            {
                "ksa_id": f"KSA-{value:02d}",
                "state": EXPECTED_KSA_CLOSURE.get(
                    f"KSA-{value:02d}", "NOT_IN_SUPPLIED_SNAPSHOT"
                ),
            }
            for value in ksas
        ],
        "implementation_state": implementation_state,
        "implementation_locators": [loc(path) for path in implementation_paths],
        "schema_config_locators": [loc(path) for path in schema_paths],
        "decisive_test_locators": [test(path, *tokens) for path, tokens in tests],
        "repository_evidence_availability": evidence,
        "gap_classification": list(gaps),
        "next_owner": next_owner,
    }


OS_NEXT = "Project OS item owner to reconcile the repository trace with the accepted KSA scope."
EXT_NEXT = "Company production owner to supply current candidate-bound deployment evidence; Project OS reviews independently."
MIXED_NEXT = "Repository owner maintains the local contract; company deployment owner supplies the external gate evidence; Project OS reconciles closure."


ROWS = [
    row("ROUND_1", "employee_workflow_host_parity_native_invocation", "One employee-visible /k-slide workflow invokes the typed host tools with host parity and no alternate product command.", "REPOSITORY_OWNED", (1, 19), "IMPLEMENTED", (".opencode/plugin/k-slide-host.ts", "src/k_slide/host_adapter.py", ".opencode/tools/kslide.ts"), (".opencode/commands/k-slide.md",), (("tests/test_chg16_host_integration.py", ("normal_employee_tool",)), ("tests/test_chg16_opencode_plugin.ts", ("typed",))),),
    row("ROUND_1", "immutable_source_multifile_evidence_boundaries", "Input references are validated before immutable snapshots and multi-file extraction; source facts and evidence remain engine-owned.", "REPOSITORY_OWNED", (2, 4, 5), "IMPLEMENTED", ("src/k_slide/host_adapter.py", "src/k_slide/ingest.py", "src/k_slide/normalization.py", "src/k_slide/extraction.py", "src/k_slide/evidence_ir.py"), ("schemas/evidence-ir.schema.json",), (("tests/test_chg16_host_integration.py", ("workspace_packet",)), ("tests/test_normalization.py", ()),), gaps=("OPEN_PROJECT_OS_RECONCILIATION",), next_owner=OS_NEXT),
    row("ROUND_1", "decision_view_reconstruction_review_disclosure_evidence_drilldown", "Deterministic reconstruction precedes interpretation; review state and decision summaries retain links to source evidence and unresolved items.", "REPOSITORY_OWNED", (3, 13, 19), "IMPLEMENTED", ("src/k_slide/translation.py", "src/k_slide/verify.py", "src/k_slide/rendering/reports.py", "src/k_slide/cli.py", "src/k_slide/evidence_ir.py"), ("schemas/slide-ir.schema.json", "schemas/translation-patch.schema.json"), (("tests/test_chg16_foundation.py", ()), ("tests/test_certification_closure.py", ("evidence",))),),
    row("ROUND_2", "pinned_runtime_exact_production_model_no_fallback", "The production target is exactly google/gemma-4-31b-it and runtime artifacts are pinned; benchmark, employee, and production routes retain exact model identity, while local results do not establish production qualification.", "MIXED_REPOSITORY_AND_EXTERNAL", (6, 7), "PARTIAL", ("src/k_slide/runtime_artifact.py", "src/k_slide/runtime.py", "src/k_slide/opencode_bootstrap.py", "scripts/build_runtime_artifact.py", "evals/heavy/doctor.py", "evals/model_eval.py", "evals/opencode_runner.py", "src/k_slide/production.py"), ("deploy/runtime/production-requirements.lock", "deploy/runtime/production-dependency-inventory.json", "evals/production-candidate.yaml"), (("tests/test_runtime_artifact.py", ()), ("tests/test_chg16_environment_binding.py", ("runtime",)), ("tests/test_certification_closure.py", ("certifying_model_runner",)), ("tests/test_certification_closure.py", ("actual_model_runner",))), evidence="REPOSITORY_TESTED_EXTERNAL_UNVERIFIED", gaps=("OPEN_EXTERNAL_PRODUCTION_GATE", "OPEN_PROJECT_OS_RECONCILIATION"), next_owner=MIXED_NEXT),
    row("ROUND_2", "durable_resumable_jobs_checkpoint_retry_cancel", "Durable job contracts persist checkpoints and distinguish bounded retry, cancellation, operational failure, and semantic review across worker restarts.", "REPOSITORY_OWNED", (6, 8), "IMPLEMENTED", ("src/k_slide/execution.py", "src/k_slide/paas.py", "src/k_slide/worker.py", "src/k_slide/run_store.py"), (), (("tests/test_chg16_durable_execution.py", ("checkpoint",)), ("tests/test_chg16_paas_worker.py", ("interruption",))), gaps=("OPEN_PROJECT_OS_RECONCILIATION",), next_owner=OS_NEXT),
    row("ROUND_2", "scoped_persistence_queue_concurrency", "Scoped reference admission uses isolated namespaces, bounded active-run capacity, FIFO promotion, and durable compare-and-set state.", "MIXED_REPOSITORY_AND_EXTERNAL", (9,), "PARTIAL", ("src/k_slide/paas.py", "src/k_slide/queue.py", "src/k_slide/resource_budget.py", "src/k_slide/locking.py", "src/k_slide/run_store.py"), ("schemas/resource-budget.schema.json",), (("tests/test_chg16_scoped_admission.py", ("capacity",)), ("tests/test_chg16_resource_budget.py", ("scoped_queue",))), evidence="REPOSITORY_TESTED_EXTERNAL_UNVERIFIED", gaps=("OPEN_EXTERNAL_PRODUCTION_GATE", "OPEN_PROJECT_OS_RECONCILIATION"), next_owner=MIXED_NEXT),
    row("ROUND_2", "exact_run_runtime_model_ocr_termbase_identity", "Resumed runs bind source, runtime, effective model, OCR, configuration, and governed terminology identities without silent identity switching.", "MIXED_REPOSITORY_AND_EXTERNAL", (10,), "PARTIAL", ("src/k_slide/environment.py", "src/k_slide/session.py", "src/k_slide/model.py", "src/k_slide/ocr/policy.py", "src/k_slide/governed_terminology.py"), ("deploy/runtime/system-packages-linux-amd64.json",), (("tests/test_chg16_environment_binding.py", ("identity",)), ("tests/test_ksa19_governed_termbase.py", ("candidate_binding",))), evidence="REPOSITORY_TESTED_EXTERNAL_UNVERIFIED", gaps=("OPEN_EXTERNAL_PRODUCTION_GATE", "OPEN_PROJECT_OS_RECONCILIATION"), next_owner=MIXED_NEXT),
    row("ROUND_3", "three_class_storage", "Content, operational control data, and telemetry use separately classified storage planes with scoped references and path safety.", "REPOSITORY_OWNED", (11,), "IMPLEMENTED", ("src/k_slide/storage.py", "src/k_slide/run_store.py", "src/k_slide/telemetry.py"), (), (("tests/test_chg16_storage_planes.py", ()),), gaps=("OPEN_PROJECT_OS_RECONCILIATION",), next_owner=OS_NEXT),
    row("ROUND_3", "content_vs_operational_retention", "Content retention and operational metadata retention have distinct policy values and cleanup behavior; no implicit duration is supplied.", "REPOSITORY_OWNED", (12,), "IMPLEMENTED", ("src/k_slide/retention_policy.py", "src/k_slide/retention.py", "src/k_slide/deletion.py"), (), (("tests/test_chg16_retention_policy.py", ("split",)), ("tests/test_chg16_deletion.py", ("retention",))), gaps=("OPEN_PROJECT_OS_RECONCILIATION",), next_owner=OS_NEXT),
    row("ROUND_3", "deletion_expiry_legal_hold", "Deletion handles expiry and explicit requests with resumable audit, legal-hold checks, scoped cleanup, and safe operational metadata expiry.", "MIXED_REPOSITORY_AND_EXTERNAL", (13,), "PARTIAL", ("src/k_slide/deletion.py", "src/k_slide/retention.py", "src/k_slide/retention_policy.py"), (), (("tests/test_chg16_deletion.py", ("hold",)),), evidence="REPOSITORY_TESTED_EXTERNAL_UNVERIFIED", gaps=("OPEN_EXTERNAL_PRODUCTION_GATE",), next_owner=EXT_NEXT),
    row("ROUND_4", "accesskey_consumption_nonleakage", "AccessKey is consumed at the authenticated call edge from the process environment and is excluded from persisted, source-bearing, and telemetry payloads.", "REPOSITORY_OWNED", (14, 15), "IMPLEMENTED", ("src/k_slide/access_key_handoff.py", "src/k_slide/authentication.py", "src/k_slide/redaction.py", ".opencode/internal/lib/k-slide-access-key.ts"), (), (("tests/test_chg16_authentication_transport.py", ("process_access_key",)), ("tests/test_chg16_accesskey_nonleakage.py", ("execution",))),),
    row("ROUND_4", "authoritative_classification", "Trusted host classification defaults conservatively and is checked against an exact route and data-use policy before source materialization.", "MIXED_REPOSITORY_AND_EXTERNAL", (16,), "PARTIAL", ("src/k_slide/classification_policy.py", "src/k_slide/host_adapter.py", "src/k_slide/production.py"), (), (("tests/test_chg16_classification_admission.py", ("authoritative",)),), evidence="REPOSITORY_TESTED_EXTERNAL_UNVERIFIED", gaps=("OPEN_EXTERNAL_PRODUCTION_GATE",), next_owner=EXT_NEXT),
    row("ROUND_4", "run_scoped_authorization_tenant_isolation", "Every managed request is bound to deployment-owned run and tenant scope; request-supplied identifiers cannot create authority or cross scope.", "MIXED_REPOSITORY_AND_EXTERNAL", (17,), "PARTIAL", ("src/k_slide/authentication.py", "src/k_slide/paas.py", "src/k_slide/environment.py"), (), (("tests/test_chg17_run_scope_authorization.py", ("cross_scope",)),), evidence="REPOSITORY_TESTED_EXTERNAL_UNVERIFIED", gaps=("OPEN_EXTERNAL_PRODUCTION_GATE",), next_owner=EXT_NEXT),
    row("ROUND_4", "default_deny_egress", "Model and support egress is authorized against a closed capability policy and denied when policy or route identity is missing, invalid, or drifting.", "MIXED_REPOSITORY_AND_EXTERNAL", (18,), "PARTIAL", ("src/k_slide/egress_policy.py", "src/k_slide/opencode_bootstrap.py", "src/k_slide/production.py"), ("security/release-security-policy.json",), (("tests/test_chg18_default_deny_egress.py", ()),), evidence="REPOSITORY_TESTED_EXTERNAL_UNVERIFIED", gaps=("OPEN_EXTERNAL_PRODUCTION_GATE",), next_owner=EXT_NEXT),
    row("ROUND_4", "governed_termbase", "Terminology resolution uses authorized core and scoped overlays with deterministic identity and candidate binding.", "MIXED_REPOSITORY_AND_EXTERNAL", (19,), "PARTIAL", ("src/k_slide/governed_terminology.py", "src/k_slide/terminology.py", "src/k_slide/translation.py"), (), (("tests/test_ksa19_governed_termbase.py", ("authorized",)),), evidence="REPOSITORY_TESTED_EXTERNAL_UNVERIFIED", gaps=("OPEN_EXTERNAL_PRODUCTION_GATE",), next_owner=EXT_NEXT),
    row("ROUND_4", "controlled_content_support", "Content-bearing support is selected by exact run-scoped references, reauthorized at access time, time-limited, and audited without making ordinary support bundles content-bearing.", "MIXED_REPOSITORY_AND_EXTERNAL", (20,), "PARTIAL", ("src/k_slide/content_support.py", "src/k_slide/support.py", "src/k_slide/deletion.py"), (), (("tests/test_ksa20_controlled_content_support.py", ("reauthor",)),), evidence="REPOSITORY_TESTED_EXTERNAL_UNVERIFIED", gaps=("OPEN_EXTERNAL_PRODUCTION_GATE", "OPEN_PROJECT_OS_RECONCILIATION"), next_owner=MIXED_NEXT),
    row("ROUND_4", "adversarial_security_prompt_injection", "Untrusted document content cannot grant tool authority, alter system policy, inject credentials, or bypass bounded evidence and translation contracts.", "REPOSITORY_OWNED", (21,), "IMPLEMENTED", ("src/k_slide/security.py", "src/k_slide/translation_contract.py", "src/k_slide/host_adapter.py"), ("prompts/translation/v1.md",), (("tests/test_ksa21_adversarial_security.py", ()),), gaps=("OPEN_PROJECT_OS_RECONCILIATION",), next_owner=OS_NEXT),
    row("ROUND_5", "source_fact_interpretation_unresolved_provenance", "Source facts, bounded interpretation, and unresolved claims retain distinct provenance links to source regions and translation decisions.", "REPOSITORY_OWNED", (22,), "IMPLEMENTED", ("src/k_slide/evidence_ir.py", "src/k_slide/translation.py", "src/k_slide/semantics.py"), ("schemas/evidence-ir.schema.json", "schemas/translation-patch.schema.json"), (("tests/test_ksa22_provenance.py", ()),), gaps=("OPEN_PROJECT_OS_RECONCILIATION",), next_owner=OS_NEXT),
    row("ROUND_5", "conflict_supersession", "Contradictory claims are represented in a versioned conflict registry with explicit supersession and without rewriting historical evidence.", "REPOSITORY_OWNED", (23,), "IMPLEMENTED", ("src/k_slide/conflicts.py", "src/k_slide/evidence_ir.py"), ("schemas/conflict-registry.schema.json",), (("tests/test_ksa23_conflicts.py", ("supersession",)),), gaps=("OPEN_PROJECT_OS_RECONCILIATION",), next_owner=OS_NEXT),
    row("ROUND_5", "mixed_language_table_chart_diagram_modality_fidelity", "Mixed-language source structure preserves visible tables, chart trends, process edges, labels, counts, units, and modality-specific evidence.", "REPOSITORY_OWNED", (24,), "IMPLEMENTED", ("src/k_slide/modality.py", "src/k_slide/extraction.py", "src/k_slide/numeric.py", "src/k_slide/ir.py"), ("schemas/evidence-ir.schema.json", "schemas/slide-ir.schema.json"), (("tests/test_ksa24_modality_conformance.py", ()), ("tests/test_ksa24_f24_real_path.py", ("table",))), gaps=("OPEN_PROJECT_OS_RECONCILIATION",), next_owner=OS_NEXT),
    row("ROUND_5", "unreadable_decorative_cross_document_recovery_law", "Unreadable, decorative, and cross-document content is routed through explicit evidence and recovery states instead of fabricated conclusions.", "REPOSITORY_OWNED", (25,), "IMPLEMENTED", ("src/k_slide/extraction.py", "src/k_slide/fusion.py", "src/k_slide/verify.py", "src/k_slide/state.py"), ("schemas/evidence-ir.schema.json",), (("tests/test_ksa25_recovery_law.py", ("unreadable",)),), gaps=("OPEN_PROJECT_OS_RECONCILIATION",), next_owner=OS_NEXT),
    row("ROUND_6", "four_set_corpus_governance", "Corpus inputs are partitioned into four governed sets with lifecycle, membership, overlap, contamination, and provenance controls.", "REPOSITORY_OWNED", (26,), "IMPLEMENTED", ("src/k_slide/corpus_governance.py", "evals/corpus_governance.py", "evals/governed_corpus.py"), (), (("tests/test_ksa26_corpus_governance.py", ()), ("tests/test_ksa26_governed_runner.py", ("governed",))), gaps=("OPEN_PROJECT_OS_RECONCILIATION",), next_owner=OS_NEXT),
    row("ROUND_6", "hard_gates_floors_repetition_false_done", "Non-compensable hard gates and category floors apply across repeated runs, including false-DONE, stability calibration, and unaveraged model-fallback failures.", "REPOSITORY_OWNED", (27, 28), "IMPLEMENTED", ("src/k_slide/quality_policy.py", "evals/model_results.py", "evals/model_scorers.py"), (), (("tests/test_ksa27_quality_policy.py", ("model_fallback",)), ("tests/test_ksa28_stability_calibration.py", ("false",))), gaps=("OPEN_PROJECT_OS_RECONCILIATION",), next_owner=OS_NEXT),
    row("ROUND_6", "bilingual_gold_adjudication", "Bilingual gold decisions preserve Korean source, English target, adjudication rationale, and accepted evaluator agreement as governed evidence.", "MIXED_REPOSITORY_AND_EXTERNAL", (29,), "PARTIAL", ("src/k_slide/bilingual_adjudication.py",), (), (("tests/test_ksa29_bilingual_adjudication.py", ()),), evidence="REPOSITORY_TESTED_EXTERNAL_UNVERIFIED", gaps=("OPEN_EXTERNAL_PRODUCTION_GATE", "OPEN_PROJECT_OS_RECONCILIATION"), next_owner=MIXED_NEXT),
    row("ROUND_6", "zero_korean_study", "The zero-Korean comprehension protocol fixes participant eligibility, task order, scoring, and decision rules; repository protocol does not supply human outcomes.", "MIXED_REPOSITORY_AND_EXTERNAL", (30,), "PARTIAL", ("src/k_slide/zero_korean_study.py", "docs/zero-korean-human-study.md"), (), (("tests/test_ksa30_zero_korean_study.py", ()),), evidence="REPOSITORY_TESTED_EXTERNAL_UNVERIFIED", gaps=("OPEN_EXTERNAL_PRODUCTION_GATE", "OPEN_PROJECT_OS_RECONCILIATION"), next_owner=MIXED_NEXT),
    row("ROUND_6", "champion_promotion_scoped_recertification_invalidation", "Champion promotion is evidence-bound; material changes scope recertification and invalidate affected prior evidence and champion state.", "MIXED_REPOSITORY_AND_EXTERNAL", (31,), "PARTIAL", ("src/k_slide/recertification.py", "src/k_slide/certification.py", "evals/release.py"), (), (("tests/test_ksa31_promotion_recertification.py", ("promotion",)),), evidence="REPOSITORY_TESTED_EXTERNAL_UNVERIFIED", gaps=("OPEN_EXTERNAL_PRODUCTION_GATE", "OPEN_PROJECT_OS_RECONCILIATION"), next_owner=MIXED_NEXT),
    row("ROUND_7", "protected_release_governance", "Release governance binds required checks, protected branch facts, code-owner coverage, reviews, and exact candidate identity; local fixtures are not live protection facts.", "MIXED_REPOSITORY_AND_EXTERNAL", (32,), "PARTIAL", ("src/k_slide/release_governance.py", "evals/capture_governance.py", "evals/release.py"), ("security/release-governance-policy.json", ".github/CODEOWNERS", ".github/workflows/k-slide-governance.yml"), (("tests/test_ksa32_release_governance.py", ("candidate",)),), evidence="REPOSITORY_TESTED_EXTERNAL_UNVERIFIED", gaps=("OPEN_EXTERNAL_PRODUCTION_GATE",), next_owner=EXT_NEXT),
    row("ROUND_7", "candidate_bound_security_evidence", "Candidate-bound security evidence rederives minimized scanner, dependency, image, and control results against the exact candidate; no current company scan is claimed.", "MIXED_REPOSITORY_AND_EXTERNAL", (33,), "PARTIAL", ("src/k_slide/security_release.py", "evals/build_security_release_context.py", "evals/security_reports.py", "evals/enforce_security.py"), ("schemas/security-release-evidence.schema.json", "schemas/vulnerability-dispositions.schema.json", "security/release-security-policy.json", ".github/workflows/k-slide-security.yml"), (("tests/test_ksa33_security_release.py", ()),), evidence="REPOSITORY_TESTED_EXTERNAL_UNVERIFIED", gaps=("OPEN_EXTERNAL_PRODUCTION_GATE",), next_owner=EXT_NEXT),
    row("ROUND_7", "rollout_pilot_canary_controls", "Signed candidate-bound rollout transitions and admission controls support disable, contraction, rollback, and staged cohorts; no pilot or canary was run.", "MIXED_REPOSITORY_AND_EXTERNAL", (34,), "PARTIAL", ("src/k_slide/rollout.py", "src/k_slide/production.py"), ("schemas/rollout-control.schema.json",), (("tests/test_ksa34_rollout.py", ("transition",)),), evidence="REPOSITORY_TESTED_EXTERNAL_UNVERIFIED", gaps=("OPEN_EXTERNAL_PRODUCTION_GATE",), next_owner=EXT_NEXT),
    row("ROUND_7", "noncontent_telemetry_issue_reporting", "Telemetry records source-free operational events and run-scoped employee allegations without carrying content or changing evidence or completion.", "MIXED_REPOSITORY_AND_EXTERNAL", (35,), "PARTIAL", ("src/k_slide/telemetry.py", "src/k_slide/support.py"), ("schemas/operational-telemetry-event.schema.json",), (("tests/test_ksa35_product_telemetry.py", ()),), evidence="REPOSITORY_TESTED_EXTERNAL_UNVERIFIED", gaps=("OPEN_EXTERNAL_PRODUCTION_GATE",), next_owner=EXT_NEXT),
    row("ROUND_7", "performance_load_budgets", "Configured input, queue, model, and runtime budgets have deterministic boundary checks and a candidate-bound measurement harness; production SLO and company capacity remain unmeasured.", "MIXED_REPOSITORY_AND_EXTERNAL", (36,), "PARTIAL", ("src/k_slide/resource_budget.py", "evals/performance_load.py"), ("schemas/resource-budget.schema.json",), (("tests/test_chg16_resource_budget.py", ("numeric_limit",)),), evidence="REPOSITORY_TESTED_EXTERNAL_UNVERIFIED", gaps=("OPEN_EXTERNAL_PRODUCTION_GATE",), next_owner=EXT_NEXT),
    row("ROUND_7", "revocation_kill_switch_drift_response", "Candidate-bound signed revocation blocks admission and release and permits recovery only after requalification and safe rollout restoration.", "MIXED_REPOSITORY_AND_EXTERNAL", (37,), "PARTIAL", ("src/k_slide/candidate_revocation.py", "src/k_slide/rollout.py", "src/k_slide/production.py", "evals/release.py"), ("schemas/candidate-revocation.schema.json",), (("tests/test_ksa37_candidate_revocation.py", ("revocation_gate",)),), evidence="REPOSITORY_TESTED_EXTERNAL_UNVERIFIED", gaps=("OPEN_EXTERNAL_PRODUCTION_GATE",), next_owner=EXT_NEXT),
    row("ROUND_7", "external_production_qualification_gates", "Company PaaS, pinned deployed runtime, production Gemma, private human and security data-use evidence, network and IAM authority, performance, governance, pilot, and canary facts require external candidate-bound proof.", "EXTERNAL_PRODUCTION_GATE", (7, 8, 9, 14, 16, 17, 18, 19, 20, 29, 30, 32, 33, 34, 35, 36, 37), "EXTERNAL_ONLY", evidence="EXTERNAL_EVIDENCE_NOT_SUPPLIED", gaps=("OPEN_EXTERNAL_PRODUCTION_GATE",), next_owner=EXT_NEXT),
    row("ROUND_8", "build_completion_traceability_regression_audit_blocker_boundary", "Build evidence must bind exact inputs, tests, changed paths, open blockers, and candidate identity while preserving Project OS as independent auditor and integration authority.", "MIXED_REPOSITORY_AND_EXTERNAL", (32, 33, 34, 35, 36, 37), "PARTIAL", ("src/k_slide/evidence_adapters.py", "src/k_slide/certification.py", "evals/release.py"), (), (("tests/test_certification_closure.py", ("candidate",)),), evidence="REPOSITORY_TESTED_EXTERNAL_UNVERIFIED", gaps=("OPEN_EXTERNAL_PRODUCTION_GATE",), next_owner=EXT_NEXT),
    row("ROUND_8", "build_complete_separate_from_production_certified", "BUILD COMPLETE is a traceability and regression result; PRODUCTION CERTIFIED remains a separate evidence-derived state gated by external production facts.", "MIXED_REPOSITORY_AND_EXTERNAL", (32, 33, 36), "PARTIAL", ("src/k_slide/certification.py", "src/k_slide/production.py", "src/k_slide/release_governance.py", "evals/release.py"), (), (("tests/test_certification_closure.py", ("production",)),), evidence="REPOSITORY_TESTED_EXTERNAL_UNVERIFIED", gaps=("OPEN_EXTERNAL_PRODUCTION_GATE",), next_owner=EXT_NEXT),
]


SOURCE_OWNERS = {
    "src/k_slide/__init__.py": (1,),
    "src/k_slide/access_key_handoff.py": (14, 15),
    "src/k_slide/authentication.py": (14, 15, 17),
    "src/k_slide/bilingual_adjudication.py": (29,),
    "src/k_slide/candidate_revocation.py": (37,),
    "src/k_slide/certification.py": (31, 32, 33, 36, 37),
    "src/k_slide/classification_policy.py": (16,),
    "src/k_slide/cli.py": (1, 3, 19),
    "src/k_slide/conflicts.py": (23,),
    "src/k_slide/content_support.py": (20,),
    "src/k_slide/corpus_governance.py": (26,),
    "src/k_slide/deletion.py": (13, 20),
    "src/k_slide/doctor.py": (7, 12, 16),
    "src/k_slide/egress_policy.py": (18,),
    "src/k_slide/environment.py": (10, 16, 17),
    "src/k_slide/errors.py": (6,),
    "src/k_slide/evidence_adapters.py": (32, 33, 34),
    "src/k_slide/evidence_ir.py": (2, 3, 22),
    "src/k_slide/execution.py": (6,),
    "src/k_slide/extraction.py": (4, 5, 24, 25),
    "src/k_slide/fusion.py": (24, 25),
    "src/k_slide/governed_terminology.py": (19,),
    "src/k_slide/host_adapter.py": (1, 19),
    "src/k_slide/ingest.py": (4, 5),
    "src/k_slide/installer.py": (1,),
    "src/k_slide/io.py": (4,),
    "src/k_slide/ir.py": (2, 3, 24),
    "src/k_slide/locking.py": (9,),
    "src/k_slide/modality.py": (24,),
    "src/k_slide/model.py": (10,),
    "src/k_slide/normalization.py": (4, 5),
    "src/k_slide/numeric.py": (24,),
    "src/k_slide/ocr/paddle.py": (7,),
    "src/k_slide/ocr/policy.py": (7, 10),
    "src/k_slide/opencode_bootstrap.py": (1, 18),
    "src/k_slide/paas.py": (8, 9, 10),
    "src/k_slide/policy.py": (3,),
    "src/k_slide/production.py": (7, 16, 17, 33, 34, 37),
    "src/k_slide/quality_policy.py": (27,),
    "src/k_slide/queue.py": (6, 9),
    "src/k_slide/recertification.py": (31,),
    "src/k_slide/redaction.py": (15,),
    "src/k_slide/release_governance.py": (32, 34),
    "src/k_slide/rendering/reports.py": (3,),
    "src/k_slide/resource_budget.py": (9, 36),
    "src/k_slide/retention.py": (12, 13),
    "src/k_slide/retention_policy.py": (12,),
    "src/k_slide/rollout.py": (34, 37),
    "src/k_slide/run_store.py": (6, 9, 11),
    "src/k_slide/runtime.py": (7,),
    "src/k_slide/runtime_artifact.py": (7,),
    "src/k_slide/security.py": (21,),
    "src/k_slide/security_release.py": (33,),
    "src/k_slide/semantics.py": (22,),
    "src/k_slide/session.py": (10,),
    "src/k_slide/state.py": (6,),
    "src/k_slide/storage.py": (11,),
    "src/k_slide/support.py": (20,),
    "src/k_slide/telemetry.py": (35,),
    "src/k_slide/terminology.py": (19,),
    "src/k_slide/translation.py": (2, 3, 22),
    "src/k_slide/translation_contract.py": (2, 3, 21),
    "src/k_slide/verify.py": (3,),
    "src/k_slide/worker.py": (8,),
    "src/k_slide/zero_korean_study.py": (30,),
    "evals/build_certification_bundle.py": (26, 31),
    "evals/build_security_release_context.py": (33,),
    "evals/capture_governance.py": (32,),
    "evals/certification.py": (31, 36),
    "evals/corpus_governance.py": (26,),
    "evals/download_certification_bundle.py": (26,),
    "evals/enforce_security.py": (33,),
    "evals/freeze_production_dependencies.py": (7,),
    "evals/generate_corpus.py": (26,),
    "evals/governed_corpus.py": (26,),
    "evals/heavy/Dockerfile": (7,),
    "evals/heavy/doctor.py": (7,),
    "evals/heavy/prefetch_ocr_models.py": (7,),
    "evals/heavy/run_checks.py": (7, 24),
    "evals/materialize_certification_bundle.py": (26,),
    "evals/model_eval.py": (27,),
    "evals/model_results.py": (27, 28),
    "evals/model_scorers.py": (27,),
    "evals/noncritical_semantics.py": (27,),
    "evals/opencode_diagnostics.py": (1,),
    "evals/opencode_runner.py": (1, 10),
    "evals/performance_load.py": (36,),
    "evals/production-candidate.example.yaml": (7, 10),
    "evals/production-candidate.yaml": (7, 10),
    "evals/release.py": (32, 36, 37),
    "evals/run_engine_eval.py": (27,),
    "evals/run_model_eval.py": (27,),
    "evals/run_opencode_diagnostics.py": (1,),
    "evals/scenarios.py": (26, 27),
    "evals/security_controls.py": (33,),
    "evals/security_reports.py": (33,),
    "evals/validate_certification_bundle_provenance.py": (26,),
    ".opencode/agents/k-slide.md": (1,),
    ".opencode/commands/k-slide-continue.md": (1,),
    ".opencode/commands/k-slide-help.md": (1,),
    ".opencode/commands/k-slide-safe.md": (1,),
    ".opencode/commands/k-slide-strict.md": (1,),
    ".opencode/commands/k-slide.md": (1,),
    ".opencode/internal/lib/k-slide-access-key.ts": (14,),
    ".opencode/plugin/k-slide-host.ts": (1,),
    ".opencode/skills/k-slide/SKILL.md": (1,),
    ".opencode/skills/k-slide/bin/prepare_run.sh": (1,),
    ".opencode/skills/k-slide/references/troubleshooting.md": (1,),
    ".opencode/tools/kslide.ts": (1,),
    "schemas/candidate-revocation.schema.json": (37,),
    "schemas/conflict-registry.schema.json": (23,),
    "schemas/evidence-ir.schema.json": (2, 22),
    "schemas/operational-telemetry-event.schema.json": (35,),
    "schemas/resource-budget.schema.json": (36,),
    "schemas/rollout-control.schema.json": (34,),
    "schemas/security-release-evidence.schema.json": (33,),
    "schemas/slide-ir.schema.json": (3,),
    "schemas/translation-patch.schema.json": (3, 22),
    "schemas/vulnerability-dispositions.schema.json": (33,),
    "security/release-governance-policy.json": (32,),
    "security/release-security-policy.json": (33,),
    "security/vulnerability-dispositions.json": (33,),
    "deploy/opencode-bootstrap.example.json": (1,),
    "deploy/production-profile.example.json": (7, 10),
    "deploy/runtime/Dockerfile": (7,),
    "deploy/runtime/ocr-context/.keep": (7,),
    "deploy/runtime/production-dependency-inventory.json": (7,),
    "deploy/runtime/production-requirements.lock": (7,),
    "deploy/runtime/system-packages-linux-amd64.json": (7,),
    "scripts/build_runtime_artifact.py": (7,),
    "scripts/launch_opencode_k_slide.py": (1,),
    "scripts/verify_runtime_reproducibility.py": (7,),
    "constraints-production.txt": (7,),
    "pyproject.toml": (7,),
    "opencode.example.jsonc": (1,),
    "prompts/translation/v1.md": (21,),
    ".github/CODEOWNERS": (32,),
    ".github/workflows/k-slide-governance.yml": (32,),
    ".github/workflows/k-slide-phase32.yml": (32,),
    ".github/workflows/k-slide-security.yml": (33,),
}


TEST_TRACE = {
    "test_certification_closure.py": (34, 35),
    "test_chg16_accesskey_nonleakage.py": (11,),
    "test_chg16_authentication_transport.py": (11, 12, 13, 14),
    "test_chg16_classification_admission.py": (12,),
    "test_chg16_deletion.py": (9, 16),
    "test_chg16_durable_execution.py": (5,),
    "test_chg16_environment_binding.py": (4, 8, 13),
    "test_chg16_foundation.py": (2, 3),
    "test_chg16_host_integration.py": (1, 2),
    "test_chg16_opencode_plugin.ts": (1,),
    "test_chg16_paas_worker.py": (5, 7),
    "test_chg16_resource_budget.py": (7, 33),
    "test_chg16_retention_policy.py": (8,),
    "test_chg16_scoped_admission.py": (7,),
    "test_chg16_storage_planes.py": (6,),
    "test_chg17_run_scope_authorization.py": (13,),
    "test_chg18_accesskey_handoff.py": (11,),
    "test_chg18_default_deny_egress.py": (14,),
    "test_chg18_opencode_bootstrap.py": (1, 14),
    "test_ksa19_employee_path.py": (1,),
    "test_ksa19_governed_termbase.py": (15,),
    "test_ksa20_controlled_content_support.py": (16,),
    "test_ksa21_adversarial_security.py": (17, 21),
    "test_ksa22_provenance.py": (15,),
    "test_ksa23_conflicts.py": (19,),
    "test_ksa24_f24_real_path.py": (20,),
    "test_ksa24_f24_repairs.py": (20,),
    "test_ksa24_modality_conformance.py": (20,),
    "test_ksa25_recovery_law.py": (18,),
    "test_ksa26_corpus_governance.py": (22,),
    "test_ksa26_governed_runner.py": (22,),
    "test_ksa27_quality_policy.py": (21,),
    "test_ksa28_stability_calibration.py": (21,),
    "test_ksa29_bilingual_adjudication.py": (24,),
    "test_ksa30_zero_korean_study.py": (25,),
    "test_ksa31_promotion_recertification.py": (26,),
    "test_ksa32_release_governance.py": (30,),
    "test_ksa33_security_release.py": (32,),
    "test_ksa34_rollout.py": (31,),
    "test_ksa35_product_telemetry.py": (33,),
    "test_ksa36_performance_load_budget.py": (33,),
    "test_ksa37_candidate_revocation.py": (30,),
    "test_normalization.py": (2, 4),
    "test_phase1.py": (2, 3),
    "test_phase11.py": (2, 3),
    "test_phase21.py": (3,),
    "test_phase32.py": (30, 32),
    "test_phase33.py": (32,),
    "test_phase34.py": (31,),
    "test_phase35.py": (33,),
    "test_runtime_artifact.py": (4,),
}


def build() -> dict[str, Any]:
    registry_document = json.loads((ROOT / KSA_SCOPE_REGISTRY_PATH).read_text(encoding="utf-8"))
    scope_registry = registry_document["items"]
    ksa_by_clause: dict[tuple[str, str], list[str]] = {}
    for item in scope_registry:
        for mapping in item["mappings"]:
            ksa_by_clause.setdefault((mapping["family_id"], mapping["clause_id"]), []).append(item["ksa_id"])

    for index, item in enumerate(ROWS, start=1):
        item["trace_id"] = f"KSA38-TR-{index:03d}"
    rows_by_number = {int(row["trace_id"][-3:]): row for row in ROWS}
    for item in ROWS:
        pair_list = [(item["contract_family"], clause) for clause in item["clause_ids"]]
        linked = sorted(
            {ksa for pair in pair_list for ksa in ksa_by_clause.get(pair, [])},
            key=lambda ksa: int(ksa[-2:]),
        )
        item["linked_ksa_items"] = linked
        item["project_os_closure"] = [
            {"ksa_id": ksa, "state": EXPECTED_KSA_CLOSURE[ksa]}
            for ksa in linked
        ]
        open_repository_links = [ksa for ksa in linked if ksa in EXPECTED_OPEN_REPOSITORY_KSAS]
        if open_repository_links:
            item["implementation_state"] = "PARTIAL"
            item["gap_classification"] = sorted(set(item["gap_classification"]) | {
                "OPEN_REPOSITORY_REQUIREMENT",
                "OPEN_PROJECT_OS_RECONCILIATION",
            })
            item["next_owner"] = "; ".join(
                registry_document["items"][int(ksa[-2:]) - 1]["future_project_os_owner"]
                for ksa in open_repository_links
            )
        elif item["clause_ids"] == ["immutable_source_multifile_evidence_boundaries"]:
            # This row carried reconciliation gaps only because the predecessor attached KSA-04/05 here.
            item["gap_classification"] = []
            item["next_owner"] = None
    row_number_by_ksa: dict[int, int] = {}
    for index, item in enumerate(ROWS, start=1):
        for ksa_id in item["linked_ksa_items"]:
            row_number_by_ksa.setdefault(int(ksa_id[-2:]), index)

    def trace_ids(numbers: tuple[int, ...]) -> list[str]:
        return list(dict.fromkeys(f"KSA38-TR-{number:03d}" for number in numbers))

    changed_paths = git(
        "diff", "--name-only", CHANGE_BASE_SHA, PRODUCT_SUBJECT_SHA
    ).splitlines()
    coverage: list[dict[str, Any]] = []
    for path in changed_paths:
        if path.startswith(".codex-fabric/"):
            coverage.append({
                "path": path,
                "historical": False,
                "coverage_type": "NON_PRODUCT_PATH_CLASSIFICATION",
                "trace_ids": [],
                "classification": "AUDIT_EVIDENCE",
                "reason": "Committed historical candidate-side audit or qualification evidence at the immutable subject; not adopted as a current KSA-38 receipt.",
            })
            continue
        if path in HISTORICAL_PATHS:
            coverage.append({
                "path": path,
                "historical": True,
                "coverage_type": "NON_PRODUCT_PATH_CLASSIFICATION",
                "trace_ids": [],
                "classification": "MIGRATION_COMPATIBILITY",
                "reason": HISTORICAL_PATHS[path],
            })
            continue
        if path.startswith("tests/"):
            name = Path(path).name
            related = TEST_TRACE.get(name, ())
            linked = trace_ids(tuple(row_number_by_ksa[n] for n in related if n in row_number_by_ksa))
            fixture = "/fixtures/" in path or "fixture" in name or "fixtures" in name
            coverage.append({
                "path": path,
                "historical": False,
                "coverage_type": "NON_PRODUCT_PATH_CLASSIFICATION",
                "trace_ids": linked,
                "classification": "FIXTURE" if fixture else "TEST",
                "reason": (
                    "Test-only fixture/support input; exact related trace rows are listed when applicable."
                    if fixture else "Repository regression test module; exact related trace rows are listed when applicable."
                ),
            })
            continue
        if path.startswith("docs/") or (path.endswith(".md") and path not in SOURCE_OWNERS) or path in {
            "README.md", "DEVELOPMENT_NOTES.md", "IMPLEMENTATION_STATUS.md",
            "SOURCE_PROVENANCE.md", "evals/README.md", "evals/EVAL_REPORT.md",
            "private-evals/README.md", "deploy/README.md",
        }:
            coverage.append({
                "path": path,
                "historical": False,
                "coverage_type": "NON_PRODUCT_PATH_CLASSIFICATION",
                "trace_ids": [],
                "classification": "DOCUMENTATION",
                "reason": "Documentation or architecture record; it explains the product contract but is not executable product behavior.",
            })
            continue
        if path.startswith(".github/workflows/"):
            ksa_number = 33 if "security" in path else 32
            number = row_number_by_ksa[ksa_number]
            coverage.append({
                "path": path,
                "historical": False,
                "coverage_type": "REQUIREMENT_ROW",
                "trace_ids": trace_ids((number,)),
                "classification": None,
                "reason": "",
            })
            rows_by_number[number]["schema_config_locators"].append(loc(path))
            continue
        if path not in SOURCE_OWNERS:
            raise ValueError(f"changed path has no explicit KSA-38 owner or classification: {path}")
        owner_ksa_numbers = SOURCE_OWNERS[path]
        owner_numbers = tuple(row_number_by_ksa[number] for number in owner_ksa_numbers)
        linked = trace_ids(owner_numbers)
        is_schema_config = (
            path.startswith(("schemas/", "security/", "deploy/", ".github/"))
            or path in {"constraints-production.txt", "pyproject.toml", "opencode.example.jsonc"}
            or path.endswith((".yaml", ".yml", ".json", ".jsonc", ".lock", ".txt"))
        )
        for number in owner_numbers:
            field = "schema_config_locators" if is_schema_config else "implementation_locators"
            if all(existing["path"] != path for existing in rows_by_number[number][field]):
                rows_by_number[number][field].append(loc(path))
        coverage.append({
            "path": path,
            "historical": False,
            "coverage_type": "REQUIREMENT_ROW",
            "trace_ids": linked,
            "classification": None,
            "reason": "",
        })

    canonical = [
        {
            "family_id": family,
            "source_section": f"Rounds 1–8 Production Contract / {family}",
            "canonical_clause_ids": list(clauses),
        }
        for family, clauses in EXPECTED_FAMILIES.items()
    ]
    matrix: dict[str, Any] = {
        "schema_version": "1.0",
        "matrix_version": "1.0",
        "project": "k-slide",
        "change_id": "CHG-16 / KSA-38",
        "product_subject": {
            "commit_sha": PRODUCT_SUBJECT_SHA,
            "tree_oid": git("rev-parse", f"{PRODUCT_SUBJECT_SHA}^{{tree}}"),
        },
        "change_span": {
            "change_base_sha": CHANGE_BASE_SHA,
            "change_base_tree_oid": git("rev-parse", f"{CHANGE_BASE_SHA}^{{tree}}"),
            "commit_count": int(git("rev-list", "--count", f"{CHANGE_BASE_SHA}..{PRODUCT_SUBJECT_SHA}")),
            "changed_path_count": len(changed_paths),
            "changed_path_coverage": coverage,
        },
        "repository_anchors": [
            {
                "role": "PRODUCT_SUBJECT",
                "commit_sha": PRODUCT_SUBJECT_SHA,
                "tree_oid": git("rev-parse", f"{PRODUCT_SUBJECT_SHA}^{{tree}}"),
                "independently_rederivable": True,
            },
            {
                "role": "CHG16_CHANGE_BASE",
                "commit_sha": CHANGE_BASE_SHA,
                "tree_oid": git("rev-parse", f"{CHANGE_BASE_SHA}^{{tree}}"),
                "independently_rederivable": True,
            },
        ],
        "project_os_closure_snapshot": {
            "authority": PROJECT_OS_SNAPSHOT_PROVENANCE,
            "items": [
                {"ksa_id": ksa, "state": state}
                for ksa, state in sorted(
                    EXPECTED_KSA_CLOSURE.items(), key=lambda item: int(item[0][-2:])
                )
            ],
        },
        "ksa_scope_registry": scope_registry,
        "canonical_contract_families": canonical,
        "trace_rows": ROWS,
        "core_invariants": {
            "production_target_model": "google/gemma-4-31b-it",
            "benchmark_user_production_path_equal": True,
            "decision_critical_fields": DECISION_FIELDS,
            "silent_model_fallback_allowed": False,
            "release_state_source": "EVIDENCE_DERIVED",
            "production_certification_external_gates_separate": True,
        },
        "evidence_provenance": {
            "closure_snapshot_source": PROJECT_OS_SNAPSHOT_PROVENANCE,
            "historical_fabric_receipts_claimed": False,
            "notion_only_locators_claimed": False,
            "external_production_evidence_claimed": False,
        },
        "summary": {},
    }
    matrix["summary"] = compute_summary(matrix)
    return matrix


def main() -> int:
    matrix = build()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(matrix, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    REPORT.write_text(render_report(matrix), encoding="utf-8")
    print(f"Wrote {OUT.relative_to(ROOT)} and {REPORT.relative_to(ROOT)} ({len(ROWS)} trace rows).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
