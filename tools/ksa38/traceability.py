"""Validation and rendering for the KSA-38 product traceability matrix."""

from __future__ import annotations

import ast
import json
import re
import subprocess
from collections import Counter
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


PRODUCT_SUBJECT_SHA = "23669bacb0392aecc009ae19c7b8c645f1d8c7dd"
CHANGE_BASE_SHA = "af5836540304b424289bedbe57a87dbb5d02763f"
KSA_SCOPE_REGISTRY_PATH = "traceability/ksa38/ksa-scope-registry.v1.json"
PROJECT_OS_SNAPSHOT_PROVENANCE = "PROJECT_OS_BOUND_DISPATCH_SNAPSHOT"
EXPECTED_COMMIT_COUNT = 152
EXPECTED_CHANGED_PATH_COUNT = 229

EXPECTED_FAMILIES: dict[str, tuple[str, ...]] = {
    "ROUND_1": (
        "employee_workflow_host_parity_native_invocation",
        "immutable_source_multifile_evidence_boundaries",
        "decision_view_reconstruction_review_disclosure_evidence_drilldown",
    ),
    "ROUND_2": (
        "pinned_runtime_exact_production_model_no_fallback",
        "durable_resumable_jobs_checkpoint_retry_cancel",
        "scoped_persistence_queue_concurrency",
        "exact_run_runtime_model_ocr_termbase_identity",
    ),
    "ROUND_3": (
        "three_class_storage",
        "content_vs_operational_retention",
        "deletion_expiry_legal_hold",
    ),
    "ROUND_4": (
        "accesskey_consumption_nonleakage",
        "authoritative_classification",
        "run_scoped_authorization_tenant_isolation",
        "default_deny_egress",
        "governed_termbase",
        "controlled_content_support",
        "adversarial_security_prompt_injection",
    ),
    "ROUND_5": (
        "source_fact_interpretation_unresolved_provenance",
        "conflict_supersession",
        "mixed_language_table_chart_diagram_modality_fidelity",
        "unreadable_decorative_cross_document_recovery_law",
    ),
    "ROUND_6": (
        "four_set_corpus_governance",
        "hard_gates_floors_repetition_false_done",
        "bilingual_gold_adjudication",
        "zero_korean_study",
        "champion_promotion_scoped_recertification_invalidation",
    ),
    "ROUND_7": (
        "protected_release_governance",
        "candidate_bound_security_evidence",
        "rollout_pilot_canary_controls",
        "noncontent_telemetry_issue_reporting",
        "performance_load_budgets",
        "revocation_kill_switch_drift_response",
        "external_production_qualification_gates",
    ),
    "ROUND_8": (
        "build_completion_traceability_regression_audit_blocker_boundary",
        "build_complete_separate_from_production_certified",
    ),
}

EXPECTED_KSA_CLOSURE: dict[str, str] = {
    **{f"KSA-{n:02d}": "DONE_INTEGRATED" for n in (1, 2, 3, 6)},
    **{f"KSA-{n:02d}": "DONE_INTEGRATED" for n in range(13, 20)},
    **{f"KSA-{n:02d}": "DONE_INTEGRATED" for n in range(32, 38)},
    "KSA-07": "ACTIVE_VERIFY_REQUIRED",
    "KSA-20": "ACTIVE",
    **{
        f"KSA-{n:02d}": "QUEUED"
        for n in (4, 5, 8, 9, 10, 11, 12, *range(21, 32))
    },
}

EXPECTED_KSA_CLAUSES: dict[str, tuple[tuple[str, str], ...]] = {
    "KSA-01": (("ROUND_2", "durable_resumable_jobs_checkpoint_retry_cancel"),),
    "KSA-02": (("ROUND_1", "employee_workflow_host_parity_native_invocation"),),
    "KSA-03": (("ROUND_1", "employee_workflow_host_parity_native_invocation"), ("ROUND_1", "immutable_source_multifile_evidence_boundaries")),
    "KSA-04": (("ROUND_1", "employee_workflow_host_parity_native_invocation"),),
    "KSA-05": (("ROUND_1", "employee_workflow_host_parity_native_invocation"), ("ROUND_1", "decision_view_reconstruction_review_disclosure_evidence_drilldown")),
    "KSA-06": (("ROUND_2", "durable_resumable_jobs_checkpoint_retry_cancel"),),
    "KSA-07": (("ROUND_2", "pinned_runtime_exact_production_model_no_fallback"), ("ROUND_7", "external_production_qualification_gates")),
    "KSA-08": (("ROUND_2", "durable_resumable_jobs_checkpoint_retry_cancel"), ("ROUND_7", "external_production_qualification_gates")),
    "KSA-09": (("ROUND_2", "scoped_persistence_queue_concurrency"), ("ROUND_7", "external_production_qualification_gates")),
    "KSA-10": (("ROUND_2", "exact_run_runtime_model_ocr_termbase_identity"), ("ROUND_7", "external_production_qualification_gates")),
    "KSA-11": (("ROUND_3", "three_class_storage"),),
    "KSA-12": (("ROUND_3", "content_vs_operational_retention"),),
    "KSA-13": (("ROUND_3", "deletion_expiry_legal_hold"),),
    "KSA-14": (("ROUND_4", "accesskey_consumption_nonleakage"), ("ROUND_7", "external_production_qualification_gates")),
    "KSA-15": (("ROUND_4", "accesskey_consumption_nonleakage"),),
    "KSA-16": (("ROUND_4", "authoritative_classification"), ("ROUND_7", "external_production_qualification_gates")),
    "KSA-17": (("ROUND_4", "run_scoped_authorization_tenant_isolation"), ("ROUND_7", "external_production_qualification_gates")),
    "KSA-18": (("ROUND_4", "default_deny_egress"), ("ROUND_7", "external_production_qualification_gates")),
    "KSA-19": (("ROUND_4", "governed_termbase"), ("ROUND_7", "external_production_qualification_gates")),
    "KSA-20": (("ROUND_4", "controlled_content_support"), ("ROUND_7", "external_production_qualification_gates")),
    "KSA-21": (("ROUND_4", "adversarial_security_prompt_injection"), ("ROUND_7", "external_production_qualification_gates")),
    "KSA-22": (("ROUND_5", "source_fact_interpretation_unresolved_provenance"),),
    "KSA-23": (("ROUND_5", "conflict_supersession"),),
    "KSA-24": (("ROUND_5", "mixed_language_table_chart_diagram_modality_fidelity"),),
    "KSA-25": (("ROUND_5", "unreadable_decorative_cross_document_recovery_law"),),
    "KSA-26": (("ROUND_6", "four_set_corpus_governance"),),
    "KSA-27": (("ROUND_6", "hard_gates_floors_repetition_false_done"),),
    "KSA-28": (("ROUND_6", "hard_gates_floors_repetition_false_done"),),
    "KSA-29": (("ROUND_6", "bilingual_gold_adjudication"), ("ROUND_7", "external_production_qualification_gates")),
    "KSA-30": (("ROUND_6", "zero_korean_study"), ("ROUND_7", "external_production_qualification_gates")),
    "KSA-31": (("ROUND_6", "champion_promotion_scoped_recertification_invalidation"), ("ROUND_7", "external_production_qualification_gates")),
    "KSA-32": (("ROUND_7", "protected_release_governance"), ("ROUND_7", "external_production_qualification_gates"), ("ROUND_8", "build_completion_traceability_regression_audit_blocker_boundary"), ("ROUND_8", "build_complete_separate_from_production_certified")),
    "KSA-33": (("ROUND_7", "candidate_bound_security_evidence"), ("ROUND_7", "external_production_qualification_gates"), ("ROUND_8", "build_completion_traceability_regression_audit_blocker_boundary"), ("ROUND_8", "build_complete_separate_from_production_certified")),
    "KSA-34": (("ROUND_7", "rollout_pilot_canary_controls"), ("ROUND_7", "external_production_qualification_gates"), ("ROUND_8", "build_completion_traceability_regression_audit_blocker_boundary"), ("ROUND_8", "build_complete_separate_from_production_certified")),
    "KSA-35": (("ROUND_7", "noncontent_telemetry_issue_reporting"), ("ROUND_7", "external_production_qualification_gates"), ("ROUND_8", "build_completion_traceability_regression_audit_blocker_boundary"), ("ROUND_8", "build_complete_separate_from_production_certified")),
    "KSA-36": (("ROUND_7", "performance_load_budgets"), ("ROUND_7", "external_production_qualification_gates"), ("ROUND_8", "build_completion_traceability_regression_audit_blocker_boundary"), ("ROUND_8", "build_complete_separate_from_production_certified")),
    "KSA-37": (("ROUND_7", "revocation_kill_switch_drift_response"), ("ROUND_7", "external_production_qualification_gates"), ("ROUND_8", "build_completion_traceability_regression_audit_blocker_boundary"), ("ROUND_8", "build_complete_separate_from_production_certified")),
}
EXPECTED_OPEN_REPOSITORY_KSAS = {"KSA-04", "KSA-05"}

GAP_CATEGORIES = {
    "OPEN_REPOSITORY_REQUIREMENT",
    "OPEN_EXTERNAL_PRODUCTION_GATE",
    "OPEN_PROJECT_OS_RECONCILIATION",
    "ORPHAN_REQUIREMENT",
}


class TraceabilityError(ValueError):
    """Raised when the matrix is structurally or semantically incomplete."""


def _git(root: Path, *args: str, check: bool = True) -> str:
    result = subprocess.run(
        ["git", *args], cwd=root, text=True, capture_output=True, check=False
    )
    if check and result.returncode:
        raise TraceabilityError(
            f"git {' '.join(args)} failed ({result.returncode}): {result.stderr.strip()}"
        )
    return result.stdout.strip()


@lru_cache(maxsize=None)
def _at_subject(root: Path, subject: str, path: str) -> bool:
    return subprocess.run(
        ["git", "cat-file", "-e", f"{subject}:{path}"],
        cwd=root,
        capture_output=True,
        check=False,
    ).returncode == 0


@lru_cache(maxsize=None)
def _subject_text(root: Path, subject: str, path: str) -> str:
    return subprocess.run(
        ["git", "show", f"{subject}:{path}"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    ).stdout


@lru_cache(maxsize=None)
def _symbol_exists(root: Path, subject: str, path: str, symbol: str) -> bool:
    text = _subject_text(root, subject, path)
    if path.endswith(".py"):
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return False
        return any(
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and node.name == symbol
            for node in ast.walk(tree)
        )
    if path.endswith((".ts", ".tsx", ".js", ".jsx")):
        patterns = (
            rf"\bfunction\s+{re.escape(symbol)}\b",
            rf"\b(?:const|let|var)\s+{re.escape(symbol)}\s*=",
            rf"\bclass\s+{re.escape(symbol)}\b",
            rf"\b{re.escape(symbol)}\s*\(",
        )
        return any(re.search(pattern, text) for pattern in patterns)
    return symbol in text


def _validate_locator(
    root: Path, subject: str, locator: dict[str, Any], label: str, *, test: bool = False
) -> None:
    path = locator["path"]
    if "*" in path:
        raise TraceabilityError(f"{label} uses a wildcard instead of a concrete path: {path}")
    if not _at_subject(root, subject, path):
        if locator.get("historical") is True:
            return
        raise TraceabilityError(f"{label} path is absent from product subject: {path}")
    symbol = locator.get("symbol")
    if test and (not symbol or not _symbol_exists(root, subject, path, symbol)):
        raise TraceabilityError(f"test locator does not resolve in product subject: {path}::{symbol}")
    if symbol and not _symbol_exists(root, subject, path, symbol):
        raise TraceabilityError(f"symbol locator does not resolve in product subject: {path}::{symbol}")


def _count_values(values: list[str], keys: list[str]) -> dict[str, int]:
    count = Counter(values)
    return {key: count.get(key, 0) for key in keys}


def compute_summary(matrix: dict[str, Any]) -> dict[str, Any]:
    rows = matrix["trace_rows"]
    family_ids = list(EXPECTED_FAMILIES)
    ownerships = [
        "REPOSITORY_OWNED",
        "MIXED_REPOSITORY_AND_EXTERNAL",
        "EXTERNAL_PRODUCTION_GATE",
    ]
    implementation_states = [
        "IMPLEMENTED",
        "PARTIAL",
        "REUSED_UNCHANGED",
        "NOT_IMPLEMENTED",
        "EXTERNAL_ONLY",
    ]
    closures = [
        "DONE_INTEGRATED",
        "ACTIVE_VERIFY_REQUIRED",
        "ACTIVE",
        "QUEUED",
        "NOT_IN_SUPPLIED_SNAPSHOT",
    ]
    closure_links = [
        link["state"] for row in rows for link in row["project_os_closure"]
    ]
    gap_values = [
        gap for row in rows for gap in row["gap_classification"]
    ]
    path_rows = matrix["change_span"]["changed_path_coverage"]
    requirement_paths = sum(
        item["coverage_type"] == "REQUIREMENT_ROW" for item in path_rows
    )
    classified_paths = sum(
        item["coverage_type"] == "NON_PRODUCT_PATH_CLASSIFICATION"
        for item in path_rows
    )
    ksa_coverage = sorted(
        {
            item
            for row in rows
            for item in row["linked_ksa_items"]
            if item in EXPECTED_KSA_CLOSURE
        }
    )
    clause_links = {
        (row["contract_family"], clause)
        for row in rows
        for clause in row["clause_ids"]
    }
    required_clause_count = sum(len(items) for items in EXPECTED_FAMILIES.values())
    crosswalk_link_count = sum(
        len(item["mappings"]) for item in matrix["ksa_scope_registry"]
    )
    mapping_states = [
        mapping["implementation_state"]
        for item in matrix["ksa_scope_registry"]
        for mapping in item["mappings"]
    ]
    return {
        "trace_rows": len(rows),
        "rows_by_contract_family": _count_values(
            [row["contract_family"] for row in rows], family_ids
        ),
        "rows_by_ownership": _count_values(
            [row["ownership"] for row in rows], ownerships
        ),
        "rows_by_implementation_state": _count_values(
            [row["implementation_state"] for row in rows], implementation_states
        ),
        "trace_links_by_project_os_closure_state": _count_values(
            closure_links, closures
        ),
        "project_os_ksa_items_by_closure_state": _count_values(
            [item["state"] for item in matrix["project_os_closure_snapshot"]["items"]],
            closures[:-1],
        ),
        "ksa_coverage": {
            "required_items": len(EXPECTED_KSA_CLOSURE),
            "covered_items": len(ksa_coverage),
            "missing_items": sorted(set(EXPECTED_KSA_CLOSURE) - set(ksa_coverage)),
        },
        "canonical_clause_coverage": {
            "required_clauses": required_clause_count,
            "covered_clauses": len(clause_links),
            "missing_clauses": [
                f"{family}:{clause}"
                for family, clauses in EXPECTED_FAMILIES.items()
                for clause in clauses
                if (family, clause) not in clause_links
            ],
        },
        "ksa_clause_crosswalk": {
            "required_links": sum(len(links) for links in EXPECTED_KSA_CLAUSES.values()),
            "covered_links": crosswalk_link_count,
            "missing_links": [],
            "mappings_by_implementation_state": _count_values(mapping_states, implementation_states),
        },
        "changed_path_coverage": {
            "expected_paths": len(path_rows),
            "requirement_referenced_paths": requirement_paths,
            "closed_classification_paths": classified_paths,
            "unexplained_paths": 0,
        },
        "rows_by_gap_classification": _count_values(
            gap_values, sorted(GAP_CATEGORIES)
        ),
        "orphan_requirement_count": sum(
            "ORPHAN_REQUIREMENT" in row["gap_classification"] for row in rows
        ),
    }


def validate_matrix(
    root: Path,
    matrix: dict[str, Any],
    schema: dict[str, Any],
    *,
    expected_subject: str = PRODUCT_SUBJECT_SHA,
    expected_change_base: str = CHANGE_BASE_SHA,
) -> dict[str, Any]:
    Draft202012Validator.check_schema(schema)
    errors = sorted(
        Draft202012Validator(schema).iter_errors(matrix),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        first = errors[0]
        location = "/".join(str(item) for item in first.absolute_path) or "$"
        raise TraceabilityError(f"schema validation failed at {location}: {first.message}")

    subject = matrix["product_subject"]
    change = matrix["change_span"]
    if subject["commit_sha"] != expected_subject:
        raise TraceabilityError("matrix product_subject_sha does not match the requested immutable subject")
    if change["change_base_sha"] != expected_change_base:
        raise TraceabilityError("matrix change_base_sha does not match the accepted CHG-16 base")
    if _git(root, "rev-parse", f"{subject['commit_sha']}^{{commit}}") != subject["commit_sha"]:
        raise TraceabilityError("product subject is not an exact repository commit")
    if _git(root, "rev-parse", f"{change['change_base_sha']}^{{commit}}") != change["change_base_sha"]:
        raise TraceabilityError("change base is not an exact repository commit")
    actual_subject_tree = _git(root, "rev-parse", f"{subject['commit_sha']}^{{tree}}")
    actual_base_tree = _git(root, "rev-parse", f"{change['change_base_sha']}^{{tree}}")
    if actual_subject_tree != subject["tree_oid"] or actual_base_tree != change["change_base_tree_oid"]:
        raise TraceabilityError("recorded Git tree identity does not match its commit")
    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", change["change_base_sha"], subject["commit_sha"]],
        cwd=root,
        check=False,
        capture_output=True,
    )
    if ancestor.returncode != 0:
        raise TraceabilityError("accepted CHG-16 change base is not an ancestor of the product subject")
    commit_count = int(_git(root, "rev-list", "--count", f"{change['change_base_sha']}..{subject['commit_sha']}"))
    changed_paths = _git(
        root, "diff", "--name-only", change["change_base_sha"], subject["commit_sha"]
    ).splitlines()
    if commit_count != EXPECTED_COMMIT_COUNT or change["commit_count"] != commit_count:
        raise TraceabilityError(f"change span commit count is {commit_count}, expected {EXPECTED_COMMIT_COUNT}")
    if len(changed_paths) != EXPECTED_CHANGED_PATH_COUNT or change["changed_path_count"] != len(changed_paths):
        raise TraceabilityError(f"change span path count is {len(changed_paths)}, expected {EXPECTED_CHANGED_PATH_COUNT}")

    snapshot = matrix["project_os_closure_snapshot"]
    snapshot_map = {item["ksa_id"]: item["state"] for item in snapshot["items"]}
    if snapshot["authority"] != PROJECT_OS_SNAPSHOT_PROVENANCE:
        raise TraceabilityError("Project OS closure snapshot provenance is not the bound-dispatch snapshot")
    if snapshot_map != EXPECTED_KSA_CLOSURE:
        raise TraceabilityError("Project OS closure snapshot differs from the binding-time Project OS state")
    if matrix["evidence_provenance"]["closure_snapshot_source"] != PROJECT_OS_SNAPSHOT_PROVENANCE:
        raise TraceabilityError("closure snapshot source is not identified as the bound-dispatch snapshot")

    registry_doc = load_json(root / KSA_SCOPE_REGISTRY_PATH)
    registry = matrix["ksa_scope_registry"]
    if registry_doc.get("authority") != "PROJECT_OS_BOUND_DISPATCH" or registry_doc.get("items") != registry:
        raise TraceabilityError("matrix KSA scope registry differs from the checked-in Project OS crosswalk")
    registry_by_id = {item["ksa_id"]: item for item in registry}
    if len(registry_by_id) != len(registry) or set(registry_by_id) != set(EXPECTED_KSA_CLOSURE):
        raise TraceabilityError("KSA scope registry must contain each KSA-01 through KSA-37 exactly once")
    observed_crosswalk: dict[str, tuple[tuple[str, str], ...]] = {}
    expected_ksas_by_clause: dict[tuple[str, str], set[str]] = {}
    for ksa_id, item in registry_by_id.items():
        mappings = item["mappings"]
        pairs = tuple((mapping["family_id"], mapping["clause_id"]) for mapping in mappings)
        if pairs != EXPECTED_KSA_CLAUSES[ksa_id]:
            raise TraceabilityError(f"{ksa_id} semantic crosswalk does not match its closed canonical scope")
        if item["repository_requirement_open"] != (ksa_id in EXPECTED_OPEN_REPOSITORY_KSAS):
            raise TraceabilityError(f"{ksa_id} repository-scope status differs from the closed Project OS registry")
        if item["repository_requirement_open"] and not item["future_project_os_owner"]:
            raise TraceabilityError(f"{ksa_id} open repository scope has no future Project OS owner")
        if item["repository_requirement_open"] and any(
            mapping["implementation_state"] in {"IMPLEMENTED", "REUSED_UNCHANGED"}
            for mapping in mappings
        ):
            raise TraceabilityError(f"{ksa_id} queued scope is falsely marked fully implemented in its semantic crosswalk")
        observed_crosswalk[ksa_id] = pairs
        for family, clause in pairs:
            expected_ksas_by_clause.setdefault((family, clause), set()).add(ksa_id)
    if set(observed_crosswalk) != set(EXPECTED_KSA_CLAUSES):
        raise TraceabilityError("semantic KSA crosswalk does not cover the closed KSA registry")

    canonical_families = {
        item["family_id"]: item["canonical_clause_ids"]
        for item in matrix["canonical_contract_families"]
    }
    if canonical_families != {key: list(value) for key, value in EXPECTED_FAMILIES.items()}:
        raise TraceabilityError("canonical contract family catalogue differs from the supplied Rounds 1–8 clauses")

    expected_clause_pairs = {
        (family, clause)
        for family, clauses in EXPECTED_FAMILIES.items()
        for clause in clauses
    }
    row_ids: set[str] = set()
    seen_clause_pairs: set[tuple[str, str]] = set()
    seen_ksa_ids: set[str] = set()
    trace_lookup = {row["trace_id"]: row for row in matrix["trace_rows"]}
    if len(trace_lookup) != len(matrix["trace_rows"]):
        raise TraceabilityError("trace IDs are not unique")
    trace_ids = set(trace_lookup)
    for row in matrix["trace_rows"]:
        if row["trace_id"] in row_ids:
            raise TraceabilityError(f"duplicate trace ID: {row['trace_id']}")
        row_ids.add(row["trace_id"])
        if row["contract_family"] not in EXPECTED_FAMILIES:
            raise TraceabilityError(f"unknown contract family: {row['contract_family']}")
        for clause in row["clause_ids"]:
            pair = (row["contract_family"], clause)
            if pair not in expected_clause_pairs:
                raise TraceabilityError(f"unknown canonical contract clause: {pair}")
            if pair in seen_clause_pairs:
                raise TraceabilityError(f"canonical contract clause is multiply assigned: {pair}")
            seen_clause_pairs.add(pair)
        expected_linked = set().union(*(
            expected_ksas_by_clause[(row["contract_family"], clause)]
            for clause in row["clause_ids"]
        ))
        actual_linked = set(row["linked_ksa_items"])
        if actual_linked != expected_linked:
            raise TraceabilityError(
                f"{row['trace_id']} semantic KSA crosswalk mismatch; "
                f"expected={sorted(expected_linked)}, actual={sorted(actual_linked)}"
            )
        for linked_id in row["linked_ksa_items"]:
            seen_ksa_ids.add(linked_id)
        if row["gap_classification"] and not row["next_owner"]:
            raise TraceabilityError(f"{row['trace_id']} has an open gap without a next owner")
        open_repository_links = actual_linked & EXPECTED_OPEN_REPOSITORY_KSAS
        if open_repository_links:
            if row["implementation_state"] not in {"PARTIAL", "NOT_IMPLEMENTED"}:
                raise TraceabilityError(
                    f"queued KSA scope {sorted(open_repository_links)} is falsely marked fully implemented in {row['trace_id']}"
                )
            required_gaps = {"OPEN_REPOSITORY_REQUIREMENT", "OPEN_PROJECT_OS_RECONCILIATION"}
            if not required_gaps <= set(row["gap_classification"]):
                raise TraceabilityError(
                    f"open KSA repository scope in {row['trace_id']} lacks repository and Project OS gap classifications"
                )
            for ksa_id in open_repository_links:
                owner = registry_by_id[ksa_id]["future_project_os_owner"]
                if not row["next_owner"] or ksa_id not in row["next_owner"] or "Project OS" not in row["next_owner"] or ksa_id not in owner:
                    raise TraceabilityError(f"open {ksa_id} scope in {row['trace_id']} lacks its future Project OS owner")
        closure_links = {link["ksa_id"]: link["state"] for link in row["project_os_closure"]}
        if set(closure_links) != set(row["linked_ksa_items"]):
            raise TraceabilityError(f"{row['trace_id']} closure links do not match its KSA links")
        for ksa_id, state in closure_links.items():
            expected_state = EXPECTED_KSA_CLOSURE.get(ksa_id, "NOT_IN_SUPPLIED_SNAPSHOT")
            if state != expected_state:
                raise TraceabilityError(f"{row['trace_id']} silently changes {ksa_id} Project OS closure")
            if state == "QUEUED" and row["gap_classification"] == []:
                raise TraceabilityError(f"queued {ksa_id} has no explicit open-gap classification")
            if state in {"ACTIVE", "ACTIVE_VERIFY_REQUIRED"} and not row["gap_classification"]:
                raise TraceabilityError(f"active {ksa_id} has no explicit open-gap classification")
        for locator in row["implementation_locators"]:
            _validate_locator(root, subject["commit_sha"], locator, row["trace_id"])
        for locator in row["schema_config_locators"]:
            _validate_locator(root, subject["commit_sha"], locator, row["trace_id"])
        for locator in row["decisive_test_locators"]:
            _validate_locator(root, subject["commit_sha"], locator, row["trace_id"], test=True)
        if row["gap_classification"] and not row["next_owner"]:
            raise TraceabilityError(f"{row['trace_id']} has an open gap without a next owner")
        if not row["gap_classification"] and row["next_owner"] is not None:
            raise TraceabilityError(f"{row['trace_id']} names a next owner without an open gap")
        if row["implementation_state"] == "NOT_IMPLEMENTED" and "OPEN_REPOSITORY_REQUIREMENT" not in row["gap_classification"]:
            raise TraceabilityError(f"unimplemented requirement {row['trace_id']} is missing its repository gap classification")
        if row["ownership"] == "REPOSITORY_OWNED" and row["implementation_state"] in {"PARTIAL", "NOT_IMPLEMENTED"} and "OPEN_REPOSITORY_REQUIREMENT" not in row["gap_classification"]:
            raise TraceabilityError(f"repository-owned open requirement {row['trace_id']} is not classified as a repository gap")
        if row["ownership"] == "REPOSITORY_OWNED" and (
            not row["implementation_locators"] or not row["decisive_test_locators"]
        ):
            raise TraceabilityError(f"repository-owned requirement {row['trace_id']} lacks implementation or decisive-test locators")
        if row["ownership"] == "MIXED_REPOSITORY_AND_EXTERNAL" and row["implementation_state"] != "EXTERNAL_ONLY" and (
            not row["implementation_locators"] or not row["decisive_test_locators"]
        ):
            raise TraceabilityError(f"mixed requirement {row['trace_id']} lacks repository implementation or decisive-test locators")
        if row["implementation_state"] == "EXTERNAL_ONLY" and "OPEN_EXTERNAL_PRODUCTION_GATE" not in row["gap_classification"]:
            raise TraceabilityError(f"external-only requirement {row['trace_id']} lacks an external-gate gap classification")
        if row["ownership"] == "EXTERNAL_PRODUCTION_GATE":
            if row["implementation_state"] != "EXTERNAL_ONLY":
                raise TraceabilityError(f"external gate {row['trace_id']} is claimed as repository implemented")
            if row["repository_evidence_availability"] != "EXTERNAL_EVIDENCE_NOT_SUPPLIED":
                raise TraceabilityError(f"external gate {row['trace_id']} is labeled repository-proven")
            if row["implementation_locators"] or row["schema_config_locators"]:
                raise TraceabilityError(f"external gate {row['trace_id']} claims repository implementation locators")
        if row["ownership"] == "MIXED_REPOSITORY_AND_EXTERNAL" and row["repository_evidence_availability"] == "REPOSITORY_TESTED_ONLY":
            raise TraceabilityError(f"mixed requirement {row['trace_id']} hides an external qualification gap")

    if seen_clause_pairs != expected_clause_pairs:
        missing = sorted(expected_clause_pairs - seen_clause_pairs)
        raise TraceabilityError(f"canonical contract clause family coverage is incomplete: {missing}")
    if seen_ksa_ids != set(EXPECTED_KSA_CLOSURE):
        missing_ksa = sorted(set(EXPECTED_KSA_CLOSURE) - seen_ksa_ids)
        extra_ksa = sorted(seen_ksa_ids - set(EXPECTED_KSA_CLOSURE))
        raise TraceabilityError(f"KSA-01 through KSA-37 semantic crosswalk coverage mismatch: missing={missing_ksa}, extra={extra_ksa}")

    path_rows = change["changed_path_coverage"]
    coverage_paths = [item["path"] for item in path_rows]
    if len(set(coverage_paths)) != len(coverage_paths):
        raise TraceabilityError("changed-path coverage contains duplicate paths")
    if coverage_paths != changed_paths:
        missing = sorted(set(changed_paths) - set(coverage_paths))
        extra = sorted(set(coverage_paths) - set(changed_paths))
        raise TraceabilityError(f"changed-path coverage mismatch or nondeterministic order; missing={missing[:5]}, extra={extra[:5]}")
    allowed_classifications = {
        "TEST",
        "FIXTURE",
        "DOCUMENTATION",
        "WORKFLOW",
        "AUDIT_EVIDENCE",
        "MIGRATION_COMPATIBILITY",
    }
    for item in path_rows:
        if not _at_subject(root, subject["commit_sha"], item["path"]) and item["historical"] is not True:
            raise TraceabilityError(f"changed path is absent from traced subject: {item['path']}")
        if _at_subject(root, subject["commit_sha"], item["path"]) and item["historical"] is True:
            raise TraceabilityError(f"path is marked historical even though it exists in the traced subject: {item['path']}")
        if item["coverage_type"] == "REQUIREMENT_ROW":
            if not item["trace_ids"] or item["classification"] is not None:
                raise TraceabilityError(f"requirement path lacks row references: {item['path']}")
            if not set(item["trace_ids"]) <= trace_ids:
                raise TraceabilityError(f"changed path refers to an unknown trace row: {item['path']}")
            referenced = {
                loc["path"]
                for trace_id in item["trace_ids"]
                for field in ("implementation_locators", "schema_config_locators", "decisive_test_locators")
                for loc in trace_lookup[trace_id][field]
            }
            if item["path"] not in referenced:
                raise TraceabilityError(f"path is not a concrete locator in its referenced row: {item['path']}")
        else:
            if item["classification"] not in allowed_classifications or not item["reason"].strip():
                raise TraceabilityError(f"non-product changed path lacks a closed classification and reason: {item['path']}")
            if item["trace_ids"] and not set(item["trace_ids"]) <= trace_ids:
                raise TraceabilityError(f"classified path refers to an unknown trace row: {item['path']}")

    anchors = matrix["repository_anchors"]
    for anchor in anchors:
        commit = anchor["commit_sha"]
        if _git(root, "rev-parse", f"{commit}^{{commit}}") != commit:
            raise TraceabilityError(f"claimed repository commit does not resolve exactly: {commit}")
        if _git(root, "rev-parse", f"{commit}^{{tree}}") != anchor["tree_oid"]:
            raise TraceabilityError(f"claimed repository tree does not match commit: {commit}")
    if {anchor["role"] for anchor in anchors} != {"PRODUCT_SUBJECT", "CHG16_CHANGE_BASE"}:
        raise TraceabilityError("repository evidence anchors must identify only the product subject and accepted change base")
    anchor_map = {anchor["role"]: anchor for anchor in anchors}
    if (
        anchor_map["PRODUCT_SUBJECT"]["commit_sha"] != subject["commit_sha"]
        or anchor_map["PRODUCT_SUBJECT"]["tree_oid"] != subject["tree_oid"]
        or anchor_map["CHG16_CHANGE_BASE"]["commit_sha"] != change["change_base_sha"]
        or anchor_map["CHG16_CHANGE_BASE"]["tree_oid"] != change["change_base_tree_oid"]
    ):
        raise TraceabilityError("repository evidence anchors do not match the matrix-bound subject and change base")

    invariants = matrix["core_invariants"]
    if invariants["production_target_model"] != "google/gemma-4-31b-it":
        raise TraceabilityError("production target model invariant changed")
    if invariants["decision_critical_fields"] != [
        "meaning", "number", "date", "unit", "table", "cardinality", "trend",
        "owner", "status", "dependency", "risk", "timing", "uncertainty",
        "terminology", "modality",
    ]:
        raise TraceabilityError("decision-critical preservation fields are incomplete or out of canonical order")
    if invariants["benchmark_user_production_path_equal"] is not True:
        raise TraceabilityError("benchmark/user/production path equality invariant changed")
    if invariants["silent_model_fallback_allowed"] is not False:
        raise TraceabilityError("silent model fallback must remain prohibited")
    if invariants["release_state_source"] != "EVIDENCE_DERIVED":
        raise TraceabilityError("release state must remain evidence-derived")
    if invariants["production_certification_external_gates_separate"] is not True:
        raise TraceabilityError("production certification gates must remain separate")

    recomputed_summary = compute_summary(matrix)
    if matrix["summary"] != recomputed_summary:
        raise TraceabilityError("stored deterministic summary does not match recomputed counts")
    return recomputed_summary


def render_report(matrix: dict[str, Any]) -> str:
    summary = matrix["summary"]
    lines = [
        "# KSA-38 requirement traceability",
        "",
        f"Product subject: `{matrix['product_subject']['commit_sha']}`",
        f"CHG-16 change base: `{matrix['change_span']['change_base_sha']}`",
        f"Span: {matrix['change_span']['commit_count']} commits, {matrix['change_span']['changed_path_count']} changed paths.",
        "",
        "This report maps the immutable product subject to the binding-time Project OS closure snapshot carried in the accepted dispatch. Code presence and Project OS closure are recorded independently. Repository tests do not establish company or production qualification.",
        "",
        "## Coverage summary",
        "",
        f"- Trace rows: {summary['trace_rows']} across {len(summary['rows_by_contract_family'])} contract families.",
        f"- KSA coverage: {summary['ksa_coverage']['covered_items']}/{summary['ksa_coverage']['required_items']} items.",
        f"- Canonical clauses: {summary['canonical_clause_coverage']['covered_clauses']}/{summary['canonical_clause_coverage']['required_clauses']}.",
        f"- Changed paths: {summary['changed_path_coverage']['requirement_referenced_paths']} requirement-referenced; {summary['changed_path_coverage']['closed_classification_paths']} classified; {summary['changed_path_coverage']['unexplained_paths']} unexplained.",
        f"- Orphan requirements: {summary['orphan_requirement_count']}.",
        "",
        "### Project OS closure snapshot",
        "",
        "| Closure state | KSA items |",
        "| --- | ---: |",
    ]
    for state, count in summary["project_os_ksa_items_by_closure_state"].items():
        lines.append(f"| `{state}` | {count} |")
    lines.extend([
        "",
        "## Closed KSA semantic crosswalk",
        "",
        "Each KSA scope below is linked only to its reviewed canonical clause set. The rationale is bounded registry data. Implementation state describes repository evidence; Project OS closure remains the binding-time state above.",
        "",
        "| KSA | Project OS scope | Mapped canonical clause(s) and rationale | Implementation state | Project OS closure | Open repository gap | External gate | Next owner |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ])
    rows_by_pair = {
        (row["contract_family"], clause): row
        for row in matrix["trace_rows"]
        for clause in row["clause_ids"]
    }
    closure_by_ksa = {
        item["ksa_id"]: item["state"]
        for item in matrix["project_os_closure_snapshot"]["items"]
    }
    for item in matrix["ksa_scope_registry"]:
        ksa_id = item["ksa_id"]
        mapped_rows = [
            (mapping, rows_by_pair[(mapping["family_id"], mapping["clause_id"])])
            for mapping in item["mappings"]
        ]
        mapped_labels = "<br>".join(
            f"`{mapping['family_id']}/{mapping['clause_id']}` ({row['trace_id']}): {mapping['mapping_rationale']}"
            for mapping, row in mapped_rows
        )
        states = ", ".join(sorted({mapping["implementation_state"] for mapping, _ in mapped_rows}))
        repository_gaps = [row for _, row in mapped_rows] if item["repository_requirement_open"] else []
        repository_gap = "<br>".join(
            f"`OPEN_REPOSITORY_REQUIREMENT` ({row['trace_id']}): {row['requirement_summary']}"
            for row in repository_gaps
        ) or "None recorded"
        explicit_external_gates = [
            row for mapping, row in mapped_rows
            if mapping["clause_id"] == "external_production_qualification_gates"
            and "OPEN_EXTERNAL_PRODUCTION_GATE" in row["gap_classification"]
        ]
        external_gates = explicit_external_gates or [
            row for _, row in mapped_rows
            if "OPEN_EXTERNAL_PRODUCTION_GATE" in row["gap_classification"]
        ]
        external_gate = ", ".join(
            f"`OPEN_EXTERNAL_PRODUCTION_GATE` ({row['trace_id']})"
            for row in external_gates
        ) or "None mapped"
        owners = []
        if item["repository_requirement_open"] and item["future_project_os_owner"]:
            owners.append(item["future_project_os_owner"])
        owners.extend(row["next_owner"] for row in external_gates if row["next_owner"])
        if closure_by_ksa[ksa_id] in {"ACTIVE", "ACTIVE_VERIFY_REQUIRED", "QUEUED"} and not item["repository_requirement_open"]:
            owners.append(f"Project OS {ksa_id} owner to reconcile this scope with the accepted binding-time state.")
        next_owner = "<br>".join(dict.fromkeys(owners)) or "None recorded"
        lines.append(
            f"| `{ksa_id}` | {item['scope']} | {mapped_labels} | `{states}` | `{closure_by_ksa[ksa_id]}` | {repository_gap} | {external_gate} | {next_owner} |"
        )
    lines.extend(["", "### Rows by implementation state", "", "| State | Rows |", "| --- | ---: |"])
    for state, count in summary["rows_by_implementation_state"].items():
        lines.append(f"| `{state}` | {count} |")
    lines.extend(["", "## Open repository and reconciliation work", ""])
    open_rows = [
        row for row in matrix["trace_rows"]
        if any(gap in row["gap_classification"] for gap in (
            "OPEN_REPOSITORY_REQUIREMENT", "OPEN_PROJECT_OS_RECONCILIATION"
        ))
    ]
    if not open_rows:
        lines.append("No repository-owned open implementation gap is recorded.")
    else:
        lines.extend([
            "| Trace ID | Requirement | Implementation | Project OS | Gap | Next owner |",
            "| --- | --- | --- | --- | --- | --- |",
        ])
        for row in open_rows:
            closure = ", ".join(f"{item['ksa_id']} {item['state']}" for item in row["project_os_closure"])
            gaps = ", ".join(row["gap_classification"])
            lines.append(
                f"| `{row['trace_id']}` | {row['requirement_summary']} | `{row['implementation_state']}` | {closure} | {gaps} | {row['next_owner']} |"
            )
    lines.extend(["", "## External production gates", ""])
    external_rows = [
        row for row in matrix["trace_rows"]
        if row["ownership"] in {"MIXED_REPOSITORY_AND_EXTERNAL", "EXTERNAL_PRODUCTION_GATE"}
        and "OPEN_EXTERNAL_PRODUCTION_GATE" in row["gap_classification"]
    ]
    lines.extend([
        "These items are not repository-proven. No private employee study, company PaaS, live IAM/network/security-data-use, production Gemma, pilot, or canary result is claimed.",
        "",
        "| Trace ID | Gate | Ownership | Repository implementation | External evidence | Next owner |",
        "| --- | --- | --- | --- | --- | --- |",
    ])
    for row in external_rows:
        lines.append(
            f"| `{row['trace_id']}` | {row['requirement_summary']} | `{row['ownership']}` | `{row['implementation_state']}` | `{row['repository_evidence_availability']}` | {row['next_owner']} |"
        )
    lines.extend(["", "## Contract family coverage", ""])
    for family, count in summary["rows_by_contract_family"].items():
        lines.append(f"- `{family}`: {count} rows")
    lines.extend([
        "",
        "## Core invariants",
        "",
        f"- Production target: `{matrix['core_invariants']['production_target_model']}`.",
        "- Benchmark, user, and production paths are explicitly required to be equal.",
        "- Silent model fallback is prohibited.",
        "- Release state is evidence-derived; external production certification gates remain separate.",
        "- Decision-critical preservation: " + ", ".join(matrix["core_invariants"]["decision_critical_fields"]) + ".",
        "",
        "## Trace rows",
        "",
        "| Trace ID | Family / clause | Requirement | Owner | Implementation | Project OS closure | Evidence / next owner |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ])
    for row in matrix["trace_rows"]:
        closure = ", ".join(f"{item['ksa_id']} `{item['state']}`" for item in row["project_os_closure"])
        evidence = row["repository_evidence_availability"]
        if row["next_owner"]:
            evidence += f"; next: {row['next_owner']}"
        clauses = ", ".join(row["clause_ids"])
        lines.append(
            f"| `{row['trace_id']}` | `{row['contract_family']}` / `{clauses}` | {row['requirement_summary']} | `{row['ownership']}` | `{row['implementation_state']}` | {closure} | {evidence} |"
        )
    lines.append("")
    return "\n".join(lines)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TraceabilityError(f"cannot load JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise TraceabilityError(f"expected a JSON object: {path}")
    return value
