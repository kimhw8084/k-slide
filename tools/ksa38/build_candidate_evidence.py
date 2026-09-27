#!/usr/bin/env python3
"""Bind observed KSA-38 FIX01 checks to the exact traceability candidate."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from traceability import (
    CHANGE_BASE_SHA,
    KSA_SCOPE_REGISTRY_PATH,
    PRODUCT_SUBJECT_SHA,
    TraceabilityError,
    load_json,
    render_report,
    validate_matrix,
)


ROOT = Path(__file__).resolve().parents[2]
MATRIX_PATH = Path("traceability/ksa38/traceability.v1.json")
MATRIX_SCHEMA_PATH = Path("traceability/ksa38/schema.v1.json")
SCOPE_REGISTRY_PATH = Path(KSA_SCOPE_REGISTRY_PATH)
CANDIDATE_SCHEMA_PATH = Path("traceability/ksa38/candidate-evidence.schema.v1.json")
QUALIFICATION_PATH = Path("traceability/ksa38/qualification.v1.json")
QUALIFICATION_SCHEMA_PATH = Path("traceability/ksa38/qualification.schema.v1.json")
REPORT_PATH = Path("traceability/ksa38/README.md")
OUTPUT_PATH = Path(".codex-fabric/ksa38/candidate-evidence.json")
AUDIT_PATH = Path(".codex-fabric/audit.json")
WORK_BRANCH = "codex/k-slide-chg16-requirement-traceability-01-fix01"
PREDECESSOR_WORK_HEAD = "6bad7b23ddfc9525acffb9e169fb65182f9c8764"
PREDECESSOR_PRODUCT_COMMIT = "b07011b674d165bf8ed28d5b2a96add6e850bd6d"
PREDECESSOR_EVIDENCE_COMMIT = "99063af41106fb26d46f573c5fd0fb52a5352cf7"
PREDECESSOR_BUILD_JOB_ID = "CF-12417898c2198699f08668aa"
CANDIDATE_PARENT = PREDECESSOR_EVIDENCE_COMMIT
EVIDENCE_PATHS = {OUTPUT_PATH.as_posix(), AUDIT_PATH.as_posix()}


class CandidateEvidenceError(ValueError):
    pass


def git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=ROOT, text=True, capture_output=True, check=False
    )
    if result.returncode:
        raise CandidateEvidenceError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def sha256(path: Path) -> str:
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def _status_paths() -> set[str]:
    result = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=no"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    return {line[3:].split(" -> ")[-1] for line in result.stdout.splitlines()}


def _is_ancestor(ancestor: str, descendant: str) -> bool:
    return subprocess.run(
        ["git", "merge-base", "--is-ancestor", ancestor, descendant],
        cwd=ROOT,
        capture_output=True,
        check=False,
    ).returncode == 0


def _validate_candidate_context(candidate_sha: str) -> tuple[str, str]:
    branch = git("branch", "--show-current")
    if branch != WORK_BRANCH:
        raise CandidateEvidenceError(f"expected work branch {WORK_BRANCH}, found {branch}")
    if git("rev-parse", f"{candidate_sha}^{{commit}}") != candidate_sha:
        raise CandidateEvidenceError("FIX01 candidate SHA is not an exact repository commit")
    parent = git("rev-parse", f"{candidate_sha}^")
    if parent != CANDIDATE_PARENT:
        raise CandidateEvidenceError("FIX01 candidate must preserve the exact predecessor evidence head as its parent")

    head = git("rev-parse", "HEAD")
    if not _is_ancestor(candidate_sha, head):
        raise CandidateEvidenceError("FIX01 candidate is not an ancestor of the current work head")
    later_paths = set(git("diff", "--name-only", candidate_sha, "HEAD").splitlines())
    if not later_paths <= EVIDENCE_PATHS:
        raise CandidateEvidenceError("commits above FIX01 candidate include non-evidence paths")
    if not _status_paths() <= EVIDENCE_PATHS:
        raise CandidateEvidenceError("candidate worktree contains changes outside the candidate-evidence sidecars")
    tree = git("rev-parse", f"{candidate_sha}^{{tree}}")
    return tree, branch


def build_evidence(candidate_sha: str | None = None) -> dict[str, Any]:
    candidate_sha = candidate_sha or git("rev-parse", "HEAD")
    candidate_tree, branch = _validate_candidate_context(candidate_sha)

    matrix = load_json(ROOT / MATRIX_PATH)
    qualification = load_json(ROOT / QUALIFICATION_PATH)
    matrix_schema = load_json(ROOT / MATRIX_SCHEMA_PATH)
    qualification_schema = load_json(ROOT / QUALIFICATION_SCHEMA_PATH)
    schema = load_json(ROOT / CANDIDATE_SCHEMA_PATH)
    Draft202012Validator.check_schema(schema)
    Draft202012Validator.check_schema(qualification_schema)
    summary = validate_matrix(ROOT, matrix, matrix_schema)
    if render_report(matrix) != (ROOT / REPORT_PATH).read_text(encoding="utf-8"):
        raise CandidateEvidenceError("checked-in human report differs from its deterministic KSA crosswalk rendering")
    qualification_errors = list(Draft202012Validator(qualification_schema).iter_errors(qualification))
    if qualification_errors:
        error = qualification_errors[0]
        raise CandidateEvidenceError(f"qualification schema failed at {list(error.absolute_path)}: {error.message}")
    if (
        qualification.get("project") != "k-slide"
        or qualification.get("operation") != "FIX"
        or qualification.get("request") != "chg16-requirement-traceability-01-fix01"
        or qualification.get("work_branch") != WORK_BRANCH
        or qualification.get("predecessor_work_head") != PREDECESSOR_WORK_HEAD
    ):
        raise CandidateEvidenceError("qualification record is not bound to this FIX01 request and predecessor")
    if matrix["product_subject"]["commit_sha"] != PRODUCT_SUBJECT_SHA:
        raise CandidateEvidenceError("matrix product subject does not match the immutable product subject")
    if matrix["change_span"]["change_base_sha"] != CHANGE_BASE_SHA:
        raise CandidateEvidenceError("matrix change base does not match accepted CHG-16 base")
    if qualification.get("product_subject_sha") != PRODUCT_SUBJECT_SHA or qualification.get("change_base_sha") != CHANGE_BASE_SHA:
        raise CandidateEvidenceError("qualification record is not bound to the required immutable subjects")
    if not qualification.get("checks") or any(
        item.get("status") not in {"PASS", "NOT_REQUIRED"} for item in qualification["checks"]
    ):
        raise CandidateEvidenceError("qualification record has missing or failed checks")

    coverage = {
        "trace_rows": summary["trace_rows"],
        "canonical_clauses": summary["canonical_clause_coverage"]["covered_clauses"],
        "contract_families": len(summary["rows_by_contract_family"]),
        "ksa_items": summary["ksa_coverage"]["covered_items"],
        "ksa_clause_mappings": summary["ksa_clause_crosswalk"]["covered_links"],
        "ksa_mapping_state_counts": summary["ksa_clause_crosswalk"]["mappings_by_implementation_state"],
        "ownership_counts": summary["rows_by_ownership"],
        "implementation_state_counts": summary["rows_by_implementation_state"],
        "closure_state_counts": summary["project_os_ksa_items_by_closure_state"],
        "gap_classification_counts": summary["rows_by_gap_classification"],
        "changed_path_coverage": {
            "commit_count": matrix["change_span"]["commit_count"],
            "changed_paths": matrix["change_span"]["changed_path_count"],
            "requirement_referenced_paths": summary["changed_path_coverage"]["requirement_referenced_paths"],
            "closed_classification_paths": summary["changed_path_coverage"]["closed_classification_paths"],
            "historical_paths": sum(
                item["historical"] for item in matrix["change_span"]["changed_path_coverage"]
            ),
            "unexplained_paths": summary["changed_path_coverage"]["unexplained_paths"],
        },
    }
    evidence = {
        "schema_version": "1.0",
        "evidence_type": "k-slide-ksa38-fix01-candidate-evidence",
        "project": "k-slide",
        "issue_id": "CHG-16",
        "operation": "FIX",
        "request": "chg16-requirement-traceability-01-fix01",
        "exact_base": {
            "commit_sha": PRODUCT_SUBJECT_SHA,
            "tree_oid": matrix["product_subject"]["tree_oid"],
        },
        "work_branch": branch,
        "product_subject_sha": PRODUCT_SUBJECT_SHA,
        "change_base_sha": CHANGE_BASE_SHA,
        "predecessor_lineage": {
            "work_head": PREDECESSOR_WORK_HEAD,
            "traceability_product_commit": PREDECESSOR_PRODUCT_COMMIT,
            "native_evidence_commit": PREDECESSOR_EVIDENCE_COMMIT,
            "native_build_job_id": PREDECESSOR_BUILD_JOB_ID,
        },
        "artifacts": {
            "matrix": {"path": MATRIX_PATH.as_posix(), "sha256": sha256(MATRIX_PATH), "version": matrix["matrix_version"]},
            "matrix_schema": {"path": MATRIX_SCHEMA_PATH.as_posix(), "sha256": sha256(MATRIX_SCHEMA_PATH), "version": matrix["schema_version"]},
            "candidate_evidence_schema": {"path": CANDIDATE_SCHEMA_PATH.as_posix(), "sha256": sha256(CANDIDATE_SCHEMA_PATH), "version": "1.0"},
            "qualification_manifest": {"path": QUALIFICATION_PATH.as_posix(), "sha256": sha256(QUALIFICATION_PATH), "version": qualification["schema_version"]},
            "qualification_schema": {"path": QUALIFICATION_SCHEMA_PATH.as_posix(), "sha256": sha256(QUALIFICATION_SCHEMA_PATH), "version": qualification["schema_version"]},
            "scope_registry": {"path": SCOPE_REGISTRY_PATH.as_posix(), "sha256": sha256(SCOPE_REGISTRY_PATH), "version": "1.0"},
            "human_report": {"path": REPORT_PATH.as_posix(), "sha256": sha256(REPORT_PATH), "version": matrix["matrix_version"]},
        },
        "project_os_closure_snapshot": matrix["project_os_closure_snapshot"],
        "coverage": coverage,
        "qualification_checks": qualification["checks"],
        "candidate_binding": {
            "commit_sha": candidate_sha,
            "tree_oid": candidate_tree,
            "parent_sha": CANDIDATE_PARENT,
            "work_branch": branch,
            "worktree_clean_at_product_candidate": True,
        },
        "current_execution_identity": None,
        "fabric_execution_identity": {
            "fabric_job_id": None,
            "owner": "Fabric native publisher post-execution evidence",
            "status": "PENDING_POST_EXECUTION_PUBLICATION",
        },
        "scope_boundary": {
            "notion_mutated": False,
            "main_moved_or_merged": False,
            "live_company_infrastructure_mutated": False,
            "employee_private_pilot_or_canary_work_run": False,
            "go_champion_production_readiness_or_certification_claimed": False,
            "project_os_remains_independent_auditor": True,
        },
    }
    errors = list(Draft202012Validator(schema).iter_errors(evidence))
    if errors:
        error = errors[0]
        raise CandidateEvidenceError(f"candidate evidence schema failed at {list(error.absolute_path)}: {error.message}")
    return evidence


def validate_evidence(evidence: dict[str, Any], audit: dict[str, Any]) -> None:
    schema = load_json(ROOT / CANDIDATE_SCHEMA_PATH)
    Draft202012Validator.check_schema(schema)
    for candidate_document in (evidence, audit):
        errors = list(Draft202012Validator(schema).iter_errors(candidate_document))
        if errors:
            error = errors[0]
            raise CandidateEvidenceError(f"candidate evidence schema failed at {list(error.absolute_path)}: {error.message}")
    if audit != evidence:
        raise CandidateEvidenceError("conventional audit.json differs from dedicated KSA-38 candidate evidence")
    expected = build_evidence(evidence["candidate_binding"]["commit_sha"])
    if evidence != expected:
        raise CandidateEvidenceError("candidate evidence differs from rederived FIX01 candidate, hashes, lineage, coverage, or observed checks")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / OUTPUT_PATH)
    parser.add_argument("--audit-output", type=Path, default=ROOT / AUDIT_PATH)
    parser.add_argument("--validate", action="store_true")
    args = parser.parse_args()
    try:
        if args.validate:
            evidence = load_json(args.output)
            audit = load_json(args.audit_output)
            validate_evidence(evidence, audit)
            print("KSA-38 FIX01 candidate evidence PASS: candidate SHA/tree, predecessor lineage, artifact hashes, and null current Fabric job identity rederived.")
        else:
            evidence = build_evidence()
            rendered = json.dumps(evidence, ensure_ascii=False, indent=2) + "\n"
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.audit_output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered, encoding="utf-8")
            args.audit_output.write_text(rendered, encoding="utf-8")
            print(f"Wrote FIX01 candidate evidence to {args.output.relative_to(ROOT)} and {args.audit_output.relative_to(ROOT)}; current Fabric job ID remains unset.")
        return 0
    except (CandidateEvidenceError, TraceabilityError, OSError, KeyError) as exc:
        print(f"KSA-38 FIX01 candidate evidence FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
