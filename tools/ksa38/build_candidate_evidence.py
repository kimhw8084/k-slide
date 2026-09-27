#!/usr/bin/env python3
"""Bind observed KSA-38 checks to the clean product-candidate commit."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from traceability import CHANGE_BASE_SHA, PRODUCT_SUBJECT_SHA, load_json, validate_matrix


ROOT = Path(__file__).resolve().parents[2]
MATRIX_PATH = Path("traceability/ksa38/traceability.v1.json")
MATRIX_SCHEMA_PATH = Path("traceability/ksa38/schema.v1.json")
CANDIDATE_SCHEMA_PATH = Path("traceability/ksa38/candidate-evidence.schema.v1.json")
QUALIFICATION_PATH = Path("traceability/ksa38/qualification.v1.json")
QUALIFICATION_SCHEMA_PATH = Path("traceability/ksa38/qualification.schema.v1.json")
OUTPUT_PATH = Path(".codex-fabric/ksa38/candidate-evidence.json")
WORK_BRANCH = "codex/k-slide-chg16-requirement-traceability-01"


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


def _no_tracked_changes() -> bool:
    result = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=no"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    return not result.stdout.strip()


def build_evidence() -> dict[str, Any]:
    head = git("rev-parse", "HEAD")
    tree = git("rev-parse", "HEAD^{tree}")
    parent = git("rev-parse", "HEAD^")
    branch = git("branch", "--show-current")
    if branch != WORK_BRANCH:
        raise CandidateEvidenceError(f"expected work branch {WORK_BRANCH}, found {branch}")
    if parent != PRODUCT_SUBJECT_SHA:
        raise CandidateEvidenceError("KSA-38 candidate must directly descend from the exact product subject")
    if not _no_tracked_changes():
        raise CandidateEvidenceError("candidate evidence must be generated from a clean committed product candidate")

    matrix = load_json(ROOT / MATRIX_PATH)
    qualification = load_json(ROOT / QUALIFICATION_PATH)
    matrix_schema = load_json(ROOT / MATRIX_SCHEMA_PATH)
    qualification_schema = load_json(ROOT / QUALIFICATION_SCHEMA_PATH)
    schema = load_json(ROOT / CANDIDATE_SCHEMA_PATH)
    Draft202012Validator.check_schema(schema)
    Draft202012Validator.check_schema(qualification_schema)
    validate_matrix(ROOT, matrix, matrix_schema)
    qualification_errors = list(Draft202012Validator(qualification_schema).iter_errors(qualification))
    if qualification_errors:
        error = qualification_errors[0]
        raise CandidateEvidenceError(f"qualification schema failed at {list(error.absolute_path)}: {error.message}")
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

    summary = matrix["summary"]
    coverage = {
        "trace_rows": summary["trace_rows"],
        "canonical_clauses": summary["canonical_clause_coverage"]["covered_clauses"],
        "contract_families": len(summary["rows_by_contract_family"]),
        "ksa_items": summary["ksa_coverage"]["covered_items"],
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
        "evidence_type": "k-slide-ksa38-candidate-evidence",
        "project": "k-slide",
        "issue_id": "CHG-16",
        "operation": "BUILD",
        "request": "chg16-requirement-traceability-01",
        "exact_base": {
            "commit_sha": PRODUCT_SUBJECT_SHA,
            "tree_oid": matrix["product_subject"]["tree_oid"],
        },
        "work_branch": WORK_BRANCH,
        "product_subject_sha": PRODUCT_SUBJECT_SHA,
        "change_base_sha": CHANGE_BASE_SHA,
        "artifacts": {
            "matrix": {"path": MATRIX_PATH.as_posix(), "sha256": sha256(MATRIX_PATH), "version": matrix["matrix_version"]},
            "matrix_schema": {"path": MATRIX_SCHEMA_PATH.as_posix(), "sha256": sha256(MATRIX_SCHEMA_PATH), "version": matrix["schema_version"]},
            "candidate_evidence_schema": {"path": CANDIDATE_SCHEMA_PATH.as_posix(), "sha256": sha256(CANDIDATE_SCHEMA_PATH), "version": "1.0"},
            "qualification_manifest": {"path": QUALIFICATION_PATH.as_posix(), "sha256": sha256(QUALIFICATION_PATH), "version": qualification["schema_version"]},
            "qualification_schema": {"path": QUALIFICATION_SCHEMA_PATH.as_posix(), "sha256": sha256(QUALIFICATION_SCHEMA_PATH), "version": qualification["schema_version"]},
        },
        "project_os_closure_snapshot": matrix["project_os_closure_snapshot"],
        "coverage": coverage,
        "qualification_checks": qualification["checks"],
        "candidate_binding": {
            "commit_sha": head,
            "tree_oid": tree,
            "parent_sha": parent,
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


def validate_evidence(evidence: dict[str, Any]) -> None:
    schema = load_json(ROOT / CANDIDATE_SCHEMA_PATH)
    Draft202012Validator.check_schema(schema)
    errors = list(Draft202012Validator(schema).iter_errors(evidence))
    if errors:
        error = errors[0]
        raise CandidateEvidenceError(f"candidate evidence schema failed at {list(error.absolute_path)}: {error.message}")
    expected = build_evidence()
    if evidence != expected:
        raise CandidateEvidenceError("candidate evidence differs from rederived matrix hashes, Git identity, closure, coverage, or check data")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / OUTPUT_PATH)
    parser.add_argument("--validate", action="store_true")
    args = parser.parse_args()
    try:
        if args.validate:
            evidence = load_json(args.output)
            validate_evidence(evidence)
            print("KSA-38 candidate evidence PASS: candidate SHA/tree and artifact hashes rederived; Fabric job ID remains unset.")
        else:
            evidence = build_evidence()
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            print(f"Wrote candidate-side evidence to {args.output.relative_to(ROOT)}; Fabric job ID remains unset.")
        return 0
    except (CandidateEvidenceError, OSError) as exc:
        print(f"KSA-38 candidate evidence FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
