#!/usr/bin/env python3
"""Bind observed KSA-38 checks to the explicitly configured continuation candidate."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
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
CONTEXT_PATH = Path("traceability/ksa38/candidate-context.v1.json")
OUTPUT_PATH = Path(".codex-fabric/ksa38/candidate-evidence.json")
AUDIT_PATH = Path(".codex-fabric/audit.json")
CLOSURE_AUTHORITY = "PROJECT_OS_BOUND_DISPATCH_SNAPSHOT"
EVIDENCE_PATHS = {
    OUTPUT_PATH.as_posix(),
    AUDIT_PATH.as_posix(),
    QUALIFICATION_PATH.as_posix(),
}
ARTIFACT_PATHS = {
    "candidate_context": CONTEXT_PATH,
    "matrix": MATRIX_PATH,
    "matrix_schema": MATRIX_SCHEMA_PATH,
    "candidate_evidence_schema": CANDIDATE_SCHEMA_PATH,
    "qualification_schema": QUALIFICATION_SCHEMA_PATH,
    "scope_registry": SCOPE_REGISTRY_PATH,
    "human_report": REPORT_PATH,
}
REQUEST_PATTERN = re.compile(r"^chg16-requirement-traceability-01(?:-fix[0-9]{2})?$")
BRANCH_PATTERN = re.compile(r"^codex/k-slide-chg16-requirement-traceability-01(?:-fix[0-9]{2})?$")
JOB_PATTERN = re.compile(r"^CF-[0-9a-f]{16,32}$")
SHA1_PATTERN = re.compile(r"^[0-9a-f]{40}$")


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


def _parents(commit: str) -> list[str]:
    return git("rev-list", "--parents", "-n", "1", commit).split()[1:]


def _native_audit(commit: str) -> dict[str, Any]:
    try:
        raw = git("show", f"{commit}:.codex-fabric/audit.json")
        value = json.loads(raw)
    except (CandidateEvidenceError, json.JSONDecodeError) as exc:
        raise CandidateEvidenceError(f"native predecessor evidence is unreadable at {commit}: {exc}") from exc
    if not isinstance(value, dict):
        raise CandidateEvidenceError(f"native predecessor evidence at {commit} is not an object")
    return value


def validate_bound_candidate_identity(
    request: str, branch: str, parent_sha: str, context: dict[str, Any]
) -> None:
    if request != context["request"]:
        raise CandidateEvidenceError("candidate request does not match the bound continuation context")
    if branch != context["work_branch"]:
        raise CandidateEvidenceError("candidate work branch does not match the bound continuation context")
    if parent_sha != context["candidate_parent_sha"]:
        raise CandidateEvidenceError("candidate parent does not match the bound predecessor work head")


def validate_qualification_identity(
    qualification: dict[str, Any], context: dict[str, Any]
) -> None:
    expected = {
        "project": context["project"],
        "operation": context["operation"],
        "request": context["request"],
        "exact_base_sha": context["exact_base_sha"],
        "product_subject_sha": context["exact_base_sha"],
        "change_base_sha": context["change_base_sha"],
        "work_branch": context["work_branch"],
        "predecessor_lineage": context["predecessor_lineage"],
        "historical_lineage": context["historical_lineage"],
        "closure_snapshot_authority": CLOSURE_AUTHORITY,
    }
    for key, value in expected.items():
        if qualification.get(key) != value:
            raise CandidateEvidenceError(
                f"qualification {key} does not match the bound continuation context"
            )


def validate_audit_match(evidence: dict[str, Any], audit: dict[str, Any]) -> None:
    if audit != evidence:
        raise CandidateEvidenceError(
            "conventional audit.json differs from dedicated KSA-38 candidate evidence"
        )


def _validate_context(context: dict[str, Any]) -> None:
    expected_keys = {
        "schema_version",
        "project",
        "operation",
        "request",
        "work_branch",
        "exact_base_sha",
        "change_base_sha",
        "candidate_parent_sha",
        "predecessor_lineage",
        "historical_lineage",
    }
    if set(context) != expected_keys:
        raise CandidateEvidenceError("candidate context has missing or unrecognized fields")
    if context["schema_version"] != "1.0" or context["project"] != "k-slide" or context["operation"] != "FIX":
        raise CandidateEvidenceError("candidate context has an unsupported project or operation")
    if not REQUEST_PATTERN.fullmatch(context["request"]):
        raise CandidateEvidenceError("candidate context request has an invalid KSA-38 request identity")
    if context["work_branch"] != f"codex/k-slide-{context['request']}":
        raise CandidateEvidenceError("candidate context request and work branch disagree")
    if not BRANCH_PATTERN.fullmatch(context["work_branch"]):
        raise CandidateEvidenceError("candidate context work branch has an invalid identity")
    if context["exact_base_sha"] != PRODUCT_SUBJECT_SHA:
        raise CandidateEvidenceError("candidate context does not preserve the immutable product subject")
    if context["change_base_sha"] != CHANGE_BASE_SHA:
        raise CandidateEvidenceError("candidate context does not preserve the accepted change base")
    if not SHA1_PATTERN.fullmatch(context["candidate_parent_sha"]):
        raise CandidateEvidenceError("candidate context parent is not an exact commit SHA")

    predecessor = context["predecessor_lineage"]
    history = context["historical_lineage"]
    if not isinstance(predecessor, dict) or not isinstance(history, list) or not history:
        raise CandidateEvidenceError("candidate context has incomplete predecessor lineage")
    records = [predecessor, *history]
    required_record_keys = {
        "request",
        "disposition",
        "work_head",
        "traceability_product_commit",
        "native_evidence_commit",
        "native_build_job_id",
    }
    for index, record in enumerate(records):
        if not isinstance(record, dict) or set(record) != required_record_keys:
            raise CandidateEvidenceError("candidate context predecessor record has missing or unrecognized fields")
        if not REQUEST_PATTERN.fullmatch(record["request"]):
            raise CandidateEvidenceError("candidate context predecessor request has an invalid identity")
        if record["disposition"] not in {"ACCEPTED", "REJECTED", "BUILD_PREDECESSOR"}:
            raise CandidateEvidenceError("candidate context predecessor disposition is invalid")
        if not JOB_PATTERN.fullmatch(record["native_build_job_id"]):
            raise CandidateEvidenceError("candidate context predecessor job identity is invalid")
        for key in ("work_head", "traceability_product_commit", "native_evidence_commit"):
            if not SHA1_PATTERN.fullmatch(record[key]):
                raise CandidateEvidenceError(f"candidate context predecessor {key} is invalid")
        if not _is_ancestor(record["traceability_product_commit"], record["work_head"]):
            raise CandidateEvidenceError("predecessor product commit is not in its recorded work-head lineage")
        if _parents(record["native_evidence_commit"]) != [record["work_head"]]:
            raise CandidateEvidenceError("native predecessor evidence does not directly follow its recorded work head")
        audit = _native_audit(record["native_evidence_commit"])
        if (
            audit.get("project_id") != "k-slide"
            or audit.get("operation") not in {"BUILD", "FIX"}
            or audit.get("request") != record["request"]
            or audit.get("job_id") != record["native_build_job_id"]
        ):
            raise CandidateEvidenceError("native predecessor audit does not match its configured request and job")
        if index < len(records) - 1:
            older_evidence = records[index + 1]["native_evidence_commit"]
            if _parents(record["traceability_product_commit"]) != [older_evidence]:
                raise CandidateEvidenceError("configured predecessor chain is not contiguous")

    if predecessor["disposition"] != "ACCEPTED":
        raise CandidateEvidenceError("current continuation predecessor must be accepted")
    if context["candidate_parent_sha"] != predecessor["work_head"]:
        raise CandidateEvidenceError("candidate parent differs from the configured predecessor work head")
    if not _is_ancestor(context["exact_base_sha"], context["candidate_parent_sha"]):
        raise CandidateEvidenceError("configured predecessor does not descend from the immutable product subject")


def _context_path(path: Path) -> Path:
    resolved = path if path.is_absolute() else ROOT / path
    try:
        resolved.relative_to(ROOT)
    except ValueError as exc:
        raise CandidateEvidenceError("candidate context must be inside the repository") from exc
    return resolved


def _validate_candidate_context(
    candidate_sha: str, context: dict[str, Any]
) -> tuple[str, str]:
    _validate_context(context)
    branch = git("branch", "--show-current")
    candidate_commit = git("rev-parse", f"{candidate_sha}^{{commit}}")
    if candidate_commit != candidate_sha:
        raise CandidateEvidenceError("candidate SHA is not an exact repository commit")
    parent = git("rev-parse", f"{candidate_sha}^")
    validate_bound_candidate_identity(context["request"], branch, parent, context)

    head = git("rev-parse", "HEAD")
    if not _is_ancestor(candidate_sha, head):
        raise CandidateEvidenceError("candidate is not an ancestor of the current work head")
    if not _is_ancestor(context["exact_base_sha"], candidate_sha):
        raise CandidateEvidenceError("candidate does not descend from the immutable product subject")
    later_paths = set(git("diff", "--name-only", candidate_sha, "HEAD").splitlines())
    if not later_paths <= EVIDENCE_PATHS:
        raise CandidateEvidenceError("commits above candidate include non-evidence paths")
    if not _status_paths() <= EVIDENCE_PATHS:
        raise CandidateEvidenceError("candidate worktree contains changes outside the evidence sidecars")
    return git("rev-parse", f"{candidate_sha}^{{tree}}"), branch


def _coverage(summary: dict[str, Any], matrix: dict[str, Any]) -> dict[str, Any]:
    return {
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


def _canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _validate_qualification_binding(
    qualification: dict[str, Any],
    candidate_binding: dict[str, Any],
    coverage_sha256: str,
    artifact_hashes: dict[str, str],
) -> None:
    expected = {
        "candidate_binding": candidate_binding,
        "coverage_sha256": coverage_sha256,
        "artifact_hashes": artifact_hashes,
    }
    for key, value in expected.items():
        existing = qualification.get(key)
        if existing is not None and existing != value:
            raise CandidateEvidenceError(f"qualification {key} is stale for the current candidate")


def build_candidate_artifacts(
    candidate_sha: str | None = None, context_path: Path = CONTEXT_PATH
) -> tuple[dict[str, Any], dict[str, Any]]:
    context_path = _context_path(context_path)
    context = load_json(context_path)
    if not isinstance(context, dict):
        raise CandidateEvidenceError("candidate context is not a JSON object")
    candidate_sha = candidate_sha or git("rev-parse", "HEAD")
    candidate_tree, branch = _validate_candidate_context(candidate_sha, context)

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
        raise CandidateEvidenceError(
            f"qualification schema failed at {list(error.absolute_path)}: {error.message}"
        )
    validate_qualification_identity(qualification, context)
    if matrix["product_subject"]["commit_sha"] != context["exact_base_sha"]:
        raise CandidateEvidenceError("matrix product subject does not match the bound immutable subject")
    if matrix["change_span"]["change_base_sha"] != context["change_base_sha"]:
        raise CandidateEvidenceError("matrix change base does not match the bound accepted change base")
    if git("rev-parse", f"{context['exact_base_sha']}^{{tree}}") != matrix["product_subject"]["tree_oid"]:
        raise CandidateEvidenceError("matrix product subject tree does not match the immutable base commit")
    if not qualification.get("checks") or any(
        item.get("status") not in {"PASS", "NOT_REQUIRED"} for item in qualification["checks"]
    ):
        raise CandidateEvidenceError("qualification record has missing or failed checks")

    coverage = _coverage(summary, matrix)
    artifact_hashes = {
        name: sha256(path if name != "candidate_context" else context_path.relative_to(ROOT))
        for name, path in ARTIFACT_PATHS.items()
    }
    candidate_binding = {
        "commit_sha": candidate_sha,
        "tree_oid": candidate_tree,
        "parent_sha": context["candidate_parent_sha"],
        "work_branch": branch,
        "worktree_clean_at_product_candidate": True,
    }
    coverage_sha256 = _canonical_digest(coverage)
    _validate_qualification_binding(
        qualification, candidate_binding, coverage_sha256, artifact_hashes
    )
    qualification["candidate_binding"] = candidate_binding
    qualification["coverage_sha256"] = coverage_sha256
    qualification["artifact_hashes"] = artifact_hashes

    qualification_errors = list(Draft202012Validator(qualification_schema).iter_errors(qualification))
    if qualification_errors:
        error = qualification_errors[0]
        raise CandidateEvidenceError(
            f"bound qualification schema failed at {list(error.absolute_path)}: {error.message}"
        )
    qualified_json = json.dumps(qualification, ensure_ascii=False, indent=2) + "\n"
    qualification_sha256 = hashlib.sha256(qualified_json.encode()).hexdigest()

    artifact_documents = {
        **ARTIFACT_PATHS,
        "qualification_manifest": QUALIFICATION_PATH,
    }
    artifacts = {
        name: {
            "path": (
                context_path.relative_to(ROOT).as_posix()
                if name == "candidate_context"
                else path.as_posix()
            ),
            "sha256": (
                artifact_hashes[name]
                if name in artifact_hashes
                else qualification_sha256
                if name == "qualification_manifest"
                else sha256(path)
            ),
            "version": "1.0" if name != "human_report" else matrix["matrix_version"],
        }
        for name, path in artifact_documents.items()
    }
    evidence = {
        "schema_version": "1.0",
        "evidence_type": "k-slide-ksa38-fix-candidate-evidence",
        "project": context["project"],
        "issue_id": "CHG-16",
        "operation": context["operation"],
        "request": context["request"],
        "exact_base": {
            "commit_sha": context["exact_base_sha"],
            "tree_oid": matrix["product_subject"]["tree_oid"],
        },
        "work_branch": branch,
        "product_subject_sha": context["exact_base_sha"],
        "change_base_sha": context["change_base_sha"],
        "predecessor_lineage": context["predecessor_lineage"],
        "historical_lineage": context["historical_lineage"],
        "artifacts": artifacts,
        "project_os_closure_snapshot": matrix["project_os_closure_snapshot"],
        "coverage": coverage,
        "qualification_checks": qualification["checks"],
        "candidate_binding": candidate_binding,
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
        raise CandidateEvidenceError(
            f"candidate evidence schema failed at {list(error.absolute_path)}: {error.message}"
        )
    return evidence, qualification


def validate_evidence(
    evidence: dict[str, Any],
    audit: dict[str, Any],
    qualification: dict[str, Any],
    context_path: Path = CONTEXT_PATH,
) -> None:
    schema = load_json(ROOT / CANDIDATE_SCHEMA_PATH)
    qualification_schema = load_json(ROOT / QUALIFICATION_SCHEMA_PATH)
    Draft202012Validator.check_schema(schema)
    Draft202012Validator.check_schema(qualification_schema)
    for candidate_document in (evidence, audit):
        errors = list(Draft202012Validator(schema).iter_errors(candidate_document))
        if errors:
            error = errors[0]
            raise CandidateEvidenceError(
                f"candidate evidence schema failed at {list(error.absolute_path)}: {error.message}"
            )
    validate_audit_match(evidence, audit)
    expected_evidence, expected_qualification = build_candidate_artifacts(
        evidence["candidate_binding"]["commit_sha"], context_path
    )
    if evidence != expected_evidence:
        raise CandidateEvidenceError(
            "candidate evidence differs from rederived candidate, hashes, lineage, coverage, or results"
        )
    if qualification != expected_qualification:
        raise CandidateEvidenceError(
            "qualification manifest differs from rederived candidate identity, hashes, coverage, or results"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / OUTPUT_PATH)
    parser.add_argument("--audit-output", type=Path, default=ROOT / AUDIT_PATH)
    parser.add_argument("--context", type=Path, default=ROOT / CONTEXT_PATH)
    parser.add_argument("--validate", action="store_true")
    args = parser.parse_args()
    try:
        context_path = _context_path(args.context)
        if args.validate:
            evidence = load_json(args.output)
            audit = load_json(args.audit_output)
            qualification = load_json(ROOT / QUALIFICATION_PATH)
            validate_evidence(evidence, audit, qualification, context_path)
            print(
                "KSA-38 candidate evidence PASS: continuation identity, candidate SHA/tree, "
                "lineage, hashes, coverage, results, and unset current Fabric identity rederived."
            )
        else:
            evidence, qualification = build_candidate_artifacts(context_path=context_path)
            rendered = json.dumps(evidence, ensure_ascii=False, indent=2) + "\n"
            qualified = json.dumps(qualification, ensure_ascii=False, indent=2) + "\n"
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.audit_output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered, encoding="utf-8")
            args.audit_output.write_text(rendered, encoding="utf-8")
            (ROOT / QUALIFICATION_PATH).write_text(qualified, encoding="utf-8")
            print(
                f"Wrote current candidate evidence, qualification binding, and conventional audit; "
                f"current Fabric job ID remains unset."
            )
        return 0
    except (CandidateEvidenceError, TraceabilityError, OSError, KeyError, TypeError) as exc:
        print(f"KSA-38 candidate evidence FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
