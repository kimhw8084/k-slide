from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from k_slide.release_governance import (
    CODEOWNERS_PATH,
    GOVERNANCE_POLICY,
    POLICY_PATH,
    REPOSITORY_FULL_NAME,
)


SUBJECT = "a" * 40
HEAD_SHA = "36f7c935b58385cc06ba65d2d1bb18a44db52027"
BASE_SHA = "c" * 40
PULL_NUMBER = 31
REPOSITORY_ID = 81234567
OWNER_ID = 27182818
AUTHOR_ID = 31415926
NOW = "2026-09-24T12:00:00Z"


def _blob_sha(content: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(content)).encode("ascii") + b"\0" + content).hexdigest()


def _file_snapshot(path: str, ref: str, content: bytes) -> dict[str, Any]:
    return {
        "path": path,
        "ref": ref,
        "sha": _blob_sha(content),
        "encoding": "base64",
        "content": base64.b64encode(content).decode("ascii"),
    }


def _checks_and_workflow_provenance(*, subject: str = SUBJECT) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    authorized = GOVERNANCE_POLICY["status_checks"]["authorized_workflows"]
    by_path: dict[str, list[dict[str, str]]] = {}
    workflow_names: dict[str, str] = {}
    for item in authorized:
        by_path.setdefault(item["workflow_path"], []).append(item)
        workflow_names[item["workflow_path"]] = item["workflow_name"]
    catalog = []
    workflow_ids = {}
    for index, path in enumerate(sorted(by_path), start=701):
        workflow_id = 8000 + index
        workflow_ids[path] = workflow_id
        catalog.append({"id": workflow_id, "name": workflow_names[path], "path": path, "state": "active"})

    checks: list[dict[str, Any]] = []
    run_items: list[dict[str, Any]] = []
    check_id = 1000
    run_id = 2000
    for path in sorted(by_path):
        contexts = by_path[path]
        events = ["push", "pull_request"] if path != ".github/workflows/k-slide-security.yml" else ["pull_request"]
        for event in events:
            run_id += 1
            jobs = []
            for item in contexts:
                check_id += 1
                context = item["context"]
                check = {
                    "id": check_id,
                    "name": context,
                    "head_sha": HEAD_SHA,
                    "status": "completed",
                    "conclusion": "success",
                    "app_id": 15368,
                    "app_slug": "github-actions",
                }
                checks.append(check)
                jobs.append({
                    "workflow_run_id": run_id,
                    "job_id": check_id,
                    "check_run_id": check_id,
                    "run_attempt": 1,
                    "name": item["job_name"],
                    "check_name": check["name"],
                    "head_sha": HEAD_SHA,
                    "status": "completed",
                    "conclusion": "success",
                    "app_id": check["app_id"],
                    "app_slug": check["app_slug"],
                })
            run_items.append({
                "repository_id": REPOSITORY_ID,
                "repository_full_name": REPOSITORY_FULL_NAME,
                "run_id": run_id,
                "workflow_id": workflow_ids[path],
                "workflow_path": path,
                "workflow_name": workflow_names[path],
                "event": event,
                "head_sha": HEAD_SHA,
                "pull_requests": [],
                "run_attempt": 1,
                "status": "completed",
                "conclusion": "success",
                "jobs_complete": True,
                "jobs": jobs,
            })
    provenance = {
        "complete": True,
        "repository_id": REPOSITORY_ID,
        "repository_full_name": REPOSITORY_FULL_NAME,
        "subject_sha": subject,
        "pull_request_number": PULL_NUMBER,
        "pull_request_head_sha": HEAD_SHA,
        "workflow_catalog": {"complete": True, "items": catalog},
        "items": run_items,
    }
    return checks, provenance


def _ruleset_rules() -> list[dict[str, Any]]:
    status_checks = [
        {"context": context, "integration_id": 15368}
        for context in GOVERNANCE_POLICY["status_checks"]["required_contexts"]
    ]
    return [
        {"type": "pull_request", "parameters": {
            "required_approving_review_count": 1,
            "dismiss_stale_reviews_on_push": True,
            "require_last_push_approval": True,
            "require_code_owner_review": True,
        }},
        {"type": "required_status_checks", "parameters": {
            "strict_required_status_checks_policy": True,
            "required_status_checks": status_checks,
        }},
        {"type": "required_conversation_resolution", "parameters": None},
        {"type": "non_fast_forward", "parameters": None},
        {"type": "deletion", "parameters": None},
    ]


def _legacy_body() -> dict[str, Any]:
    return {
        "required_status_checks": {
            "strict": True,
            "checks": [
                {"context": context, "integration_id": 15368}
                for context in GOVERNANCE_POLICY["status_checks"]["required_contexts"]
            ],
        },
        "enforce_admins": {"enabled": True},
        "required_pull_request_reviews": {
            "required_approving_review_count": 1,
            "dismiss_stale_reviews": True,
            "require_code_owner_reviews": True,
            "require_last_push_approval": True,
            "bypass_pull_request_allowances": {"users": [], "teams": [], "apps": []},
        },
        "required_conversation_resolution": {"enabled": True},
        "allow_force_pushes": {"enabled": False},
        "allow_deletions": {"enabled": False},
    }


def github_governance_snapshot(
    *,
    subject: str = SUBJECT,
    protection: str = "ruleset",
    changed_paths: list[str] | None = None,
    codeowners_text: str | None = None,
) -> dict[str, Any]:
    root = Path(__file__).resolve().parents[1]
    codeowners = codeowners_text.encode("utf-8") if codeowners_text is not None else (root / CODEOWNERS_PATH).read_bytes()
    policy_bytes = (root / POLICY_PATH).read_bytes()
    if protection == "ruleset":
        ruleset_ref = {"id": 441, "target": "branch", "enforcement": "active"}
        details = [{
            "id": 441,
            "source": REPOSITORY_FULL_NAME,
            "source_type": "Repository",
            "target": "branch",
            "enforcement": "active",
            "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
            "bypass_actors": [],
            "rules": _ruleset_rules(),
        }]
        collection = {"complete": True, "items": [ruleset_ref]}
        legacy = {"http_status": 403, "body": None}
    elif protection == "legacy":
        details = []
        collection = {"complete": True, "items": []}
        legacy = {"http_status": 200, "body": _legacy_body()}
    elif protection == "combined":
        snap = github_governance_snapshot(subject=subject, protection="ruleset", changed_paths=changed_paths, codeowners_text=codeowners_text)
        snap["legacy_branch_protection"] = {"http_status": 200, "body": _legacy_body()}
        return snap
    else:
        raise ValueError(protection)
    check_runs, workflow_provenance = _checks_and_workflow_provenance(subject=subject)
    return {
        "repository_metadata": {"id": REPOSITORY_ID, "full_name": REPOSITORY_FULL_NAME, "default_branch": "main"},
        "target_branch": {"name": "main", "protected": True, "commit_sha": subject},
        "ruleset_collection": collection,
        "ruleset_details": details,
        "legacy_branch_protection": legacy,
        "pull_request": {
            "id": 9901,
            "number": PULL_NUMBER,
            "requested_number": PULL_NUMBER,
            "state": "closed",
            "merged": True,
            "merged_at": NOW,
            "merge_commit_sha": subject,
            "author": {"id": AUTHOR_ID, "login": "release-contributor"},
            "base": {
                "sha": BASE_SHA,
                "ref": "main",
                "repository_id": REPOSITORY_ID,
                "repository_full_name": REPOSITORY_FULL_NAME,
            },
            "head": {
                "sha": HEAD_SHA, "ref": "release-candidate",
                "repository_id": REPOSITORY_ID, "repository_full_name": REPOSITORY_FULL_NAME,
            },
        },
        "pull_request_reviews": [{
            "id": 7001,
            "user_id": OWNER_ID,
            "user_login": "kimhw8084",
            "state": "APPROVED",
            "commit_id": HEAD_SHA,
            "submitted_at": NOW,
        }],
        "pull_request_check_runs": {"complete": True, "items": check_runs},
        "workflow_run_provenance": workflow_provenance,
        "head_commit_pull_requests": {
            "complete": True,
            "repository_id": REPOSITORY_ID,
            "repository_full_name": REPOSITORY_FULL_NAME,
            "requested_pull_number": PULL_NUMBER,
            "head_sha": HEAD_SHA,
            "items": [{
                "id": 9901,
                "number": PULL_NUMBER,
                "base_repository_id": REPOSITORY_ID,
                "base_repository_full_name": REPOSITORY_FULL_NAME,
                "base_ref": "main",
                "head_sha": HEAD_SHA,
                "head_ref": "release-candidate",
                "head_repository_id": REPOSITORY_ID,
                "head_repository_full_name": REPOSITORY_FULL_NAME,
            }],
        },
        "pull_request_files": {"complete": True, "items": [{"filename": path} for path in (["src/k_slide/release_governance.py"] if changed_paths is None else changed_paths)]},
        "merge_commit": {"sha": subject, "parent_shas": [BASE_SHA, HEAD_SHA]},
        "candidate_codeowners": _file_snapshot(CODEOWNERS_PATH, subject, codeowners),
        "candidate_governance_policy": _file_snapshot(POLICY_PATH, subject, policy_bytes),
    }


def write_governance_sources(folder: Path, *, snapshot: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Path]:
    folder.mkdir(parents=True, exist_ok=True)
    value = snapshot if snapshot is not None else github_governance_snapshot(**kwargs)
    sources = {}
    for role, item in value.items():
        path = folder / f"{role}.json"
        path.write_text(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
        sources[role] = path
    return sources


def replace_snapshot_source(sources: dict[str, Path], role: str, value: Any) -> None:
    sources[role].write_text(json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")


def load_snapshot_source(sources: dict[str, Path], role: str) -> Any:
    return json.loads(sources[role].read_text(encoding="utf-8"))
