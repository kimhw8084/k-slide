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
HEAD_SHA = "b" * 40
BASE_SHA = "c" * 40
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


def _checks() -> list[dict[str, Any]]:
    return [
        {
            "id": index + 100,
            "name": context,
            "head_sha": HEAD_SHA,
            "status": "completed",
            "conclusion": "success",
            "app_id": 15368,
            "app_slug": "github-actions",
        }
        for index, context in enumerate(GOVERNANCE_POLICY["status_checks"]["required_contexts"])
    ]


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
    return {
        "repository_metadata": {"id": REPOSITORY_ID, "full_name": REPOSITORY_FULL_NAME, "default_branch": "main"},
        "target_branch": {"name": "main", "protected": True, "commit_sha": subject},
        "ruleset_collection": collection,
        "ruleset_details": details,
        "legacy_branch_protection": legacy,
        "pull_request": {
            "id": 9901,
            "number": 32,
            "requested_number": 32,
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
            "head": {"sha": HEAD_SHA, "ref": "release-candidate"},
        },
        "pull_request_reviews": [{
            "id": 7001,
            "user_id": OWNER_ID,
            "user_login": "kimhw8084",
            "state": "APPROVED",
            "commit_id": HEAD_SHA,
            "submitted_at": NOW,
        }],
        "pull_request_check_runs": {"complete": True, "items": _checks()},
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
