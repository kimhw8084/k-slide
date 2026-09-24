"""Capture minimal GitHub governance facts and derive candidate-bound evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from evals.release import _candidate_spec_for_release
from evals.scenarios import split_manifest
from k_slide.certification import canonical_candidate_factors, candidate_deployment_fingerprint
from k_slide.evidence_adapters import AdapterError, build_machine_evidence
from k_slide.model_policy import load_model_policy
from k_slide.release_governance import (
    GOVERNANCE_CONTRACT_IDENTITY,
    GOVERNANCE_CONTRACT_VERSION,
    GOVERNANCE_POLICY_ID,
    GOVERNANCE_POLICY_IDENTITY,
    GOVERNANCE_POLICY_VERSION,
    POLICY_PATH,
    CODEOWNERS_PATH,
    REPOSITORY_FULL_NAME,
)


class CaptureError(ValueError):
    pass


class GitHubReader:
    def __init__(self, token: str, api_url: str) -> None:
        self.token = token
        self.api_url = api_url.rstrip("/")

    def get(self, route: str, *, optional_protection: bool = False) -> tuple[Any, int]:
        request = Request(
            f"{self.api_url}/{route.lstrip('/')}",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urlopen(request, timeout=30) as response:
                body = response.read()
                return json.loads(body.decode("utf-8")), response.status
        except HTTPError as exc:
            if optional_protection and exc.code in {401, 403, 404}:
                return None, exc.code
            if exc.code in {401, 403}:
                raise CaptureError("GITHUB_READ_PERMISSION_MISSING") from exc
            raise CaptureError("GITHUB_API_REQUEST_FAILED") from exc
        except (URLError, TimeoutError, UnicodeError, json.JSONDecodeError) as exc:
            raise CaptureError("GITHUB_API_REQUEST_FAILED") from exc


def _array_pages(api: GitHubReader, route: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    page = 1
    while True:
        value, _status = api.get(f"{route}{'&' if '?' in route else '?'}per_page=100&page={page}")
        if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
            raise CaptureError("GITHUB_PAGED_RESPONSE_INVALID")
        result.extend(value)
        if len(value) < 100:
            return result
        page += 1


def _ruleset_projection(item: dict[str, Any]) -> dict[str, Any]:
    conditions = item.get("conditions")
    if not isinstance(conditions, dict):
        projected_conditions = conditions
    else:
        ref = conditions.get("ref_name")
        projected_conditions = {"ref_name": None if ref is None else {
            "include": ref.get("include"), "exclude": ref.get("exclude", []),
        }}
        repo_condition = conditions.get("repository_id")
        if repo_condition is not None:
            projected_conditions["repository_id"] = {
                "include": repo_condition.get("include"),
                "exclude": repo_condition.get("exclude", []),
            }
    rules = item.get("rules")
    if not isinstance(rules, list):
        raise CaptureError("GITHUB_RULESET_RESPONSE_INVALID")
    projected_rules = []
    for rule in rules:
        if not isinstance(rule, dict):
            raise CaptureError("GITHUB_RULESET_RESPONSE_INVALID")
        projected_rules.append({"type": rule.get("type"), "parameters": rule.get("parameters")})
    actors = item.get("bypass_actors")
    if not isinstance(actors, list):
        raise CaptureError("GITHUB_RULESET_RESPONSE_INVALID")
    projected_actors = []
    for actor in actors:
        if not isinstance(actor, dict):
            raise CaptureError("GITHUB_RULESET_RESPONSE_INVALID")
        projected_actors.append({
            "actor_id": actor.get("actor_id"), "actor_type": actor.get("actor_type"),
            "bypass_mode": actor.get("bypass_mode"),
        })
    return {
        "id": item.get("id"), "source": item.get("source"), "source_type": item.get("source_type"),
        "target": item.get("target"), "enforcement": item.get("enforcement"),
        "conditions": projected_conditions, "bypass_actors": projected_actors, "rules": projected_rules,
    }


def _legacy_projection(value: dict[str, Any]) -> dict[str, Any]:
    required_checks = value.get("required_status_checks")
    if isinstance(required_checks, dict):
        checks = required_checks.get("checks")
        projected_checks = None if not isinstance(checks, list) else [
            {"context": item.get("context"), "integration_id": item.get("app_id")}
            for item in checks if isinstance(item, dict)
        ]
        status = {"strict": required_checks.get("strict"), "checks": projected_checks}
    else:
        status = None
    reviews = value.get("required_pull_request_reviews")
    if isinstance(reviews, dict):
        allowances = reviews.get("bypass_pull_request_allowances") or {}
        reviews = {
            "required_approving_review_count": reviews.get("required_approving_review_count"),
            "dismiss_stale_reviews": reviews.get("dismiss_stale_reviews"),
            "require_code_owner_reviews": reviews.get("require_code_owner_reviews"),
            "require_last_push_approval": reviews.get("require_last_push_approval"),
            "bypass_pull_request_allowances": {
                key: allowances.get(key, []) for key in ("users", "teams", "apps")
            },
        }
    else:
        reviews = None
    def enabled(name: str) -> dict[str, Any]:
        item = value.get(name)
        return {"enabled": item.get("enabled")} if isinstance(item, dict) else {"enabled": None}
    return {
        "required_status_checks": status,
        "enforce_admins": enabled("enforce_admins"),
        "required_pull_request_reviews": reviews,
        "required_conversation_resolution": enabled("required_conversation_resolution"),
        "allow_force_pushes": enabled("allow_force_pushes"),
        "allow_deletions": enabled("allow_deletions"),
    }


def _candidate_file(api: GitHubReader, repository: str, path: str, subject_sha: str) -> dict[str, Any]:
    encoded_path = quote(path, safe="/")
    value, _status = api.get(f"repos/{repository}/contents/{encoded_path}?ref={subject_sha}")
    if not isinstance(value, dict) or value.get("type") != "file":
        raise CaptureError("CANDIDATE_FILE_NOT_FOUND")
    return {
        "path": value.get("path"), "ref": subject_sha, "sha": value.get("sha"),
        "encoding": value.get("encoding"), "content": value.get("content"),
    }


def _pull_projection(value: dict[str, Any], repository_id: int, requested_number: int) -> dict[str, Any]:
    author = value.get("user")
    base = value.get("base")
    head = value.get("head")
    if not all(isinstance(item, dict) for item in (author, base, head)):
        raise CaptureError("GITHUB_PULL_REQUEST_RESPONSE_INVALID")
    base_repo = base.get("repo")
    if not isinstance(base_repo, dict):
        raise CaptureError("GITHUB_PULL_REQUEST_RESPONSE_INVALID")
    return {
        "id": value.get("id"), "number": value.get("number"), "requested_number": requested_number, "state": value.get("state"),
        "merged": value.get("merged"), "merged_at": value.get("merged_at"),
        "merge_commit_sha": value.get("merge_commit_sha"),
        "author": {"id": author.get("id"), "login": author.get("login")},
        "base": {
            "sha": base.get("sha"), "ref": base.get("ref"),
            "repository_id": base_repo.get("id", repository_id),
            "repository_full_name": base_repo.get("full_name"),
        },
        "head": {"sha": head.get("sha"), "ref": head.get("ref")},
    }


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


def capture_snapshots(api: GitHubReader, repository: str, pull_number: int, subject_sha: str, output: Path) -> dict[str, Path]:
    if repository.casefold() != REPOSITORY_FULL_NAME.casefold():
        raise CaptureError("GOVERNANCE_REPOSITORY_NOT_AUTHORIZED")
    repo, _ = api.get(f"repos/{repository}")
    if not isinstance(repo, dict):
        raise CaptureError("GITHUB_REPOSITORY_RESPONSE_INVALID")
    repository_id = repo.get("id")
    branch_name = "main"
    branch, _ = api.get(f"repos/{repository}/branches/{quote(branch_name, safe='')}")
    if not isinstance(branch, dict) or not isinstance(branch.get("commit"), dict):
        raise CaptureError("GITHUB_BRANCH_RESPONSE_INVALID")
    refs, _ = api.get(f"repos/{repository}/rulesets?include_parents=false&per_page=100&page=1")
    if not isinstance(refs, list) or any(not isinstance(item, dict) for item in refs):
        raise CaptureError("GITHUB_RULESET_COLLECTION_INVALID")
    all_refs = list(refs)
    page = 2
    while len(refs) == 100:
        refs, _ = api.get(f"repos/{repository}/rulesets?include_parents=false&per_page=100&page={page}")
        if not isinstance(refs, list) or any(not isinstance(item, dict) for item in refs):
            raise CaptureError("GITHUB_RULESET_COLLECTION_INVALID")
        all_refs.extend(refs)
        page += 1
    refs = all_refs
    rule_details = []
    projected_refs = []
    for item in refs:
        projected_refs.append({"id": item.get("id"), "target": item.get("target"), "enforcement": item.get("enforcement")})
        detail, _ = api.get(f"repos/{repository}/rulesets/{item.get('id')}")
        if not isinstance(detail, dict):
            raise CaptureError("GITHUB_RULESET_DETAIL_INVALID")
        rule_details.append(_ruleset_projection(detail))
    protection, protection_status = api.get(
        f"repos/{repository}/branches/{quote(branch_name, safe='')}/protection",
        optional_protection=True,
    )
    legacy = {
        "http_status": protection_status,
        "body": _legacy_projection(protection) if protection_status == 200 and isinstance(protection, dict) else None,
    }
    pull_value, _ = api.get(f"repos/{repository}/pulls/{pull_number}")
    if not isinstance(pull_value, dict):
        raise CaptureError("GITHUB_PULL_REQUEST_RESPONSE_INVALID")
    pull = _pull_projection(pull_value, repository_id, pull_number)
    head_sha = pull["head"]["sha"]
    merge_sha = pull["merge_commit_sha"]
    if not isinstance(head_sha, str) or not isinstance(merge_sha, str):
        raise CaptureError("GITHUB_PULL_REQUEST_RESPONSE_INVALID")

    reviews = _array_pages(api, f"repos/{repository}/pulls/{pull_number}/reviews")
    projected_reviews = []
    for item in reviews:
        user = item.get("user")
        if not isinstance(user, dict):
            user = {}
        projected_reviews.append({
            "id": item.get("id"), "user_id": user.get("id"), "user_login": user.get("login"),
            "state": item.get("state"), "commit_id": item.get("commit_id"),
            "submitted_at": item.get("submitted_at"),
        })
    checks = []
    page = 1
    while True:
        value, _ = api.get(f"repos/{repository}/commits/{head_sha}/check-runs?per_page=100&page={page}")
        if not isinstance(value, dict) or not isinstance(value.get("check_runs"), list):
            raise CaptureError("GITHUB_CHECK_RUN_RESPONSE_INVALID")
        runs = value["check_runs"]
        for item in runs:
            app = item.get("app")
            if not isinstance(app, dict):
                app = {}
            checks.append({
                "id": item.get("id"), "name": item.get("name"), "head_sha": item.get("head_sha"),
                "status": item.get("status"), "conclusion": item.get("conclusion"),
                "app_id": app.get("id"), "app_slug": app.get("slug"),
            })
        if len(runs) < 100:
            break
        page += 1
    files = _array_pages(api, f"repos/{repository}/pulls/{pull_number}/files")
    projected_files = [{"filename": item.get("filename")} for item in files]
    commit_value, _ = api.get(f"repos/{repository}/commits/{merge_sha}")
    if not isinstance(commit_value, dict) or not isinstance(commit_value.get("parents"), list):
        raise CaptureError("GITHUB_MERGE_COMMIT_RESPONSE_INVALID")
    merge_commit = {"sha": commit_value.get("sha"), "parent_shas": [item.get("sha") for item in commit_value["parents"] if isinstance(item, dict)]}
    snapshots = {
        "repository_metadata": {"id": repository_id, "full_name": repo.get("full_name"), "default_branch": repo.get("default_branch")},
        "target_branch": {"name": branch.get("name"), "protected": branch.get("protected"), "commit_sha": branch["commit"].get("sha")},
        "ruleset_collection": {"complete": True, "items": projected_refs},
        "ruleset_details": rule_details,
        "legacy_branch_protection": legacy,
        "pull_request": pull,
        "pull_request_reviews": projected_reviews,
        "pull_request_check_runs": {"complete": True, "items": checks},
        "pull_request_files": {"complete": True, "items": projected_files},
        "merge_commit": merge_commit,
        "candidate_codeowners": _candidate_file(api, repository, CODEOWNERS_PATH, subject_sha),
        "candidate_governance_policy": _candidate_file(api, repository, POLICY_PATH, subject_sha),
    }
    snapshot_root = output
    paths = {}
    for role, value in snapshots.items():
        path = snapshot_root / f"{role}.json"
        _write_json(path, value)
        paths[role] = path
    return paths


def _candidate_identity(candidate: dict[str, Any]) -> tuple[str, str]:
    factors = canonical_candidate_factors(candidate)
    deployment = candidate_deployment_fingerprint(candidate)
    candidate_identity = hashlib.sha256(json.dumps(factors, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return deployment, candidate_identity


def capture_and_derive(*, repository: str, pull_number: int, subject_sha: str, candidate_profile: Path, output: Path, root: Path) -> dict[str, Any]:
    token = os.environ.get("KSLIDE_GOVERNANCE_READ_TOKEN", "")
    if not token.strip():
        raise CaptureError("GOVERNANCE_READ_CREDENTIAL_MISSING")
    subject_sha = subject_sha.lower()
    api = GitHubReader(token, os.environ.get("GITHUB_API_URL", "https://api.github.com"))
    output.mkdir(parents=True, exist_ok=True)
    candidate, resolved_subject = _candidate_spec_for_release(
        root,
        candidate_profile=candidate_profile,
        subject_sha=subject_sha,
        model=None,
        policy=load_model_policy(root),
        corpus=split_manifest(),
        require_identity=True,
    )
    if resolved_subject != subject_sha:
        raise CaptureError("CANDIDATE_SUBJECT_MISMATCH")
    deployment, candidate_identity = _candidate_identity(candidate)
    sources = capture_snapshots(api, repository, pull_number, subject_sha, output)
    evidence = output / "evidence.json"
    try:
        build_machine_evidence(
            evidence,
            evidence_type="governance",
            subject_git_sha=subject_sha,
            deployment_fingerprint=deployment,
            sources=sources,
            root=root,
            candidate_spec=candidate,
            generated_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        )
        status = {
            "schema_version": "1.0", "status": "PASS",
            "governance_contract_version": GOVERNANCE_CONTRACT_VERSION,
            "governance_contract_identity": GOVERNANCE_CONTRACT_IDENTITY,
            "governance_policy_id": GOVERNANCE_POLICY_ID,
            "governance_policy_version": GOVERNANCE_POLICY_VERSION,
            "governance_policy_identity": GOVERNANCE_POLICY_IDENTITY,
            "repository_full_name": REPOSITORY_FULL_NAME,
            "subject_git_sha": subject_sha,
            "candidate_deployment_fingerprint": deployment,
            "candidate_spec_identity_sha256": candidate_identity,
            "evidence_sha256": hashlib.sha256(evidence.read_bytes()).hexdigest(),
        }
        _write_json(output / "governance-status.json", status)
        return status
    except (AdapterError, OSError, ValueError) as exc:
        role_hashes = {
            role: hashlib.sha256(path.read_bytes()).hexdigest()
            for role, path in sorted(sources.items())
        }
        code = str(exc).rsplit("(", 1)[-1].rstrip(")") if "(" in str(exc) else "GOVERNANCE_FACTS_INSUFFICIENT"
        status = {
            "schema_version": "1.0", "status": "NOT_QUALIFIED",
            "outcome_code": "GOVERNANCE_FACTS_INSUFFICIENT",
            "reason_code": code if code and code.isupper() else "GOVERNANCE_FACTS_INSUFFICIENT",
            "governance_contract_version": GOVERNANCE_CONTRACT_VERSION,
            "governance_contract_identity": GOVERNANCE_CONTRACT_IDENTITY,
            "governance_policy_id": GOVERNANCE_POLICY_ID,
            "governance_policy_version": GOVERNANCE_POLICY_VERSION,
            "governance_policy_identity": GOVERNANCE_POLICY_IDENTITY,
            "repository_full_name": REPOSITORY_FULL_NAME,
            "subject_git_sha": subject_sha,
            "candidate_deployment_fingerprint": deployment,
            "candidate_spec_identity_sha256": candidate_identity,
            "snapshot_role_sha256": role_hashes,
        }
        _write_json(output / "governance-status.json", status)
        return status


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Capture exact candidate-bound GitHub release-governance facts")
    parser.add_argument("--repository", required=True)
    parser.add_argument("--pull-request", required=True, type=int)
    parser.add_argument("--subject-sha", required=True)
    parser.add_argument("--candidate-profile", type=Path, default=Path("evals/production-candidate.yaml"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    try:
        status = capture_and_derive(
            repository=args.repository,
            pull_number=args.pull_request,
            subject_sha=args.subject_sha,
            candidate_profile=args.candidate_profile,
            output=args.output,
            root=args.root,
        )
    except (CaptureError, OSError, ValueError) as exc:
        code = str(exc) if str(exc).isupper() else "GOVERNANCE_CAPTURE_FAILED"
        print(json.dumps({"status": "BLOCKED", "outcome_code": code}, sort_keys=True))
        return 2
    print(json.dumps({
        "status": status["status"],
        "governance_policy_version": status["governance_policy_version"],
        "candidate_deployment_fingerprint": status["candidate_deployment_fingerprint"],
        "subject_git_sha": status["subject_git_sha"],
    }, sort_keys=True))
    return 0 if status["status"] in {"PASS", "NOT_QUALIFIED"} else 2


if __name__ == "__main__":
    sys.exit(main())
