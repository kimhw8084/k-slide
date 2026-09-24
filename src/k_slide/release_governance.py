"""Closed GitHub fact derivation for the repository release gate.

The policy constants in this module are the authority.  Candidate-bound GitHub
snapshots are inputs only; no caller-authored outcome or source label can
replace the derivation below.
"""

from __future__ import annotations

import base64
import fnmatch
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any


GOVERNANCE_CONTRACT_VERSION = "1.0"
GOVERNANCE_POLICY = {
    "schema_version": "1.0",
    "contract": {"id": "k-slide.protected-release-governance", "version": "1.0"},
    "policy": {"id": "kimhw8084-k-slide-production-release", "version": "1.0"},
    "repository": {"full_name": "kimhw8084/k-slide"},
    "target": {"default_branch": "main", "release_branch": "main"},
    "production_sensitive_paths": [
        "/AGENTS.md", "/src/", "/.opencode/", "/schemas/", "/evals/",
        "/prompts/", "/termbase/", "/security/", "/deploy/",
        "/.github/workflows/", "/.github/CODEOWNERS",
        "/constraints-production.txt",
        "/pyproject.toml", "/production-slo.yaml", "/scripts/",
        "/private-evals/", "/tests/", "/docs/zero-korean-human-study.md",
    ],
    "eligible_codeowners": ["kimhw8084"],
    "review": {
        "minimum_approvals": 1,
        "independent_from_author": True,
        "approval_commit": "exact_current_pr_head",
        "dismiss_stale_reviews_on_push": True,
        "require_last_push_approval": True,
        "require_code_owner_review": True,
    },
    "status_checks": {
        "strict": True,
        "required_contexts": [
            "test (3.11)", "test (3.12)", "security", "fast (3.11)", "fast (3.12)",
        ],
        "integration": {"app_id": 15368, "slug": "github-actions"},
    },
    "protection": {
        "pr_only_integration": True,
        "conversation_resolution": True,
        "prevent_force_pushes": True,
        "prevent_branch_deletion": True,
        "enforce_admins": True,
        "allow_bypass_actors": False,
        "supported_mechanisms": ["repository_rulesets", "legacy_branch_protection"],
    },
}
GOVERNANCE_POLICY_VERSION = GOVERNANCE_POLICY["policy"]["version"]
GOVERNANCE_POLICY_ID = GOVERNANCE_POLICY["policy"]["id"]
REPOSITORY_FULL_NAME = GOVERNANCE_POLICY["repository"]["full_name"]
RELEASE_BRANCH = GOVERNANCE_POLICY["target"]["release_branch"]
POLICY_PATH = "security/release-governance-policy.json"
CODEOWNERS_PATH = ".github/CODEOWNERS"

_ROLES = frozenset({
    "repository_metadata", "target_branch", "ruleset_collection", "ruleset_details",
    "legacy_branch_protection", "pull_request", "pull_request_reviews",
    "pull_request_check_runs", "pull_request_files", "merge_commit",
    "candidate_codeowners", "candidate_governance_policy",
})
_PASS_CODES = [
    "REPOSITORY_BOUND", "RELEASE_SUBJECT_MERGED_BY_PR", "PROTECTION_EFFECTIVE",
    "INDEPENDENT_CURRENT_HEAD_REVIEW", "CODEOWNERS_ENFORCED", "STRICT_REQUIRED_CHECKS",
    "PRODUCTION_BRANCH_INTEGRITY", "NO_GATE_BYPASS",
]
_PAYLOAD_KEYS = frozenset({
    "schema_version", "governance_contract_version", "governance_contract_identity",
    "governance_policy_id", "governance_policy_version", "governance_policy_identity",
    "governance_policy_file_sha256", "repository_full_name", "repository_id",
    "repository_identity_sha256", "default_branch", "release_branch", "branch_head_sha",
    "release_subject_sha", "pull_request_number", "pull_request_identity_sha256",
    "pull_request_author_identity_sha256", "independent_reviewer_identities",
    "pull_request_head_sha", "pull_request_base_sha", "pull_request_merge_commit_sha",
    "candidate_deployment_fingerprint", "candidate_spec_identity_sha256",
    "protection_mechanism", "protection_detail_http_status", "active_ruleset_ids",
    "ruleset_identity_sha256s", "legacy_protection_sha256", "effective_protection_sha256",
    "required_approving_reviews", "review_count", "independent_approval_count",
    "approving_review_identities", "review_pass", "codeowners_sha256", "codeowners_git_blob_sha",
    "changed_file_count", "production_sensitive_change_count", "changed_file_set_sha256",
    "codeowner_group_count", "codeowner_approval_group_count", "codeowners_pass",
    "status_check_contexts", "required_check_run_ids", "required_check_identities",
    "required_check_app_ids", "required_check_pass", "required_status_checks_strict",
    "stale_review_dismissal_required", "last_push_approval_required",
    "code_owner_enforcement_required", "conversation_resolution_required",
    "force_push_prevention_required", "branch_deletion_prevention_required",
    "admin_enforcement_required", "pr_only_integration_required", "bypass_actor_count", "pass_codes",
})
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class ReleaseGovernanceError(ValueError):
    """A raw governance snapshot is incomplete, contradictory, or insufficient."""


class _DuplicateJsonKey(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey("duplicate JSON object key")
        result[key] = value
    return result


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


GOVERNANCE_POLICY_IDENTITY = _sha256(_canonical_bytes(GOVERNANCE_POLICY))
GOVERNANCE_CONTRACT_IDENTITY = _sha256(_canonical_bytes({
    "contract": GOVERNANCE_POLICY["contract"],
    "policy_id": GOVERNANCE_POLICY_ID,
    "policy_identity": GOVERNANCE_POLICY_IDENTITY,
}))


def required_governance_roles() -> tuple[str, ...]:
    return tuple(sorted(_ROLES))


def _read_source(path: Path) -> Any:
    if path.is_symlink() or not path.is_file():
        raise ReleaseGovernanceError("GOVERNANCE_SOURCE_MISSING")
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError, _DuplicateJsonKey) as exc:
        raise ReleaseGovernanceError("GOVERNANCE_SOURCE_MALFORMED") from exc


def _expect_keys(value: Any, keys: set[str] | frozenset[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ReleaseGovernanceError(code)
    return value


def _string(value: Any, code: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ReleaseGovernanceError(code)
    return value


def _int(value: Any, code: str, *, minimum: int = 1) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise ReleaseGovernanceError(code)
    return value


def _sha(value: Any, code: str, *, length: int = 40) -> str:
    if not isinstance(value, str):
        raise ReleaseGovernanceError(code)
    normalized = value.lower()
    pattern = _HEX40 if length == 40 else _HEX64
    if not pattern.fullmatch(normalized):
        raise ReleaseGovernanceError(code)
    return normalized


def _identity(value: Any) -> str:
    return _sha256(_canonical_bytes(value))


def _snapshot_bytes(value: Any, path: str, subject_sha: str) -> tuple[bytes, str, str]:
    item = _expect_keys(value, {"path", "ref", "sha", "encoding", "content"}, "CANDIDATE_FILE_SNAPSHOT_INVALID")
    if item["path"] != path or item["ref"] != subject_sha or item["encoding"] != "base64":
        raise ReleaseGovernanceError("CANDIDATE_FILE_NOT_BOUND_TO_RELEASE_SUBJECT")
    blob_sha = _string(item["sha"], "CANDIDATE_FILE_SNAPSHOT_INVALID").lower()
    try:
        encoded = "".join(_string(item["content"], "CANDIDATE_FILE_SNAPSHOT_INVALID").split())
        content = base64.b64decode(encoded, validate=True)
        text = content.decode("utf-8")
    except (ValueError, UnicodeError) as exc:
        raise ReleaseGovernanceError("CANDIDATE_FILE_SNAPSHOT_INVALID") from exc
    actual_blob_sha = hashlib.sha1(b"blob " + str(len(content)).encode("ascii") + b"\0" + content).hexdigest()
    if actual_blob_sha != blob_sha:
        raise ReleaseGovernanceError("CANDIDATE_FILE_BLOB_IDENTITY_MISMATCH")
    return content, text, blob_sha


def _parse_codeowners(text: str) -> list[tuple[str, tuple[str, ...]]]:
    rules: list[tuple[str, tuple[str, ...]]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) < 2 or fields[0].startswith("!"):
            raise ReleaseGovernanceError("CODEOWNERS_SYNTAX_UNSUPPORTED")
        pattern = fields[0].replace("\\#", "#")
        owners = tuple(fields[1:])
        if not pattern or any(not owner.startswith("@") or owner.count("@") != 1 or "/" in owner[1:] for owner in owners):
            raise ReleaseGovernanceError("CODEOWNERS_OWNER_UNSUPPORTED")
        allowed = {item.casefold() for item in GOVERNANCE_POLICY["eligible_codeowners"]}
        if any(owner[1:].casefold() not in allowed for owner in owners):
            raise ReleaseGovernanceError("CODEOWNERS_PRINCIPAL_NOT_AUTHORIZED")
        rules.append((pattern, owners))
    if not rules:
        raise ReleaseGovernanceError("CODEOWNERS_EMPTY")
    return rules


def _pattern_matches(pattern: str, path: str) -> bool:
    pattern = pattern.lstrip("/")
    path = path.lstrip("/")
    if pattern == "*":
        return bool(path)
    if pattern.endswith("/"):
        return path.startswith(pattern)
    if "/" not in pattern:
        return any(fnmatch.fnmatchcase(part, pattern) for part in path.split("/"))
    # CODEOWNERS uses gitignore-style globs: a single * does not cross a slash.
    tokens: list[str] = []
    index = 0
    while index < len(pattern):
        if pattern[index:index + 2] == "**":
            tokens.append(".*")
            index += 2
        elif pattern[index] == "*":
            tokens.append("[^/]*")
            index += 1
        elif pattern[index] == "?":
            tokens.append("[^/]")
            index += 1
        else:
            tokens.append(re.escape(pattern[index]))
            index += 1
    expression = "^" + "".join(tokens) + ("(?:/.*)?" if pattern.endswith("/") else "$")
    return re.match(expression, path) is not None


def _owners_for_path(rules: list[tuple[str, tuple[str, ...]]], path: str) -> tuple[str, ...]:
    owners: tuple[str, ...] = ()
    for pattern, candidate_owners in rules:
        if _pattern_matches(pattern, path):
            owners = candidate_owners
    return owners


def _path_is_sensitive(path: str) -> bool:
    for protected in GOVERNANCE_POLICY["production_sensitive_paths"]:
        target = protected.lstrip("/")
        if target.endswith("/") and path.startswith(target):
            return True
        if path == target:
            return True
    return False


def _verify_codeowners_coverage(rules: list[tuple[str, tuple[str, ...]]]) -> None:
    available = {pattern.lstrip("/") for pattern, _owners in rules}
    if "*" in available:
        return
    for protected in GOVERNANCE_POLICY["production_sensitive_paths"]:
        path = protected.lstrip("/")
        alternatives = {path}
        if path.endswith("/"):
            alternatives.add(path + "**")
        if not alternatives.intersection(available):
            raise ReleaseGovernanceError("CODEOWNERS_POLICY_PATH_UNCOVERED")
        samples = [path.rstrip("/")] if not path.endswith("/") else [
            path + "__kslide_governance_probe__.py",
            path + "nested/__kslide_governance_probe__.py",
        ]
        if any(not _owners_for_path(rules, sample) for sample in samples):
            raise ReleaseGovernanceError("CODEOWNERS_EFFECTIVE_RULE_UNCOVERED")


def _ruleset_scope(detail: dict[str, Any], repository_id: int) -> tuple[bool, bool]:
    if detail.get("target") != "branch":
        return False, False
    conditions = detail.get("conditions")
    if not isinstance(conditions, dict):
        raise ReleaseGovernanceError("RULESET_CONDITIONS_AMBIGUOUS")
    if set(conditions) - {"ref_name", "repository_id"}:
        raise ReleaseGovernanceError("RULESET_CONDITIONS_AMBIGUOUS")
    repository_condition = conditions.get("repository_id")
    repository_exact = True
    if repository_condition is not None:
        if not isinstance(repository_condition, dict):
            raise ReleaseGovernanceError("RULESET_CONDITIONS_AMBIGUOUS")
        include_ids = repository_condition.get("include")
        exclude_ids = repository_condition.get("exclude", [])
        if not isinstance(include_ids, list) or not isinstance(exclude_ids, list):
            raise ReleaseGovernanceError("RULESET_CONDITIONS_AMBIGUOUS")
        if include_ids and repository_id not in include_ids:
            return False, False
        if repository_id in exclude_ids:
            return False, False
        repository_exact = include_ids == [repository_id] and exclude_ids == []
    refs = conditions.get("ref_name")
    if refs is None:
        return True, False
    if not isinstance(refs, dict) or set(refs) != {"include", "exclude"}:
        raise ReleaseGovernanceError("RULESET_CONDITIONS_AMBIGUOUS")
    include = refs["include"]
    exclude = refs["exclude"]
    if not isinstance(include, list) or not isinstance(exclude, list) or any(not isinstance(item, str) for item in include + exclude):
        raise ReleaseGovernanceError("RULESET_CONDITIONS_AMBIGUOUS")
    target_ref = f"refs/heads/{RELEASE_BRANCH}"
    included = not include or any(item == "~ALL" or item == "~DEFAULT_BRANCH" or fnmatch.fnmatchcase(target_ref, item) for item in include)
    excluded = any(item == "~ALL" or item == "~DEFAULT_BRANCH" or fnmatch.fnmatchcase(target_ref, item) for item in exclude)
    if not included or excluded:
        return False, False
    exact = repository_exact and include in ([target_ref], ["~DEFAULT_BRANCH"]) and exclude == []
    return True, exact


def _check_map(items: Any, *, source: str) -> dict[str, int]:
    if not isinstance(items, list):
        raise ReleaseGovernanceError(f"{source}_STATUS_CHECKS_INVALID")
    result: dict[str, int] = {}
    for item in items:
        check = _expect_keys(item, {"context", "integration_id"}, f"{source}_STATUS_CHECKS_INVALID")
        context = _string(check["context"], f"{source}_STATUS_CHECKS_INVALID")
        integration_id = _int(check["integration_id"], f"{source}_STATUS_CHECKS_INVALID")
        if context in result:
            raise ReleaseGovernanceError("STATUS_CHECK_CONTEXT_DUPLICATE")
        result[context] = integration_id
    return result


def _require_status_policy(checks: dict[str, int], *, strict: bool) -> None:
    expected = set(GOVERNANCE_POLICY["status_checks"]["required_contexts"])
    if not strict:
        raise ReleaseGovernanceError("STATUS_CHECKS_NOT_STRICT")
    if set(checks) != expected:
        raise ReleaseGovernanceError("STATUS_CHECK_POLICY_MISMATCH")
    app_id = GOVERNANCE_POLICY["status_checks"]["integration"]["app_id"]
    if any(binding != app_id for binding in checks.values()):
        raise ReleaseGovernanceError("STATUS_CHECK_INTEGRATION_MISMATCH")


def _effective_rulesets(value: Any, details_value: Any, repository_id: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    collection = _expect_keys(value, {"complete", "items"}, "RULESET_COLLECTION_INVALID")
    if collection["complete"] is not True or not isinstance(collection["items"], list):
        raise ReleaseGovernanceError("RULESET_COLLECTION_INCOMPLETE")
    references: dict[int, dict[str, Any]] = {}
    for item in collection["items"]:
        ref = _expect_keys(item, {"id", "target", "enforcement"}, "RULESET_COLLECTION_INVALID")
        rule_id = _int(ref["id"], "RULESET_COLLECTION_INVALID")
        if rule_id in references:
            raise ReleaseGovernanceError("RULESET_COLLECTION_DUPLICATE")
        references[rule_id] = ref
    if not isinstance(details_value, list):
        raise ReleaseGovernanceError("RULESET_DETAILS_INVALID")
    details_by_id: dict[int, dict[str, Any]] = {}
    for item in details_value:
        detail = _expect_keys(item, {"id", "source", "source_type", "target", "enforcement", "conditions", "bypass_actors", "rules"}, "RULESET_DETAILS_INVALID")
        rule_id = _int(detail["id"], "RULESET_DETAILS_INVALID")
        if rule_id in details_by_id:
            raise ReleaseGovernanceError("RULESET_DETAILS_DUPLICATE")
        details_by_id[rule_id] = detail
    if set(references) != set(details_by_id):
        raise ReleaseGovernanceError("RULESET_DETAILS_INCOMPLETE")
    effective: list[dict[str, Any]] = []
    for rule_id, ref in references.items():
        detail = details_by_id[rule_id]
        if any(detail[key] != ref[key] for key in ("target", "enforcement")):
            raise ReleaseGovernanceError("RULESET_COLLECTION_DETAIL_MISMATCH")
        source = detail["source"]
        source_type = detail["source_type"]
        if not isinstance(source, str) or source.casefold() != REPOSITORY_FULL_NAME.casefold():
            raise ReleaseGovernanceError("RULESET_REPOSITORY_MISMATCH")
        if source_type != "Repository":
            raise ReleaseGovernanceError("RULESET_SOURCE_TYPE_UNSUPPORTED")
        applicable, exact = _ruleset_scope(detail, repository_id)
        if not applicable or detail["enforcement"] != "active":
            continue
        if not exact:
            raise ReleaseGovernanceError("RULESET_TARGET_NOT_EXACT")
        actors = detail["bypass_actors"]
        if not isinstance(actors, list):
            raise ReleaseGovernanceError("RULESET_BYPASS_INVALID")
        for actor in actors:
            _expect_keys(actor, {"actor_id", "actor_type", "bypass_mode"}, "RULESET_BYPASS_INVALID")
        if actors:
            raise ReleaseGovernanceError("RULESET_BYPASS_ACTOR_PRESENT")
        effective.append(detail)
    requirements: dict[str, Any] = {
        "approvals": 0, "stale": False, "last_push": False, "codeowners": False,
        "strict": False, "status_checks": {}, "conversation": False,
        "force_push_prevention": False, "deletion_prevention": False,
    }
    for detail in effective:
        rules = detail["rules"]
        if not isinstance(rules, list):
            raise ReleaseGovernanceError("RULESET_RULES_INVALID")
        seen: set[str] = set()
        for raw_rule in rules:
            rule = _expect_keys(raw_rule, {"type", "parameters"}, "RULESET_RULES_INVALID")
            kind = _string(rule["type"], "RULESET_RULES_INVALID")
            if kind in seen:
                raise ReleaseGovernanceError("RULESET_RULE_DUPLICATE")
            seen.add(kind)
            parameters = rule["parameters"]
            if kind == "pull_request":
                params = _expect_keys(parameters, {
                    "required_approving_review_count", "dismiss_stale_reviews_on_push",
                    "require_last_push_approval", "require_code_owner_review",
                }, "RULESET_PULL_REQUEST_RULE_INVALID")
                requirements["approvals"] = max(requirements["approvals"], _int(params["required_approving_review_count"], "RULESET_APPROVAL_COUNT_INVALID", minimum=0))
                requirements["stale"] = requirements["stale"] or params["dismiss_stale_reviews_on_push"] is True
                requirements["last_push"] = requirements["last_push"] or params["require_last_push_approval"] is True
                requirements["codeowners"] = requirements["codeowners"] or params["require_code_owner_review"] is True
            elif kind == "required_status_checks":
                params = _expect_keys(parameters, {"strict_required_status_checks_policy", "required_status_checks"}, "RULESET_STATUS_RULE_INVALID")
                if params["strict_required_status_checks_policy"] is not True:
                    raise ReleaseGovernanceError("STATUS_CHECKS_NOT_STRICT")
                status = _check_map(params["required_status_checks"], source="RULESET")
                for context, app_id in status.items():
                    if context in requirements["status_checks"] and requirements["status_checks"][context] != app_id:
                        raise ReleaseGovernanceError("STATUS_CHECK_BINDING_AMBIGUOUS")
                    requirements["status_checks"][context] = app_id
                requirements["strict"] = True
            elif kind == "required_conversation_resolution":
                if parameters not in (None, {}):
                    raise ReleaseGovernanceError("RULESET_CONVERSATION_RULE_INVALID")
                requirements["conversation"] = True
            elif kind == "non_fast_forward":
                if parameters not in (None, {}):
                    raise ReleaseGovernanceError("RULESET_FORCE_PUSH_RULE_INVALID")
                requirements["force_push_prevention"] = True
            elif kind == "deletion":
                if parameters not in (None, {}):
                    raise ReleaseGovernanceError("RULESET_DELETION_RULE_INVALID")
                requirements["deletion_prevention"] = True
            else:
                raise ReleaseGovernanceError("RULESET_RULE_TYPE_UNSUPPORTED")
    return effective, requirements


def _legacy_requirements(value: Any) -> tuple[dict[str, Any] | None, int]:
    response = _expect_keys(value, {"http_status", "body"}, "LEGACY_PROTECTION_SNAPSHOT_INVALID")
    status = _int(response["http_status"], "LEGACY_PROTECTION_SNAPSHOT_INVALID", minimum=100)
    if status != 200:
        if status not in {401, 403, 404} or response["body"] is not None:
            raise ReleaseGovernanceError("LEGACY_PROTECTION_RESPONSE_UNSUPPORTED")
        return None, status
    body = _expect_keys(response["body"], {
        "required_status_checks", "enforce_admins", "required_pull_request_reviews",
        "required_conversation_resolution", "allow_force_pushes", "allow_deletions",
    }, "LEGACY_PROTECTION_BODY_INVALID")
    pr = body["required_pull_request_reviews"]
    if not isinstance(pr, dict):
        raise ReleaseGovernanceError("LEGACY_PR_REVIEW_RULE_MISSING")
    required_pr_keys = {
        "required_approving_review_count", "dismiss_stale_reviews", "require_code_owner_reviews",
        "require_last_push_approval", "bypass_pull_request_allowances",
    }
    pr = _expect_keys(pr, required_pr_keys, "LEGACY_PR_REVIEW_RULE_INVALID")
    allowances = _expect_keys(pr["bypass_pull_request_allowances"], {"users", "teams", "apps"}, "LEGACY_BYPASS_ALLOWANCES_INVALID")
    if any(not isinstance(allowances[key], list) for key in allowances) or any(allowances.values()):
        raise ReleaseGovernanceError("LEGACY_BYPASS_ALLOWANCE_PRESENT")
    checks = body["required_status_checks"]
    if not isinstance(checks, dict):
        raise ReleaseGovernanceError("LEGACY_STATUS_RULE_MISSING")
    checks = _expect_keys(checks, {"strict", "checks"}, "LEGACY_STATUS_RULE_INVALID")
    check_map = _check_map(checks["checks"], source="LEGACY")
    _require_status_policy(check_map, strict=checks["strict"] is True)
    enabled_rules = {}
    for key in ("enforce_admins", "required_conversation_resolution", "allow_force_pushes", "allow_deletions"):
        enabled_rules[key] = _expect_keys(body[key], {"enabled"}, "LEGACY_BRANCH_RULE_INVALID")["enabled"]
        if not isinstance(enabled_rules[key], bool):
            raise ReleaseGovernanceError("LEGACY_BRANCH_RULE_INVALID")
    if enabled_rules["enforce_admins"] is not True:
        raise ReleaseGovernanceError("LEGACY_ADMIN_ENFORCEMENT_MISSING")
    if enabled_rules["required_conversation_resolution"] is not True:
        raise ReleaseGovernanceError("CONVERSATION_RESOLUTION_MISSING")
    if enabled_rules["allow_force_pushes"] is not False:
        raise ReleaseGovernanceError("FORCE_PUSH_ALLOWED")
    if enabled_rules["allow_deletions"] is not False:
        raise ReleaseGovernanceError("BRANCH_DELETION_ALLOWED")
    return {
        "approvals": _int(pr["required_approving_review_count"], "LEGACY_APPROVAL_COUNT_INVALID", minimum=0),
        "stale": pr["dismiss_stale_reviews"] is True,
        "last_push": pr["require_last_push_approval"] is True,
        "codeowners": pr["require_code_owner_reviews"] is True,
        "strict": checks["strict"] is True,
        "status_checks": check_map,
        "conversation": enabled_rules["required_conversation_resolution"],
        "force_push_prevention": not enabled_rules["allow_force_pushes"],
        "deletion_prevention": not enabled_rules["allow_deletions"],
        "admin_enforced": enabled_rules["enforce_admins"],
        "bypass_actor_count": 0,
    }, status


def _review_time(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ReleaseGovernanceError("PR_REVIEW_TIME_INVALID")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReleaseGovernanceError("PR_REVIEW_TIME_INVALID") from exc
    if parsed.tzinfo is None:
        raise ReleaseGovernanceError("PR_REVIEW_TIME_INVALID")
    return parsed


def _review_digest(review: dict[str, Any]) -> str:
    return _identity({
        "review_id": review["id"], "reviewer_id": review["user_id"],
        "state": review["state"], "commit_id": review["commit_id"],
        "submitted_at": review["submitted_at"],
    })


def _evaluate_reviews(value: Any, *, author_id: int, head_sha: str, rules: list[tuple[str, tuple[str, ...]]], changed_paths: list[str], codeowner_enforced: bool) -> tuple[list[dict[str, Any]], set[str], int]:
    if not isinstance(value, list):
        raise ReleaseGovernanceError("PR_REVIEW_SNAPSHOT_INVALID")
    normalized: list[dict[str, Any]] = []
    seen_ids: set[int] = set()
    for raw in value:
        review = _expect_keys(raw, {"id", "user_id", "user_login", "state", "commit_id", "submitted_at"}, "PR_REVIEW_SNAPSHOT_INVALID")
        review_id = _int(review["id"], "PR_REVIEW_SNAPSHOT_INVALID")
        user_id = _int(review["user_id"], "PR_REVIEW_SNAPSHOT_INVALID")
        login = _string(review["user_login"], "PR_REVIEW_SNAPSHOT_INVALID").casefold()
        state = _string(review["state"], "PR_REVIEW_SNAPSHOT_INVALID").upper()
        if review_id in seen_ids or state not in {"APPROVED", "CHANGES_REQUESTED", "COMMENTED", "DISMISSED", "PENDING"}:
            raise ReleaseGovernanceError("PR_REVIEW_SNAPSHOT_INVALID")
        seen_ids.add(review_id)
        normalized.append({
            "id": review_id, "user_id": user_id, "user_login": login, "state": state,
            "commit_id": _sha(review["commit_id"], "PR_REVIEW_COMMIT_INVALID"),
            "submitted_at": review["submitted_at"], "_time": _review_time(review["submitted_at"]),
        })
    normalized.sort(key=lambda row: (row["_time"], row["id"]))
    if len({(row["_time"], row["user_id"]) for row in normalized}) != len(normalized):
        raise ReleaseGovernanceError("PR_REVIEW_ORDER_AMBIGUOUS")
    latest_by_user: dict[int, dict[str, Any]] = {}
    for row in normalized:
        latest_by_user[row["user_id"]] = row
    changes_requested = [row["_time"] for row in normalized if row["state"] == "CHANGES_REQUESTED"]
    approvals: list[dict[str, Any]] = []
    for row in normalized:
        if row["state"] != "APPROVED" or row["commit_id"] != head_sha or row["user_id"] == author_id:
            continue
        if latest_by_user[row["user_id"]] is not row:
            continue
        if any(timestamp > row["_time"] for timestamp in changes_requested):
            continue
        approvals.append(row)
    if not approvals:
        raise ReleaseGovernanceError("INDEPENDENT_REVIEW_MISSING")
    sensitive_paths = [path for path in changed_paths if _path_is_sensitive(path)]
    owner_groups: list[set[str]] = []
    for path in sensitive_paths:
        owners = _owners_for_path(rules, path)
        if not owners:
            raise ReleaseGovernanceError("CODEOWNERS_CHANGED_PATH_UNCOVERED")
        owner_groups.append({owner[1:].casefold() for owner in owners})
    unique_groups = {tuple(sorted(group)) for group in owner_groups}
    if sensitive_paths and not codeowner_enforced:
        raise ReleaseGovernanceError("CODEOWNER_REVIEW_NOT_REQUIRED")
    approved_logins = {row["user_login"] for row in approvals}
    if any(not set(group).intersection(approved_logins) for group in unique_groups):
        raise ReleaseGovernanceError("CODEOWNER_APPROVAL_MISSING")
    return approvals, approved_logins, len(unique_groups)


def _safe_pr_projection(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": value["id"], "number": value["number"], "requested_number": value["requested_number"], "state": value["state"],
        "merged": value["merged"], "merged_at": value["merged_at"],
        "merge_commit_sha": value["merge_commit_sha"],
        "author_id": value["author"]["id"], "base_sha": value["base"]["sha"],
        "base_ref": value["base"]["ref"], "base_repository_id": value["base"]["repository_id"],
        "head_sha": value["head"]["sha"], "head_ref": value["head"]["ref"],
    }


def _evaluate_check_runs(value: Any, *, head_sha: str, effective_checks: dict[str, int]) -> tuple[list[int], list[str], list[int]]:
    wrapper = _expect_keys(value, {"complete", "items"}, "CHECK_RUN_SNAPSHOT_INVALID")
    if wrapper["complete"] is not True or not isinstance(wrapper["items"], list):
        raise ReleaseGovernanceError("CHECK_RUN_SNAPSHOT_INCOMPLETE")
    runs_by_name: dict[str, list[dict[str, Any]]] = {}
    all_ids: set[int] = set()
    for raw in wrapper["items"]:
        run = _expect_keys(raw, {"id", "name", "head_sha", "status", "conclusion", "app_id", "app_slug"}, "CHECK_RUN_SNAPSHOT_INVALID")
        run_id = _int(run["id"], "CHECK_RUN_SNAPSHOT_INVALID")
        if run_id in all_ids:
            raise ReleaseGovernanceError("CHECK_RUN_ID_DUPLICATE")
        all_ids.add(run_id)
        current_sha = _sha(run["head_sha"], "CHECK_RUN_HEAD_INVALID")
        if current_sha != head_sha:
            raise ReleaseGovernanceError("CHECK_RUN_WRONG_HEAD_SHA")
        name = _string(run["name"], "CHECK_RUN_SNAPSHOT_INVALID")
        runs_by_name.setdefault(name, []).append(run)
    run_ids: list[int] = []
    identities: list[str] = []
    app_ids: list[int] = []
    authorized = GOVERNANCE_POLICY["status_checks"]["integration"]
    for context in GOVERNANCE_POLICY["status_checks"]["required_contexts"]:
        matches = runs_by_name.get(context, [])
        if len(matches) != 1:
            raise ReleaseGovernanceError("CHECK_RUN_MISSING_OR_AMBIGUOUS")
        run = matches[0]
        app_id = _int(run["app_id"], "CHECK_RUN_APP_MISSING")
        if app_id != authorized["app_id"] or run["app_slug"] != authorized["slug"] or effective_checks.get(context) != app_id:
            raise ReleaseGovernanceError("CHECK_RUN_INTEGRATION_MISMATCH")
        if run["status"] != "completed" or run["conclusion"] != "success":
            raise ReleaseGovernanceError("CHECK_RUN_NOT_SUCCESSFUL")
        run_ids.append(run["id"])
        app_ids.append(app_id)
        identities.append(_identity({
            "id": run["id"], "name": context, "head_sha": head_sha,
            "status": run["status"], "conclusion": run["conclusion"],
            "app_id": app_id, "app_slug": run["app_slug"],
        }))
    return run_ids, identities, app_ids


def _verify_policy_file(value: Any, *, subject_sha: str) -> tuple[str, str]:
    content, text, blob_sha = _snapshot_bytes(value, POLICY_PATH, subject_sha)
    try:
        policy = json.loads(text, object_pairs_hook=_unique_object)
    except (json.JSONDecodeError, _DuplicateJsonKey) as exc:
        raise ReleaseGovernanceError("CANDIDATE_POLICY_INVALID") from exc
    if policy != GOVERNANCE_POLICY:
        raise ReleaseGovernanceError("GOVERNANCE_POLICY_MISMATCH")
    return _sha256(content), blob_sha


def derive_governance_payload(
    sources: dict[str, Path], *, subject_git_sha: str, deployment_fingerprint: str,
    candidate_spec: dict[str, Any] | None,
) -> dict[str, Any]:
    """Derive a source-free governance payload from the required raw snapshots."""

    from .certification import canonical_candidate_factors, candidate_deployment_fingerprint

    if set(sources) != _ROLES or candidate_spec is None:
        raise ReleaseGovernanceError("GOVERNANCE_INPUT_ROLES_INCOMPLETE")
    snapshot = {role: _read_source(path) for role, path in sources.items()}
    subject = _sha(subject_git_sha, "GOVERNANCE_SUBJECT_INVALID")
    deployment = _sha(deployment_fingerprint, "GOVERNANCE_DEPLOYMENT_INVALID", length=64)
    candidate = canonical_candidate_factors(candidate_spec)
    if candidate.get("subject_git_sha") != subject or candidate_deployment_fingerprint(candidate_spec) != deployment:
        raise ReleaseGovernanceError("GOVERNANCE_CANDIDATE_MISMATCH")

    repo = _expect_keys(snapshot["repository_metadata"], {"id", "full_name", "default_branch"}, "REPOSITORY_SNAPSHOT_INVALID")
    repository_id = _int(repo["id"], "REPOSITORY_SNAPSHOT_INVALID")
    full_name = _string(repo["full_name"], "REPOSITORY_SNAPSHOT_INVALID")
    default_branch = _string(repo["default_branch"], "REPOSITORY_SNAPSHOT_INVALID")
    if full_name.casefold() != REPOSITORY_FULL_NAME.casefold() or default_branch != GOVERNANCE_POLICY["target"]["default_branch"]:
        raise ReleaseGovernanceError("REPOSITORY_POLICY_MISMATCH")
    branch = _expect_keys(snapshot["target_branch"], {"name", "protected", "commit_sha"}, "TARGET_BRANCH_SNAPSHOT_INVALID")
    branch_name = _string(branch["name"], "TARGET_BRANCH_SNAPSHOT_INVALID")
    branch_head_sha = _sha(branch["commit_sha"], "TARGET_BRANCH_HEAD_INVALID")
    if branch_name != RELEASE_BRANCH or branch["protected"] is not True:
        raise ReleaseGovernanceError("TARGET_BRANCH_NOT_PROTECTED")
    if branch_head_sha != subject:
        raise ReleaseGovernanceError("RELEASE_SUBJECT_NOT_CURRENT_BRANCH_HEAD")

    # The policy and ownership bytes are read from the exact merge commit via
    # GitHub's contents API and verified against their Git blob identities.
    policy_file_sha, policy_blob_sha = _verify_policy_file(snapshot["candidate_governance_policy"], subject_sha=subject)
    _ = policy_blob_sha
    owner_bytes, owner_text, owner_blob_sha = _snapshot_bytes(snapshot["candidate_codeowners"], CODEOWNERS_PATH, subject)
    owner_sha = _sha256(owner_bytes)
    owners = _parse_codeowners(owner_text)
    _verify_codeowners_coverage(owners)

    collection = snapshot["ruleset_collection"]
    details_value = snapshot["ruleset_details"]
    effective_rulesets, ruleset_requirements = _effective_rulesets(collection, details_value, repository_id)
    rule_hashes = [_identity(detail) for detail in sorted(effective_rulesets, key=lambda item: item["id"])]
    legacy, protection_status = _legacy_requirements(snapshot["legacy_branch_protection"])
    active_rulesets = bool(effective_rulesets)
    if not active_rulesets and legacy is None:
        raise ReleaseGovernanceError("NO_PROVEN_ACTIVE_BRANCH_PROTECTION")

    # Each protection mechanism that has an authoritative response is checked;
    # required facts are combined across active repository rulesets because
    # GitHub applies them conjunctively.
    requirements = {
        "approvals": ruleset_requirements["approvals"],
        "stale": ruleset_requirements["stale"],
        "last_push": ruleset_requirements["last_push"],
        "codeowners": ruleset_requirements["codeowners"],
        "strict": ruleset_requirements["strict"],
        "status_checks": dict(ruleset_requirements["status_checks"]),
        "conversation": ruleset_requirements["conversation"],
        "force_push_prevention": ruleset_requirements["force_push_prevention"],
        "deletion_prevention": ruleset_requirements["deletion_prevention"],
        "admin_enforced": True,
        "bypass_actor_count": 0,
    }
    if legacy is not None:
        for field in ("approvals", "stale", "last_push", "codeowners"):
            if field == "approvals":
                requirements[field] = max(requirements[field], legacy[field])
            else:
                requirements[field] = requirements[field] or legacy[field]
        for context, app_id in legacy["status_checks"].items():
            if context in requirements["status_checks"] and requirements["status_checks"][context] != app_id:
                raise ReleaseGovernanceError("STATUS_CHECK_BINDING_AMBIGUOUS")
            requirements["status_checks"][context] = app_id
        for field in ("strict", "conversation", "force_push_prevention", "deletion_prevention"):
            requirements[field] = requirements[field] or legacy[field]
        requirements["admin_enforced"] = legacy["admin_enforced"]
        requirements["bypass_actor_count"] += legacy["bypass_actor_count"]
    if requirements["approvals"] < GOVERNANCE_POLICY["review"]["minimum_approvals"]:
        raise ReleaseGovernanceError("APPROVING_REVIEW_REQUIREMENT_MISSING")
    for field, code in (
        ("stale", "STALE_REVIEW_INVALIDATION_MISSING"),
        ("last_push", "LAST_PUSH_APPROVAL_MISSING"),
        ("codeowners", "CODEOWNER_REVIEW_NOT_REQUIRED"),
        ("conversation", "CONVERSATION_RESOLUTION_MISSING"),
        ("force_push_prevention", "FORCE_PUSH_ALLOWED"),
        ("deletion_prevention", "BRANCH_DELETION_ALLOWED"),
        ("admin_enforced", "LEGACY_ADMIN_ENFORCEMENT_MISSING"),
    ):
        if not requirements[field]:
            raise ReleaseGovernanceError(code)
    _require_status_policy(requirements["status_checks"], strict=requirements["strict"])
    if requirements["bypass_actor_count"]:
        raise ReleaseGovernanceError("BYPASS_ACTOR_PRESENT")

    pr = _expect_keys(snapshot["pull_request"], {
        "id", "number", "requested_number", "state", "merged", "merged_at", "merge_commit_sha",
        "author", "base", "head",
    }, "PR_SNAPSHOT_INVALID")
    pr_id = _int(pr["id"], "PR_SNAPSHOT_INVALID")
    pr_number = _int(pr["number"], "PR_SNAPSHOT_INVALID")
    requested_pr_number = _int(pr["requested_number"], "PR_SNAPSHOT_INVALID")
    if requested_pr_number != pr_number:
        raise ReleaseGovernanceError("PR_ROUTE_BINDING_MISMATCH")
    author = _expect_keys(pr["author"], {"id", "login"}, "PR_AUTHOR_INVALID")
    author_id = _int(author["id"], "PR_AUTHOR_INVALID")
    _string(author["login"], "PR_AUTHOR_INVALID")
    base = _expect_keys(pr["base"], {"sha", "ref", "repository_id", "repository_full_name"}, "PR_BASE_INVALID")
    base_sha = _sha(base["sha"], "PR_BASE_INVALID")
    base_ref = _string(base["ref"], "PR_BASE_INVALID")
    if base_ref != RELEASE_BRANCH or _int(base["repository_id"], "PR_BASE_INVALID") != repository_id or base["repository_full_name"].casefold() != full_name.casefold():
        raise ReleaseGovernanceError("PR_TARGET_MISMATCH")
    head = _expect_keys(pr["head"], {"sha", "ref"}, "PR_HEAD_INVALID")
    head_sha = _sha(head["sha"], "PR_HEAD_INVALID")
    _string(head["ref"], "PR_HEAD_INVALID")
    merge_sha = _sha(pr["merge_commit_sha"], "PR_MERGE_SHA_INVALID")
    if pr["state"] != "closed" or pr["merged"] is not True or not isinstance(pr["merged_at"], str) or not pr["merged_at"] or merge_sha != subject:
        raise ReleaseGovernanceError("RELEASE_SUBJECT_NOT_FROM_MERGED_PR")
    commit = _expect_keys(snapshot["merge_commit"], {"sha", "parent_shas"}, "MERGE_COMMIT_SNAPSHOT_INVALID")
    if _sha(commit["sha"], "MERGE_COMMIT_SNAPSHOT_INVALID") != subject or not isinstance(commit["parent_shas"], list) or not commit["parent_shas"]:
        raise ReleaseGovernanceError("MERGE_COMMIT_IDENTITY_MISMATCH")
    parent_shas = [_sha(item, "MERGE_COMMIT_PARENT_INVALID") for item in commit["parent_shas"]]
    if len(parent_shas) > 2:
        raise ReleaseGovernanceError("MERGE_COMMIT_PARENT_COUNT_INVALID")

    files = _expect_keys(snapshot["pull_request_files"], {"complete", "items"}, "PR_FILES_SNAPSHOT_INVALID")
    if files["complete"] is not True or not isinstance(files["items"], list):
        raise ReleaseGovernanceError("PR_FILES_SNAPSHOT_INCOMPLETE")
    changed_paths: list[str] = []
    for raw in files["items"]:
        item = _expect_keys(raw, {"filename"}, "PR_FILES_SNAPSHOT_INVALID")
        path = _string(item["filename"], "PR_FILES_SNAPSHOT_INVALID")
        if path.startswith("/") or "\\" in path or any(part in {"", ".", ".."} for part in path.split("/")):
            raise ReleaseGovernanceError("PR_FILE_PATH_INVALID")
        changed_paths.append(path)
    if len(set(changed_paths)) != len(changed_paths):
        raise ReleaseGovernanceError("PR_FILES_DUPLICATE")
    changed_paths.sort()
    sensitive_paths = [path for path in changed_paths if _path_is_sensitive(path)]
    approvals, approving_logins, group_count = _evaluate_reviews(
        snapshot["pull_request_reviews"], author_id=author_id, head_sha=head_sha,
        rules=owners, changed_paths=changed_paths, codeowner_enforced=requirements["codeowners"],
    )
    independent_approvals = {row["user_id"] for row in approvals}
    if len(independent_approvals) < GOVERNANCE_POLICY["review"]["minimum_approvals"]:
        raise ReleaseGovernanceError("INDEPENDENT_REVIEW_MISSING")
    codeowner_approval_count = sum(
        1 for group in {
            tuple(sorted(_owners_for_path(owners, path))) for path in sensitive_paths
        } if {owner[1:].casefold() for owner in group}.intersection(approving_logins)
    )
    if sensitive_paths and codeowner_approval_count != group_count:
        raise ReleaseGovernanceError("CODEOWNER_APPROVAL_MISSING")

    run_ids, check_identities, app_ids = _evaluate_check_runs(
        snapshot["pull_request_check_runs"], head_sha=head_sha,
        effective_checks=requirements["status_checks"],
    )
    repo_identity = _identity({"id": repository_id, "full_name": full_name.casefold()})
    review_identities = sorted({_review_digest(row) for row in approvals})
    ruleset_ids = sorted(detail["id"] for detail in effective_rulesets)
    legacy_sha = _identity(snapshot["legacy_branch_protection"]) if protection_status == 200 else None
    mechanisms = int(active_rulesets) + int(legacy is not None)
    mechanism_name = "combined" if mechanisms == 2 else "repository_rulesets" if active_rulesets else "legacy_branch_protection"
    effective_protection = {
        "active_ruleset_ids": ruleset_ids,
        "ruleset_identity_sha256s": rule_hashes,
        "legacy_protection_sha256": legacy_sha,
        "review": {key: requirements[key] for key in ("approvals", "stale", "last_push", "codeowners")},
        "status_checks": requirements["status_checks"],
        "strict": requirements["strict"],
        "conversation": requirements["conversation"],
        "force_push_prevention": requirements["force_push_prevention"],
        "deletion_prevention": requirements["deletion_prevention"],
        "admin_enforced": requirements["admin_enforced"],
        "bypass_actor_count": requirements["bypass_actor_count"],
    }
    candidate_identity = _identity(candidate)
    payload = {
        "schema_version": "1.0",
        "governance_contract_version": GOVERNANCE_CONTRACT_VERSION,
        "governance_contract_identity": GOVERNANCE_CONTRACT_IDENTITY,
        "governance_policy_id": GOVERNANCE_POLICY_ID,
        "governance_policy_version": GOVERNANCE_POLICY_VERSION,
        "governance_policy_identity": GOVERNANCE_POLICY_IDENTITY,
        "governance_policy_file_sha256": policy_file_sha,
        "repository_full_name": full_name,
        "repository_id": repository_id,
        "repository_identity_sha256": repo_identity,
        "default_branch": default_branch,
        "release_branch": branch_name,
        "branch_head_sha": branch_head_sha,
        "release_subject_sha": subject,
        "pull_request_number": pr_number,
        "pull_request_identity_sha256": _identity({"id": pr_id, **_safe_pr_projection(pr)}),
        "pull_request_author_identity_sha256": _identity({"repository_id": repository_id, "user_id": author_id}),
        "independent_reviewer_identities": sorted({
            _identity({"repository_id": repository_id, "user_id": row["user_id"]}) for row in approvals
        }),
        "pull_request_head_sha": head_sha,
        "pull_request_base_sha": base_sha,
        "pull_request_merge_commit_sha": merge_sha,
        "candidate_deployment_fingerprint": deployment,
        "candidate_spec_identity_sha256": candidate_identity,
        "protection_mechanism": mechanism_name,
        "protection_detail_http_status": protection_status,
        "active_ruleset_ids": ruleset_ids,
        "ruleset_identity_sha256s": rule_hashes,
        "legacy_protection_sha256": legacy_sha,
        "effective_protection_sha256": _identity(effective_protection),
        "required_approving_reviews": requirements["approvals"],
        "review_count": len(snapshot["pull_request_reviews"]),
        "independent_approval_count": len(independent_approvals),
        "approving_review_identities": review_identities,
        "review_pass": True,
        "codeowners_sha256": owner_sha,
        "codeowners_git_blob_sha": owner_blob_sha,
        "changed_file_count": len(changed_paths),
        "production_sensitive_change_count": len(sensitive_paths),
        "changed_file_set_sha256": _identity(changed_paths),
        "codeowner_group_count": group_count,
        "codeowner_approval_group_count": codeowner_approval_count,
        "codeowners_pass": True,
        "status_check_contexts": list(GOVERNANCE_POLICY["status_checks"]["required_contexts"]),
        "required_check_run_ids": run_ids,
        "required_check_identities": check_identities,
        "required_check_app_ids": app_ids,
        "required_check_pass": True,
        "required_status_checks_strict": True,
        "stale_review_dismissal_required": True,
        "last_push_approval_required": True,
        "code_owner_enforcement_required": True,
        "conversation_resolution_required": True,
        "force_push_prevention_required": True,
        "branch_deletion_prevention_required": True,
        "admin_enforcement_required": requirements["admin_enforced"],
        "pr_only_integration_required": True,
        "bypass_actor_count": requirements["bypass_actor_count"],
        "pass_codes": list(_PASS_CODES),
    }
    validate_governance_payload(payload)
    return payload


def validate_governance_payload(payload: dict[str, Any]) -> None:
    """Check the closed source-free payload contract used by load_evidence."""

    if not isinstance(payload, dict) or set(payload) != _PAYLOAD_KEYS:
        raise ReleaseGovernanceError("GOVERNANCE_PAYLOAD_NOT_CLOSED")
    if payload["schema_version"] != "1.0" or payload["governance_contract_version"] != GOVERNANCE_CONTRACT_VERSION:
        raise ReleaseGovernanceError("GOVERNANCE_CONTRACT_VERSION_UNSUPPORTED")
    if payload["governance_contract_identity"] != GOVERNANCE_CONTRACT_IDENTITY:
        raise ReleaseGovernanceError("GOVERNANCE_CONTRACT_IDENTITY_MISMATCH")
    if payload["governance_policy_id"] != GOVERNANCE_POLICY_ID or payload["governance_policy_version"] != GOVERNANCE_POLICY_VERSION or payload["governance_policy_identity"] != GOVERNANCE_POLICY_IDENTITY:
        raise ReleaseGovernanceError("GOVERNANCE_POLICY_IDENTITY_MISMATCH")
    if payload["repository_full_name"].casefold() != REPOSITORY_FULL_NAME.casefold() or payload["default_branch"] != RELEASE_BRANCH or payload["release_branch"] != RELEASE_BRANCH:
        raise ReleaseGovernanceError("GOVERNANCE_REPOSITORY_BINDING_MISMATCH")
    for field in (
        "governance_policy_file_sha256", "repository_identity_sha256",
        "pull_request_identity_sha256", "pull_request_author_identity_sha256", "candidate_deployment_fingerprint",
        "candidate_spec_identity_sha256", "effective_protection_sha256", "codeowners_sha256",
        "changed_file_set_sha256",
    ):
        _sha(payload[field], "GOVERNANCE_PAYLOAD_IDENTITY_INVALID", length=64)
    for field in ("branch_head_sha", "release_subject_sha", "pull_request_head_sha", "pull_request_base_sha", "pull_request_merge_commit_sha", "codeowners_git_blob_sha"):
        _sha(payload[field], "GOVERNANCE_PAYLOAD_IDENTITY_INVALID")
    if payload["release_subject_sha"] != payload["pull_request_merge_commit_sha"]:
        raise ReleaseGovernanceError("GOVERNANCE_SUBJECT_BINDING_MISMATCH")
    if payload["protection_mechanism"] not in {"repository_rulesets", "legacy_branch_protection", "combined"}:
        raise ReleaseGovernanceError("GOVERNANCE_PROTECTION_MECHANISM_INVALID")
    if payload["protection_detail_http_status"] not in {200, 401, 403, 404}:
        raise ReleaseGovernanceError("GOVERNANCE_PROTECTION_STATUS_INVALID")
    for field in (
        "review_pass", "codeowners_pass", "required_check_pass", "required_status_checks_strict",
        "stale_review_dismissal_required", "last_push_approval_required", "code_owner_enforcement_required",
        "conversation_resolution_required", "force_push_prevention_required",
        "branch_deletion_prevention_required", "admin_enforcement_required",
        "pr_only_integration_required",
    ):
        if payload[field] is not True:
            raise ReleaseGovernanceError("GOVERNANCE_PASS_FACT_INVALID")
    if payload["bypass_actor_count"] != 0 or payload["pass_codes"] != _PASS_CODES:
        raise ReleaseGovernanceError("GOVERNANCE_OUTCOME_INVALID")
    if payload["status_check_contexts"] != GOVERNANCE_POLICY["status_checks"]["required_contexts"]:
        raise ReleaseGovernanceError("GOVERNANCE_STATUS_POLICY_MISMATCH")
    if not isinstance(payload["active_ruleset_ids"], list) or not isinstance(payload["ruleset_identity_sha256s"], list):
        raise ReleaseGovernanceError("GOVERNANCE_PROTECTION_IDENTITY_INVALID")
    for value in payload["ruleset_identity_sha256s"]:
        _sha(value, "GOVERNANCE_PROTECTION_IDENTITY_INVALID", length=64)
    if payload["legacy_protection_sha256"] is not None:
        _sha(payload["legacy_protection_sha256"], "GOVERNANCE_PROTECTION_IDENTITY_INVALID", length=64)
    checks = GOVERNANCE_POLICY["status_checks"]["required_contexts"]
    if len(payload["required_check_run_ids"]) != len(checks) or len(payload["required_check_identities"]) != len(checks) or len(payload["required_check_app_ids"]) != len(checks):
        raise ReleaseGovernanceError("GOVERNANCE_CHECK_IDENTITY_INVALID")
    for run_id in payload["required_check_run_ids"]:
        _int(run_id, "GOVERNANCE_CHECK_IDENTITY_INVALID")
    for identity in payload["required_check_identities"]:
        _sha(identity, "GOVERNANCE_CHECK_IDENTITY_INVALID", length=64)
    if payload["required_check_app_ids"] != [GOVERNANCE_POLICY["status_checks"]["integration"]["app_id"]] * len(checks):
        raise ReleaseGovernanceError("GOVERNANCE_CHECK_INTEGRATION_MISMATCH")
    for field in ("repository_id", "pull_request_number", "required_approving_reviews", "review_count", "independent_approval_count", "changed_file_count", "production_sensitive_change_count", "codeowner_group_count", "codeowner_approval_group_count"):
        minimum = 0 if field in {"review_count", "production_sensitive_change_count", "codeowner_group_count", "codeowner_approval_group_count"} else 1
        _int(payload[field], "GOVERNANCE_PAYLOAD_COUNT_INVALID", minimum=minimum)
    if payload["independent_approval_count"] < 1 or payload["review_count"] < payload["independent_approval_count"]:
        raise ReleaseGovernanceError("GOVERNANCE_REVIEW_COUNT_INVALID")
    if payload["production_sensitive_change_count"] and payload["codeowner_approval_group_count"] != payload["codeowner_group_count"]:
        raise ReleaseGovernanceError("GOVERNANCE_CODEOWNER_COUNT_INVALID")
    if not isinstance(payload["approving_review_identities"], list) or not payload["approving_review_identities"]:
        raise ReleaseGovernanceError("GOVERNANCE_REVIEW_IDENTITY_INVALID")
    if len(payload["approving_review_identities"]) != payload["independent_approval_count"]:
        raise ReleaseGovernanceError("GOVERNANCE_REVIEW_IDENTITY_INVALID")
    for identity in payload["approving_review_identities"]:
        _sha(identity, "GOVERNANCE_REVIEW_IDENTITY_INVALID", length=64)
    if not isinstance(payload["independent_reviewer_identities"], list) or not payload["independent_reviewer_identities"]:
        raise ReleaseGovernanceError("GOVERNANCE_REVIEW_IDENTITY_INVALID")
    for identity in payload["independent_reviewer_identities"]:
        _sha(identity, "GOVERNANCE_REVIEW_IDENTITY_INVALID", length=64)
    if len(set(payload["independent_reviewer_identities"])) != payload["independent_approval_count"]:
        raise ReleaseGovernanceError("GOVERNANCE_REVIEW_IDENTITY_INVALID")
