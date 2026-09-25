from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from evals.capture_governance import (
    CaptureError,
    _pull_projection,
    capture_head_commit_pull_requests,
    capture_workflow_run_provenance,
)
from evals.release import _load_records, derive_release_state
from k_slide.certification import (
    EVIDENCE_SCHEMA_VERSION,
    EvidenceValidationError,
    candidate_deployment_fingerprint,
    load_evidence,
)
from k_slide.evidence_adapters import ADAPTER_VERSION, AdapterError, build_machine_evidence
from k_slide.model_policy import load_model_policy
from k_slide.recertification import build_recertification_record, candidate_change_impact
from k_slide.release_governance import (
    GOVERNANCE_CONTRACT_IDENTITY,
    GOVERNANCE_POLICY,
    GOVERNANCE_POLICY_IDENTITY,
    POLICY_PATH,
    validate_governance_payload,
)
from tests.ksa32_governance_fixtures import (
    AUTHOR_ID,
    BASE_SHA,
    HEAD_SHA,
    OWNER_ID,
    PULL_NUMBER,
    REPOSITORY_ID,
    REPOSITORY_FULL_NAME,
    SUBJECT,
    github_governance_snapshot,
    replace_snapshot_source,
    write_governance_sources,
)
from tests.test_certification_closure import _candidate_spec


class KSA32ReleaseGovernanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.subject = SUBJECT
        self.candidate = _candidate_spec(self.subject)
        self.deployment = candidate_deployment_fingerprint(self.candidate)
        self.case_number = 0

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _folder(self) -> Path:
        self.case_number += 1
        folder = self.root / f"case-{self.case_number}"
        folder.mkdir()
        return folder

    def _sources(self, *, protection: str = "ruleset", snapshot: dict | None = None, **kwargs):
        return write_governance_sources(self._folder() / "snapshots", snapshot=snapshot, protection=protection, **kwargs)

    def _build(self, sources: dict[str, Path], *, candidate: dict | None = None, subject: str | None = None, deployment: str | None = None) -> Path:
        folder = sources["repository_metadata"].parent.parent
        path = folder / "evidence.json"
        selected_candidate = candidate or self.candidate
        build_machine_evidence(
            path,
            evidence_type="governance",
            subject_git_sha=subject or self.subject,
            deployment_fingerprint=deployment or candidate_deployment_fingerprint(selected_candidate),
            sources=sources,
            candidate_spec=selected_candidate,
            generated_at="2026-09-24T00:00:00Z",
        )
        return path

    def _reject_snapshot(self, snapshot: dict, code: str | None = None) -> None:
        sources = self._sources(snapshot=snapshot)
        with self.assertRaises(AdapterError) as caught:
            self._build(sources)
        if code:
            self.assertIn(code, str(caught.exception))

    def _pr_job(self, snapshot: dict, context: str) -> tuple[dict, dict, dict]:
        authorized = next(item for item in GOVERNANCE_POLICY["status_checks"]["authorized_workflows"] if item["context"] == context)
        for run in snapshot["workflow_run_provenance"]["items"]:
            if run["event"] != "pull_request" or run["workflow_path"] != authorized["workflow_path"]:
                continue
            for job in run["jobs"]:
                if job["name"] == context:
                    check = next(item for item in snapshot["pull_request_check_runs"]["items"] if item["id"] == job["check_run_id"])
                    return run, job, check
        raise AssertionError(f"no PR job for required context {context}")

    def _update_pr_check(self, snapshot: dict, context: str, **changes) -> tuple[dict, dict, dict]:
        run, job, check = self._pr_job(snapshot, context)
        for key, value in changes.items():
            if key == "name":
                job["name"] = value
                job["check_name"] = value
                check["name"] = value
            else:
                job[key] = value
                check[key] = value
        return run, job, check

    def _load(self, path: Path, *, candidate: dict | None = None, subject: str | None = None, deployment: str | None = None):
        chosen = candidate or self.candidate
        return load_evidence(
            path,
            expected_type="governance",
            subject_git_sha=subject or self.subject,
            deployment_fingerprint=deployment or candidate_deployment_fingerprint(chosen),
            candidate_spec=chosen,
            require_candidate_spec=True,
        )

    def test_valid_ruleset_evidence_rederives_and_is_source_free(self):
        sources = self._sources()
        path = self._build(sources)
        loaded = self._load(path)
        payload = loaded["payload"]
        self.assertEqual(payload["governance_policy_identity"], GOVERNANCE_POLICY_IDENTITY)
        self.assertEqual(payload["governance_contract_identity"], GOVERNANCE_CONTRACT_IDENTITY)
        self.assertEqual(payload["governance_contract_version"], "1.2")
        self.assertEqual(payload["governance_policy_version"], "1.1")
        self.assertEqual(EVIDENCE_SCHEMA_VERSION, "2.6")
        self.assertEqual(payload["protection_mechanism"], "repository_rulesets")
        self.assertEqual(payload["status_check_contexts"], GOVERNANCE_POLICY["status_checks"]["required_contexts"])
        self.assertEqual(payload["active_ruleset_ids"], [441])
        self.assertEqual(payload["review_count"], 1)
        self.assertNotIn("user_login", payload)
        self.assertNotIn("comment", json.dumps(payload).casefold())
        self.assertEqual(len(loaded["sources"]), 14)
        self.assertRegex(payload["head_commit_pull_requests_identity_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(payload["required_check_workflow_paths"], [
            item["workflow_path"] for item in GOVERNANCE_POLICY["status_checks"]["authorized_workflows"]
        ])
        self.assertEqual(payload["required_check_workflow_run_ids"][0], payload["required_check_workflow_run_ids"][1])
        self.assertEqual(payload["required_check_workflow_run_ids"][3], payload["required_check_workflow_run_ids"][4])
        serialized = json.dumps(payload).casefold()
        self.assertNotIn("https://", serialized)
        self.assertNotIn("logs", serialized)
        self.assertNotIn('"event"', serialized)

    def test_valid_legacy_branch_protection_equivalent_succeeds(self):
        path = self._build(self._sources(protection="legacy"))
        payload = self._load(path)["payload"]
        self.assertEqual(payload["protection_mechanism"], "legacy_branch_protection")
        self.assertEqual(payload["protection_detail_http_status"], 200)
        self.assertTrue(payload["admin_enforcement_required"])

    def test_valid_ruleset_and_legacy_protections_are_combined(self):
        path = self._build(self._sources(protection="combined"))
        self.assertEqual(self._load(path)["payload"]["protection_mechanism"], "combined")

    def test_unprotected_branch_empty_rulesets_and_unavailable_detail_fail(self):
        snapshot = github_governance_snapshot()
        snapshot["target_branch"]["protected"] = False
        snapshot["ruleset_collection"]["items"] = []
        snapshot["ruleset_details"] = []
        self._reject_snapshot(snapshot, "TARGET_BRANCH_NOT_PROTECTED")

    def test_403_protection_detail_without_sufficient_ruleset_fails(self):
        snapshot = github_governance_snapshot(protection="legacy")
        snapshot["legacy_branch_protection"] = {"http_status": 403, "body": None}
        self._reject_snapshot(snapshot, "NO_PROVEN_ACTIVE_BRANCH_PROTECTION")

    def test_duplicate_json_keys_in_raw_governance_snapshot_fail_closed(self):
        sources = self._sources()
        sources["repository_metadata"].write_text(
            '{"id":81234567,"id":81234567,"full_name":"kimhw8084/k-slide","default_branch":"main"}\n',
            encoding="utf-8",
        )
        with self.assertRaises(AdapterError) as caught:
            self._build(sources)
        self.assertIn("GOVERNANCE_SOURCE_MALFORMED", str(caught.exception))

    def test_ambiguous_ruleset_provenance_or_scope_fails_closed(self):
        snapshot = github_governance_snapshot()
        snapshot["ruleset_details"][0]["source"] = None
        self._reject_snapshot(snapshot, "RULESET_REPOSITORY_MISMATCH")
        snapshot = github_governance_snapshot()
        snapshot["ruleset_details"][0]["conditions"]["repository_name"] = {
            "include": ["kimhw8084/k-slide"], "exclude": [],
        }
        self._reject_snapshot(snapshot, "RULESET_CONDITIONS_AMBIGUOUS")

    def test_aggregate_boolean_legacy_input_fails_at_adapter_and_loader(self):
        folder = self._folder()
        source = folder / "governance.json"
        source.write_text(json.dumps({
            "source_kind": "github_api", "codeowners_pass": True,
            "branch_protection_pass": True, "required_ci_pass": True,
            "review_required": True,
        }) + "\n", encoding="utf-8")
        with self.assertRaises(AdapterError):
            build_machine_evidence(
                folder / "evidence.json", evidence_type="governance", subject_git_sha=self.subject,
                deployment_fingerprint=self.deployment, sources={"governance_api": source},
            )
        factors = __import__("k_slide.certification", fromlist=["canonical_candidate_factors"]).canonical_candidate_factors(self.candidate)
        envelope = {
            "schema_version": EVIDENCE_SCHEMA_VERSION, "evidence_type": "governance", "status": "PASS",
            "subject_git_sha": self.subject, "deployment_fingerprint": self.deployment,
            "generated_at": "2026-09-24T00:00:00Z", "adapter_version": ADAPTER_VERSION,
            "sources": [{"role": "governance_api", "path": "governance.json", "sha256": hashlib.sha256(source.read_bytes()).hexdigest()}],
            "payload": {"source_kind": "github_api", "codeowners_pass": True, "branch_protection_pass": True, "required_ci_pass": True, "review_required": True},
            "candidate_spec": factors,
        }
        legacy_path = folder / "legacy-envelope.json"
        legacy_path.write_text(json.dumps(envelope) + "\n", encoding="utf-8")
        with self.assertRaises(EvidenceValidationError):
            self._load(legacy_path)

    def test_ruleset_evaluate_only_and_wrong_target_do_not_qualify(self):
        for enforcement, refs in (("evaluate", ["refs/heads/main"]), ("active", ["refs/heads/release"])):
            snapshot = github_governance_snapshot()
            snapshot["ruleset_collection"]["items"][0]["enforcement"] = enforcement
            detail = snapshot["ruleset_details"][0]
            detail["enforcement"] = enforcement
            detail["conditions"]["ref_name"]["include"] = refs
            self._reject_snapshot(snapshot, "NO_PROVEN_ACTIVE_BRANCH_PROTECTION")

    def test_active_applicable_ruleset_without_approvals_fails(self):
        snapshot = github_governance_snapshot()
        next(rule for rule in snapshot["ruleset_details"][0]["rules"] if rule["type"] == "pull_request")["parameters"]["required_approving_review_count"] = 0
        self._reject_snapshot(snapshot, "APPROVING_REVIEW_REQUIREMENT_MISSING")

    def test_zero_reviews_fails(self):
        snapshot = github_governance_snapshot()
        snapshot["pull_request_reviews"] = []
        self._reject_snapshot(snapshot, "INDEPENDENT_REVIEW_MISSING")

    def test_self_review_and_stale_head_approval_fail(self):
        snapshot = github_governance_snapshot()
        snapshot["pull_request"]["author"] = {"id": OWNER_ID, "login": "kimhw8084"}
        self._reject_snapshot(snapshot, "INDEPENDENT_REVIEW_MISSING")
        snapshot = github_governance_snapshot()
        snapshot["pull_request_reviews"][0]["commit_id"] = "d" * 40
        self._reject_snapshot(snapshot, "INDEPENDENT_REVIEW_MISSING")

    def test_later_dismissal_or_changes_requested_invalidates_approval(self):
        for state in ("DISMISSED", "CHANGES_REQUESTED"):
            snapshot = github_governance_snapshot()
            snapshot["pull_request_reviews"].append({
                "id": 7002, "user_id": OWNER_ID, "user_login": "kimhw8084", "state": state,
                "commit_id": HEAD_SHA, "submitted_at": "2026-09-24T12:01:00Z",
            })
            self._reject_snapshot(snapshot, "INDEPENDENT_REVIEW_MISSING")

    def test_missing_code_owner_enforcement_and_incomplete_coverage_fail(self):
        snapshot = github_governance_snapshot()
        next(rule for rule in snapshot["ruleset_details"][0]["rules"] if rule["type"] == "pull_request")["parameters"]["require_code_owner_review"] = False
        self._reject_snapshot(snapshot, "CODEOWNER_REVIEW_NOT_REQUIRED")
        snapshot = github_governance_snapshot(codeowners_text=(
            "/AGENTS.md @kimhw8084\n/src/ @kimhw8084\n/.opencode/ @kimhw8084\n"
            "/schemas/ @kimhw8084\n/evals/ @kimhw8084\n/termbase/ @kimhw8084\n"
            "/security/ @kimhw8084\n/deploy/ @kimhw8084\n/.github/workflows/ @kimhw8084\n"
            "/.github/CODEOWNERS @kimhw8084\n/constraints-production.txt @kimhw8084\n"
            "/pyproject.toml @kimhw8084\n/scripts/ @kimhw8084\n/private-evals/ @kimhw8084\n"
        ))
        self._reject_snapshot(snapshot, "CODEOWNERS_POLICY_PATH_UNCOVERED")

    def test_single_owner_author_owned_sensitive_change_cannot_qualify(self):
        snapshot = github_governance_snapshot()
        snapshot["pull_request"]["author"] = {"id": OWNER_ID, "login": "kimhw8084"}
        self._reject_snapshot(snapshot, "INDEPENDENT_REVIEW_MISSING")

    def test_required_check_rule_policy_mismatch_fails(self):
        snapshot = github_governance_snapshot()
        params = next(rule for rule in snapshot["ruleset_details"][0]["rules"] if rule["type"] == "required_status_checks")["parameters"]
        params["required_status_checks"].pop()
        self._reject_snapshot(snapshot, "STATUS_CHECK_POLICY_MISMATCH")
        snapshot = github_governance_snapshot()
        params = next(rule for rule in snapshot["ruleset_details"][0]["rules"] if rule["type"] == "required_status_checks")["parameters"]
        params["required_status_checks"].append(copy.deepcopy(params["required_status_checks"][0]))
        self._reject_snapshot(snapshot, "STATUS_CHECK_CONTEXT_DUPLICATE")

    def test_missing_failed_pending_and_wrong_sha_required_checks_fail(self):
        snapshot = github_governance_snapshot()
        run, job, check = self._pr_job(snapshot, "test (3.11)")
        run["jobs"].remove(job)
        snapshot["pull_request_check_runs"]["items"].remove(check)
        self._reject_snapshot(snapshot, "CHECK_RUN_MISSING_OR_AMBIGUOUS")
        for changes in (
            {"conclusion": "failure"},
            {"status": "in_progress", "conclusion": None},
            {"head_sha": "d" * 40},
        ):
            snapshot = github_governance_snapshot()
            self._update_pr_check(snapshot, "test (3.11)", **changes)
            self._reject_snapshot(snapshot)

    def test_same_named_required_check_from_wrong_app_fails(self):
        snapshot = github_governance_snapshot()
        self._update_pr_check(snapshot, "test (3.11)", app_id=123, app_slug="untrusted-app")
        self._reject_snapshot(snapshot, "CHECK_RUN_INTEGRATION_MISMATCH")

    def test_pr31_event_checks_are_selected_while_same_head_push_duplicates_are_ignored(self):
        snapshot = github_governance_snapshot()
        payload = self._load(self._build(self._sources(snapshot=snapshot)))["payload"]
        for index, context in enumerate(GOVERNANCE_POLICY["status_checks"]["required_contexts"]):
            run, job, check = self._pr_job(snapshot, context)
            self.assertEqual(payload["required_check_workflow_run_ids"][index], run["run_id"])
            self.assertEqual(payload["required_check_run_ids"][index], check["id"])
            self.assertEqual(job["run_attempt"], payload["required_check_run_attempts"][index])
        push_runs = [item for item in snapshot["workflow_run_provenance"]["items"] if item["event"] == "push"]
        self.assertEqual(len(push_runs), 2)
        self.assertTrue(all(item["head_sha"] == HEAD_SHA for item in push_runs))

    def test_push_only_required_jobs_do_not_qualify(self):
        snapshot = github_governance_snapshot()
        for run in snapshot["workflow_run_provenance"]["items"]:
            if run["event"] == "pull_request":
                run["event"] = "push"
                run["pull_requests"] = []
        self._reject_snapshot(snapshot, "CHECK_RUN_MISSING_OR_AMBIGUOUS")

    def test_wrong_pr_association_and_workflow_identity_fail(self):
        snapshot = github_governance_snapshot()
        run, _job, _check = self._pr_job(snapshot, "test (3.11)")
        run["pull_requests"] = [{"number": 99, "head_sha": HEAD_SHA}]
        self._reject_snapshot(snapshot, "WORKFLOW_RUN_PR_ASSOCIATION_CONTRADICTION")

        snapshot = github_governance_snapshot()
        run, _job, _check = self._pr_job(snapshot, "test (3.11)")
        run["pull_requests"] = [{"number": PULL_NUMBER, "head_sha": "d" * 40}]
        self._reject_snapshot(snapshot, "WORKFLOW_RUN_PR_HEAD_MISMATCH")

        snapshot = github_governance_snapshot()
        run, _job, _check = self._pr_job(snapshot, "test (3.11)")
        run["workflow_path"] = ".github/workflows/k-slide-security.yml"
        self._reject_snapshot(snapshot, "WORKFLOW_RUN_WORKFLOW_IDENTITY_MISMATCH")

        snapshot = github_governance_snapshot()
        run, _job, _check = self._pr_job(snapshot, "test (3.11)")
        run["workflow_id"] = next(
            item["id"] for item in snapshot["workflow_run_provenance"]["workflow_catalog"]["items"]
            if item["path"] == ".github/workflows/k-slide-security.yml"
        )
        self._reject_snapshot(snapshot, "WORKFLOW_RUN_WORKFLOW_IDENTITY_MISMATCH")

        snapshot = github_governance_snapshot()
        run, _job, _check = self._pr_job(snapshot, "test (3.11)")
        phase_workflow = next(
            item for item in snapshot["workflow_run_provenance"]["workflow_catalog"]["items"]
            if item["path"] == ".github/workflows/k-slide-phase32.yml"
        )
        run["workflow_id"] = phase_workflow["id"]
        run["workflow_path"] = phase_workflow["path"]
        run["workflow_name"] = phase_workflow["name"]
        self._reject_snapshot(snapshot, "WORKFLOW_RUN_NOT_AUTHORIZED_FOR_REQUIRED_CHECK")

        snapshot = github_governance_snapshot()
        run, _job, _check = self._pr_job(snapshot, "test (3.11)")
        run["event"] = "workflow_dispatch"
        self._reject_snapshot(snapshot, "WORKFLOW_RUN_EVENT_INVALID_FOR_REQUIRED_CHECK")

    def test_workflow_provenance_is_bound_to_candidate_subject_pr_and_head(self):
        for field, value in (
            ("subject_sha", "d" * 40),
            ("pull_request_number", 99),
            ("pull_request_head_sha", "d" * 40),
        ):
            snapshot = github_governance_snapshot()
            snapshot["workflow_run_provenance"][field] = value
            self._reject_snapshot(snapshot, "WORKFLOW_RUN_CANDIDATE_BINDING_MISMATCH")

    def test_pr31_empty_workflow_associations_qualify_only_with_global_commit_association(self):
        snapshot = github_governance_snapshot()
        self.assertTrue(all(
            run["pull_requests"] == []
            for run in snapshot["workflow_run_provenance"]["items"]
            if run["event"] == "pull_request"
        ))
        payload = self._load(self._build(self._sources(snapshot=snapshot)))["payload"]
        self.assertEqual(payload["pull_request_number"], PULL_NUMBER)
        self.assertEqual(payload["pull_request_head_sha"], HEAD_SHA)

        missing = github_governance_snapshot()
        missing["head_commit_pull_requests"]["items"] = []
        self._reject_snapshot(missing, "HEAD_COMMIT_PULL_REQUESTS_REQUESTED_PR_MISSING_OR_AMBIGUOUS")

    def test_commit_pull_association_must_be_unique_and_match_exact_pr_facts(self):
        mutations = (
            ("head_sha", "d" * 40),
            ("base_ref", "develop"),
            ("base_repository_id", REPOSITORY_ID + 1),
            ("base_repository_full_name", "other/repository"),
            ("head_repository_id", REPOSITORY_ID + 1),
            ("head_repository_full_name", "other/fork"),
        )
        for field, value in mutations:
            snapshot = github_governance_snapshot()
            snapshot["head_commit_pull_requests"]["items"][0][field] = value
            with self.subTest(field=field):
                self._reject_snapshot(snapshot, "HEAD_COMMIT_PULL_REQUESTS_REQUESTED_PR_MISMATCH")

        snapshot = github_governance_snapshot()
        snapshot["head_commit_pull_requests"]["repository_id"] += 1
        self._reject_snapshot(snapshot, "HEAD_COMMIT_PULL_REQUESTS_BINDING_MISMATCH")

        snapshot = github_governance_snapshot()
        snapshot["head_commit_pull_requests"]["repository_full_name"] = "other/repository"
        self._reject_snapshot(snapshot, "HEAD_COMMIT_PULL_REQUESTS_BINDING_MISMATCH")

        snapshot = github_governance_snapshot()
        snapshot["head_commit_pull_requests"]["head_sha"] = "d" * 40
        self._reject_snapshot(snapshot, "HEAD_COMMIT_PULL_REQUESTS_BINDING_MISMATCH")

        snapshot = github_governance_snapshot()
        snapshot["head_commit_pull_requests"]["items"].append(copy.deepcopy(snapshot["head_commit_pull_requests"]["items"][0]))
        self._reject_snapshot(snapshot, "HEAD_COMMIT_PULL_REQUESTS_REQUESTED_PR_MISSING_OR_AMBIGUOUS")

    def test_other_commit_pull_associations_do_not_make_exact_pr_ambiguous(self):
        snapshot = github_governance_snapshot()
        snapshot["head_commit_pull_requests"]["items"].append({
            "id": 88002,
            "number": 17,
            "base_repository_id": REPOSITORY_ID,
            "base_repository_full_name": REPOSITORY_FULL_NAME,
            "base_ref": "main",
            "head_sha": HEAD_SHA,
            "head_ref": "historical-branch",
            "head_repository_id": 998877,
            "head_repository_full_name": "contributor/k-slide",
        })
        self.assertTrue(self._load(self._build(self._sources(snapshot=snapshot)))["payload"]["required_check_pass"])

    def test_latest_attempt_qualifies_older_superseded_attempt_does_not(self):
        snapshot = github_governance_snapshot()
        run, current, check = self._pr_job(snapshot, "test (3.11)")
        run["run_attempt"] = 2
        for job in run["jobs"]:
            job["run_attempt"] = 2
        stale = copy.deepcopy(current)
        stale.update({"job_id": 9999, "check_run_id": 9999, "run_attempt": 1})
        stale_check = copy.deepcopy(check)
        stale_check["id"] = 9999
        run["jobs"].append(stale)
        snapshot["pull_request_check_runs"]["items"].append(stale_check)
        payload = self._load(self._build(self._sources(snapshot=snapshot)))["payload"]
        index = GOVERNANCE_POLICY["status_checks"]["required_contexts"].index("test (3.11)")
        self.assertEqual(payload["required_check_run_attempts"][index], 2)
        self.assertNotEqual(payload["required_check_run_ids"][index], 9999)

        run["jobs"].remove(current)
        snapshot["pull_request_check_runs"]["items"].remove(check)
        self._reject_snapshot(snapshot, "CHECK_RUN_MISSING_OR_AMBIGUOUS")

    def test_two_current_eligible_pr_jobs_for_one_context_fail_closed(self):
        snapshot = github_governance_snapshot()
        source_run, source_job, source_check = self._pr_job(snapshot, "test (3.11)")
        duplicate = copy.deepcopy(source_run)
        duplicate["run_id"] = 99001
        duplicate["jobs"] = [copy.deepcopy(source_job)]
        duplicate["jobs"][0].update({"workflow_run_id": 99001, "job_id": 99002, "check_run_id": 99002})
        duplicate["jobs"][0]["run_attempt"] = 1
        duplicate_check = copy.deepcopy(source_check)
        duplicate_check["id"] = 99002
        snapshot["workflow_run_provenance"]["items"].append(duplicate)
        snapshot["pull_request_check_runs"]["items"].append(duplicate_check)
        self._reject_snapshot(snapshot, "CHECK_RUN_MISSING_OR_AMBIGUOUS")

    def test_legacy_non_strict_checks_and_missing_stale_or_last_push_rule_fail(self):
        snapshot = github_governance_snapshot(protection="legacy")
        snapshot["legacy_branch_protection"]["body"]["required_status_checks"]["strict"] = False
        self._reject_snapshot(snapshot, "STATUS_CHECKS_NOT_STRICT")
        for key, code in (("dismiss_stale_reviews", "STALE_REVIEW_INVALIDATION_MISSING"), ("require_last_push_approval", "LAST_PUSH_APPROVAL_MISSING")):
            snapshot = github_governance_snapshot(protection="legacy")
            snapshot["legacy_branch_protection"]["body"]["required_pull_request_reviews"][key] = False
            self._reject_snapshot(snapshot, code)

    def test_conversation_force_push_deletion_admin_and_bypass_gates_fail(self):
        cases = (
            ("required_conversation_resolution", "CONVERSATION_RESOLUTION_MISSING"),
            ("non_fast_forward", "FORCE_PUSH_ALLOWED"),
            ("deletion", "BRANCH_DELETION_ALLOWED"),
        )
        for kind, code in cases:
            snapshot = github_governance_snapshot()
            snapshot["ruleset_details"][0]["rules"] = [rule for rule in snapshot["ruleset_details"][0]["rules"] if rule["type"] != kind]
            self._reject_snapshot(snapshot, code)
        snapshot = github_governance_snapshot(protection="legacy")
        snapshot["legacy_branch_protection"]["body"]["enforce_admins"]["enabled"] = False
        self._reject_snapshot(snapshot, "LEGACY_ADMIN_ENFORCEMENT_MISSING")
        snapshot = github_governance_snapshot()
        snapshot["ruleset_details"][0]["bypass_actors"] = [{"actor_id": 42, "actor_type": "Team", "bypass_mode": "always"}]
        self._reject_snapshot(snapshot, "RULESET_BYPASS_ACTOR_PRESENT")
        snapshot = github_governance_snapshot(protection="legacy")
        snapshot["legacy_branch_protection"]["body"]["required_pull_request_reviews"]["bypass_pull_request_allowances"]["users"] = ["kimhw8084"]
        self._reject_snapshot(snapshot, "LEGACY_BYPASS_ALLOWANCE_PRESENT")

    def test_wrong_repository_branch_pr_merge_subject_and_direct_push_fail(self):
        mutations = (
            lambda value: value["repository_metadata"].update(full_name="elsewhere/k-slide"),
            lambda value: value["repository_metadata"].update(default_branch="release"),
            lambda value: value["target_branch"].update(commit_sha="d" * 40),
            lambda value: value["pull_request"]["base"].update(ref="release"),
            lambda value: value["pull_request"].update(merge_commit_sha="d" * 40),
            lambda value: value["pull_request"].update(merged=False),
        )
        for mutate in mutations:
            snapshot = github_governance_snapshot()
            mutate(snapshot)
            self._reject_snapshot(snapshot)

    def test_candidate_files_are_bound_to_merge_subject_and_policy_identity(self):
        snapshot = github_governance_snapshot()
        snapshot["candidate_codeowners"]["ref"] = BASE_SHA
        self._reject_snapshot(snapshot, "CANDIDATE_FILE_NOT_BOUND_TO_RELEASE_SUBJECT")
        snapshot = github_governance_snapshot()
        from tests.ksa32_governance_fixtures import _file_snapshot
        altered = copy.deepcopy(GOVERNANCE_POLICY)
        altered["policy"]["version"] = "9.9"
        content = json.dumps(altered, sort_keys=True).encode("utf-8")
        snapshot["candidate_governance_policy"] = _file_snapshot(
            "security/release-governance-policy.json", SUBJECT, content,
        )
        self._reject_snapshot(snapshot, "GOVERNANCE_POLICY_MISMATCH")

    def test_payload_tampering_and_replay_across_candidate_or_repository_fail(self):
        sources = self._sources()
        path = self._build(sources)
        envelope = json.loads(path.read_text(encoding="utf-8"))
        envelope["payload"]["pull_request_number"] = 33
        path.write_text(json.dumps(envelope) + "\n", encoding="utf-8")
        with self.assertRaises(EvidenceValidationError):
            self._load(path)

        path = self._build(self._sources())
        changed_candidate = copy.deepcopy(self.candidate)
        changed_candidate["provider"] = "replayed-candidate"
        with self.assertRaises(EvidenceValidationError):
            self._load(path, candidate=changed_candidate)
        with self.assertRaises(EvidenceValidationError):
            self._load(path, subject="d" * 40)

    def test_governance_is_invalidated_for_any_candidate_or_subject_change(self):
        sources = self._sources()
        path = self._build(sources)
        old = self._load(path)
        changed = copy.deepcopy(self.candidate)
        changed["retention_policy"]["operational_metadata_retention_days"] = 61
        impact = candidate_change_impact(self.candidate, changed)
        self.assertIn("governance", impact["affected_evidence"])
        with self.assertRaises(EvidenceValidationError):
            build_recertification_record(
                self.candidate, changed, {"governance": old}, ["governance"],
                prior_release_manifest_sha256="e" * 64,
            )
        changed["subject_git_sha"] = "d" * 40
        impact = candidate_change_impact(self.candidate, changed)
        self.assertIn("governance", impact["affected_evidence"])
        records, errors = _load_records(
            {"governance": path},
            subject_sha=changed["subject_git_sha"],
            deployment_fp=candidate_deployment_fingerprint(changed),
            repository_root=self.root,
            candidate_spec=changed,
            require_candidate_binding=True,
        )
        self.assertNotIn("governance", records)
        self.assertTrue(errors)
        with self.assertRaises(EvidenceValidationError):
            build_recertification_record(
                self.candidate, changed, {"governance": old}, ["governance"],
                prior_release_manifest_sha256="e" * 64,
            )

    def test_snapshot_source_tampering_and_policy_payload_tampering_fail(self):
        sources = self._sources()
        path = self._build(sources)
        snapshot = json.loads(sources["pull_request_reviews"].read_text(encoding="utf-8"))
        snapshot.clear()
        sources["pull_request_reviews"].write_text("[]\n", encoding="utf-8")
        with self.assertRaises(EvidenceValidationError):
            self._load(path)
        path = self._build(self._sources())
        envelope = json.loads(path.read_text(encoding="utf-8"))
        envelope["payload"]["governance_policy_identity"] = "0" * 64
        path.write_text(json.dumps(envelope) + "\n", encoding="utf-8")
        with self.assertRaises(EvidenceValidationError):
            self._load(path)

    def test_freeform_review_text_is_rejected_from_raw_snapshots(self):
        snapshot = github_governance_snapshot()
        snapshot["pull_request_reviews"][0]["body"] = "Looks good"
        self._reject_snapshot(snapshot, "PR_REVIEW_SNAPSHOT_INVALID")

    def test_release_states_require_and_accept_only_current_governance_evidence(self):
        policy = load_model_policy(self.root)
        for requested in ("PILOT_APPROVED", "PRODUCTION_CERTIFIED"):
            state, blockers = derive_release_state(
                requested, records={}, root=self.root, policy=policy,
                deployment_fp=self.deployment, candidate_spec=self.candidate,
            )
            self.assertNotIn(state, {"PILOT_APPROVED", "PRODUCTION_CERTIFIED"})
            self.assertTrue(any("missing validated governance evidence" in item for item in blockers))
            valid_path = self._build(self._sources())
            valid = self._load(valid_path)
            state, blockers = derive_release_state(
                requested, records={"governance": valid}, root=self.root, policy=policy,
                deployment_fp=self.deployment, candidate_spec=self.candidate,
            )
            self.assertNotIn("missing validated governance evidence", blockers)
            self.assertNotIn(state, {"PILOT_APPROVED", "PRODUCTION_CERTIFIED"})

    def test_contract_file_matches_pinned_policy_and_payload_validator_is_closed(self):
        policy_path = Path(__file__).resolve().parents[1] / POLICY_PATH
        self.assertEqual(json.loads(policy_path.read_text(encoding="utf-8")), GOVERNANCE_POLICY)
        with self.assertRaises(Exception):
            validate_governance_payload({"source_kind": "github_api", "codeowners_pass": True})

    def test_capture_workflow_run_snapshot_is_complete_and_candidate_pr_head_bound(self):
        source = github_governance_snapshot()
        provenance = source["workflow_run_provenance"]
        latest_run = next(
            item for item in provenance["items"]
            if item["event"] == "pull_request" and item["workflow_path"] == ".github/workflows/k-slide.yml"
        )
        latest_run["run_attempt"] = 2
        for job in latest_run["jobs"]:
            job["run_attempt"] = 2
        routes: list[str] = []

        class FakeApi:
            def __init__(self, *, incomplete: bool = False):
                self.incomplete = incomplete

            def get(self, route: str, **_kwargs):
                routes.append(route)
                endpoint = route.split("?", 1)[0]
                if endpoint == f"repos/{REPOSITORY_FULL_NAME}/actions/workflows":
                    items = provenance["workflow_catalog"]["items"]
                    return {"total_count": len(items) + int(self.incomplete), "workflows": [
                        {"id": item["id"], "name": item["name"], "path": item["path"], "state": item["state"]}
                        for item in items
                    ]}, 200
                if endpoint == f"repos/{REPOSITORY_FULL_NAME}/actions/runs":
                    runs = provenance["items"]
                    return {"total_count": len(runs), "workflow_runs": [
                        {
                            "id": item["run_id"], "workflow_id": item["workflow_id"],
                            "head_sha": item["head_sha"], "event": item["event"],
                            "run_attempt": item["run_attempt"], "status": item["status"],
                            "conclusion": item["conclusion"],
                            "repository": {"id": item["repository_id"], "full_name": item["repository_full_name"]},
                            "pull_requests": [
                                {"number": assoc["number"], "head": {"sha": assoc["head_sha"]}}
                                for assoc in item["pull_requests"]
                            ],
                        }
                        for item in runs
                    ]}, 200
                if "/attempts/" in endpoint and endpoint.endswith("/jobs"):
                    pieces = endpoint.split("/")
                    run_id = int(pieces[-4])
                    attempt = int(pieces[-2])
                    run = next(item for item in provenance["items"] if item["run_id"] == run_id)
                    if attempt != run["run_attempt"]:
                        raise AssertionError("capture did not request the authoritative latest attempt")
                    jobs = run["jobs"]
                    return {"total_count": len(jobs), "jobs": [
                        {
                            "id": item["job_id"], "run_id": item["workflow_run_id"],
                            "head_sha": item["head_sha"], "name": item["name"],
                            "status": item["status"], "conclusion": item["conclusion"],
                        }
                        for item in jobs
                    ]}, 200
                raise AssertionError(f"unexpected route {route}")

        captured = capture_workflow_run_provenance(
            FakeApi(),
            repository=REPOSITORY_FULL_NAME,
            repository_id=81234567,
            pull_number=PULL_NUMBER,
            subject_sha=SUBJECT,
            head_sha=HEAD_SHA,
            check_runs=source["pull_request_check_runs"]["items"],
        )
        self.assertTrue(captured["complete"])
        self.assertTrue(captured["workflow_catalog"]["complete"])
        self.assertEqual(captured["repository_id"], 81234567)
        self.assertEqual(captured["subject_sha"], SUBJECT)
        self.assertEqual(captured["pull_request_number"], PULL_NUMBER)
        self.assertEqual(captured["pull_request_head_sha"], HEAD_SHA)
        self.assertEqual(len(captured["items"]), 5)
        self.assertEqual(sum(len(run["jobs"]) for run in captured["items"]), 9)
        self.assertEqual(next(item for item in captured["items"] if item["run_id"] == latest_run["run_id"])["run_attempt"], 2)
        self.assertTrue(any(f"/attempts/2/jobs?" in route for route in routes))
        self.assertTrue(all("/attempts/" in route for route in routes if route.endswith("/jobs?per_page=100&page=1")))
        serialized = json.dumps(captured).casefold()
        self.assertNotIn("https://", serialized)
        self.assertNotIn("logs", serialized)
        with self.assertRaises(CaptureError):
            capture_workflow_run_provenance(
                FakeApi(incomplete=True), repository=REPOSITORY_FULL_NAME,
                repository_id=81234567, pull_number=PULL_NUMBER, subject_sha=SUBJECT,
                head_sha=HEAD_SHA, check_runs=source["pull_request_check_runs"]["items"],
            )

    def test_capture_commit_pull_pages_and_exact_pr_normalization(self):
        def raw_pull(number: int, *, head_sha: str = HEAD_SHA) -> dict:
            return {
                "id": 9901 if number == PULL_NUMBER else 10000 + number,
                "number": number,
                "base": {
                    "ref": "main",
                    "repo": {"id": REPOSITORY_ID, "full_name": "KimHW8084/K-Slide"},
                },
                "head": {
                    "sha": head_sha,
                    "ref": "release-candidate" if number == PULL_NUMBER else f"historical-{number}",
                    "repo": {"id": REPOSITORY_ID, "full_name": "KimHW8084/K-Slide"},
                },
            }

        exact_pr = {
            "id": 9901,
            "number": PULL_NUMBER,
            "user": {"id": AUTHOR_ID, "login": "release-contributor"},
            "base": {
                "sha": BASE_SHA, "ref": "main",
                "repo": {"id": REPOSITORY_ID, "full_name": "KimHW8084/K-Slide"},
            },
            "head": {
                "sha": HEAD_SHA, "ref": "release-candidate",
                "repo": {"id": REPOSITORY_ID, "full_name": "KimHW8084/K-Slide"},
            },
            "state": "closed", "merged": True, "merged_at": "2026-09-24T00:00:00Z",
            "merge_commit_sha": SUBJECT,
        }
        projected_pr = _pull_projection(exact_pr, REPOSITORY_ID, PULL_NUMBER)
        self.assertEqual(projected_pr["base"]["repository_full_name"], REPOSITORY_FULL_NAME)
        self.assertEqual(projected_pr["head"]["repository_id"], REPOSITORY_ID)
        self.assertEqual(projected_pr["head"]["repository_full_name"], REPOSITORY_FULL_NAME)

        raw_items = [raw_pull(100 + index, head_sha="e" * 40) for index in range(100)]
        raw_items.append(raw_pull(PULL_NUMBER))
        routes = []

        class FakeApi:
            def get(self, route: str, **_kwargs):
                routes.append(route)
                page = int(route.rsplit("page=", 1)[1])
                return (raw_items[:100] if page == 1 else raw_items[100:]), 200

        captured = capture_head_commit_pull_requests(
            FakeApi(), repository=REPOSITORY_FULL_NAME, repository_id=REPOSITORY_ID,
            pull_number=PULL_NUMBER, head_sha=HEAD_SHA,
        )
        self.assertTrue(captured["complete"])
        self.assertEqual(len(captured["items"]), 101)
        self.assertEqual([route.rsplit("page=", 1)[1] for route in routes], ["1", "2"])
        requested = next(item for item in captured["items"] if item["number"] == PULL_NUMBER)
        self.assertEqual(requested, {
            "id": 9901, "number": PULL_NUMBER,
            "base_repository_id": REPOSITORY_ID,
            "base_repository_full_name": REPOSITORY_FULL_NAME,
            "base_ref": "main", "head_sha": HEAD_SHA, "head_ref": "release-candidate",
            "head_repository_id": REPOSITORY_ID,
            "head_repository_full_name": REPOSITORY_FULL_NAME,
        })

        class IncompleteApi:
            def get(self, route: str, **_kwargs):
                if int(route.rsplit("page=", 1)[1]) == 1:
                    return raw_items[:100], 200
                raise CaptureError("GITHUB_API_REQUEST_FAILED")

        with self.assertRaises(CaptureError):
            capture_head_commit_pull_requests(
                IncompleteApi(), repository=REPOSITORY_FULL_NAME, repository_id=REPOSITORY_ID,
                pull_number=PULL_NUMBER, head_sha=HEAD_SHA,
            )

    def test_capture_workflow_is_manual_and_keeps_raw_snapshots_separate(self):
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github" / "workflows" / "k-slide-governance.yml").read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("pull_request:", workflow)
        self.assertNotIn("push:", workflow)
        self.assertIn("KSLIDE_GOVERNANCE_READ_TOKEN", workflow)
        self.assertIn("--subject-sha \"$GITHUB_SHA\"", workflow)
        self.assertIn("k-slide-governance-evidence-", workflow)
        self.assertIn("k-slide-governance-snapshots-", workflow)


if __name__ == "__main__":
    unittest.main()
