from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

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
        self.assertEqual(payload["protection_mechanism"], "repository_rulesets")
        self.assertEqual(payload["status_check_contexts"], GOVERNANCE_POLICY["status_checks"]["required_contexts"])
        self.assertEqual(payload["active_ruleset_ids"], [441])
        self.assertEqual(payload["review_count"], 1)
        self.assertNotIn("user_login", payload)
        self.assertNotIn("comment", json.dumps(payload).casefold())
        self.assertEqual(len(loaded["sources"]), 12)

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
        mutations = (
            lambda runs: runs["items"].pop(),
            lambda runs: runs["items"][0].update(conclusion="failure"),
            lambda runs: runs["items"][0].update(status="in_progress", conclusion=None),
            lambda runs: runs["items"][0].update(head_sha="d" * 40),
        )
        for mutate in mutations:
            snapshot = github_governance_snapshot()
            mutate(snapshot["pull_request_check_runs"])
            self._reject_snapshot(snapshot)

    def test_same_named_required_check_from_wrong_app_fails(self):
        snapshot = github_governance_snapshot()
        snapshot["pull_request_check_runs"]["items"][0]["app_id"] = 123
        snapshot["pull_request_check_runs"]["items"][0]["app_slug"] = "untrusted-app"
        self._reject_snapshot(snapshot, "CHECK_RUN_INTEGRATION_MISMATCH")

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
