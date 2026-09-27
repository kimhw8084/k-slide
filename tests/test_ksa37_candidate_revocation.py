from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from jsonschema import Draft202012Validator

from k_slide.candidate_revocation import (
    REVOCATION_REASON_CATEGORIES,
    CandidateRevocationError,
    CandidateRevocationStatus,
    ReferenceFileCandidateRevocationControl,
    _sign,
    apply_reference_candidate_event,
    build_candidate_control_event,
    candidate_revocation_gate,
    record_reference_candidate_event,
)
from k_slide.ingest import prepare_run
from k_slide.io import atomic_write_json, read_json
from k_slide.rollout import (
    RolloutCandidateBinding,
    RolloutControlError,
    ReferenceFileRolloutControl,
    apply_rollout_transition,
    build_transition_command,
    rollout_policy_identity,
    transition_reference_rollout_control,
)
from k_slide.state import load_state, RunPhase
from tests.test_ksa34_rollout import KEY, NOW, _environment, _initialize, _state, _timestamp, _transition


SCHEMA = json.loads(Path("schemas/candidate-revocation.schema.json").read_text(encoding="utf-8"))
ROLLOUT_SCHEMA = json.loads(Path("schemas/rollout-control.schema.json").read_text(encoding="utf-8"))


def binding(environment) -> RolloutCandidateBinding:
    return RolloutCandidateBinding.from_environment(environment)


def event_for(
    root: Path,
    environment,
    *,
    action: str = "REVOKE",
    category: str = "SECURITY_INCIDENT",
    event_id: str = "incident-1",
    evidence_kind: str = "INCIDENT_RECORD",
    authority: str | None = None,
    expected_status: CandidateRevocationStatus | None = None,
):
    candidate = binding(environment)
    status = expected_status or ReferenceFileCandidateRevocationControl(root, key=KEY).status(candidate)
    if authority is None:
        authority = {
            "CRITICAL_SEMANTIC_DEFECT": "quality_authority",
            "SECURITY_INCIDENT": "security_authority",
            "PRIVACY_INCIDENT": "privacy_authority",
            "CREDENTIAL_LEAKAGE": "security_authority",
            "TENANT_ISOLATION_FAILURE": "security_authority",
            "PROVIDER_MODEL_CONFIG_DRIFT": "deployment_authority",
            "BROKEN_EVIDENCE_IDENTITY": "release_authority",
            "MATERIAL_DATA_USE_POLICY_CHANGE": "privacy_authority",
            "CRITICAL_VULNERABILITY": "security_authority",
        }[category] if action == "REVOKE" else "qualification_authority"
    return build_candidate_control_event(
        action=action,
        candidate=candidate,
        actor_ref="incident_operator" if action == "REVOKE" else "release_operator",
        authority_ref=authority,
        event_id=event_id,
        expected_revision=status.revision,
        expected_state_identity=status.state_identity,
        previous_event_identity=status.event_identity,
        occurred_at=_timestamp(NOW),
        reason_categories=[category],
        evidence_kind=evidence_kind,
        evidence_identity=hashlib.sha256(("evidence:" + event_id).encode()).hexdigest(),
        key=KEY,
    )


class KSA37CandidateRevocationTests(unittest.TestCase):
    def setUp(self):
        Draft202012Validator.check_schema(SCHEMA)
        Draft202012Validator.check_schema(ROLLOUT_SCHEMA)

    def test_all_closed_reason_categories_are_authoritative_and_source_free(self):
        self.assertEqual(len(REVOCATION_REASON_CATEGORIES), 9)
        for index, category in enumerate(REVOCATION_REASON_CATEGORIES):
            with self.subTest(category=category), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                active = _environment(f"category-{index}")
                _initialize(root, active)
                signed = event_for(root, active, category=category, event_id=f"reason-{index}")
                Draft202012Validator(SCHEMA).validate(signed)
                status = apply_reference_candidate_event(root, event=signed, key=KEY, now=NOW)
                self.assertEqual(status.active_reason_categories, (category,))
                self.assertTrue(status.revoked)
                durable = (root / ".k-slide-config" / "candidate-revocations").rglob("*.json")
                encoded = "".join(path.read_text(encoding="utf-8") for path in durable)
                self.assertNotIn("source content", encoded)
                self.assertNotIn("prompt body", encoded)
                self.assertNotIn("AccessKey=", encoded)
                self.assertNotIn("secret-value", encoded)

    def test_matching_active_candidate_revocation_uses_signed_authorized_rollback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active, fallback = _environment("revoked"), _environment("fallback")
            policy = _initialize(root, active, rollback=fallback)
            _transition(root, policy, action="SET_STAGE", transition_id="open", stage="CANARY")
            policy_identity = rollout_policy_identity(policy, key=KEY, now=NOW)
            signed = event_for(root, active, category="CRITICAL_VULNERABILITY")
            status = apply_reference_candidate_event(root, event=signed, key=KEY, now=NOW)
            state = _state(root)
            self.assertEqual(status.status, "REVOKED")
            self.assertEqual(state["transition_action"], "ROLLBACK")
            self.assertEqual(state["candidate_binding"], binding(fallback).as_dict())
            self.assertEqual((state["stage"], state["admissions_enabled"], state["admitted_cohorts"]), ("DISABLED", False, []))
            self.assertEqual(read_json(root / ".k-slide-config" / "rollout-policy.json"), policy)
            self.assertEqual(state["policy_identity"], policy_identity)
            self.assertEqual(ReferenceFileRolloutControl(root, key=KEY, cohort_id="alpha", now=NOW).admit(binding(fallback)).reason_code, "ADMISSIONS_DISABLED")

    def test_no_rollback_target_disables_the_active_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = _environment("no-fallback")
            policy = _initialize(root, active)
            _transition(root, policy, action="SET_STAGE", transition_id="open", stage="FULL")
            apply_reference_candidate_event(root, event=event_for(root, active), key=KEY, now=NOW)
            state = _state(root)
            self.assertEqual(state["transition_action"], "DISABLE")
            self.assertEqual(state["candidate_binding"], binding(active).as_dict())
            self.assertEqual((state["stage"], state["admissions_enabled"]), ("DISABLED", False))

    def test_revoked_fallback_is_never_selected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active, fallback = _environment("active"), _environment("bad-fallback")
            policy = _initialize(root, active, rollback=fallback)
            apply_reference_candidate_event(root, event=event_for(root, fallback, category="SECURITY_INCIDENT"), key=KEY, now=NOW)
            # The fallback event is recorded against that exact candidate and
            # cannot change the currently selected primary candidate.
            self.assertEqual(_state(root)["candidate_binding"], binding(active).as_dict())
            _transition(root, policy, action="SET_STAGE", transition_id="open", stage="PILOT")
            apply_reference_candidate_event(root, event=event_for(root, active, category="PRIVACY_INCIDENT", event_id="active-privacy"), key=KEY, now=NOW)
            self.assertEqual(_state(root)["transition_action"], "DISABLE")
            self.assertEqual(_state(root)["candidate_binding"], binding(active).as_dict())

    def test_event_targets_exact_candidate_and_stale_candidate_never_moves_rollout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active, fallback, wrong = _environment("active"), _environment("fallback"), _environment("unbound")
            _initialize(root, active, rollback=fallback)
            mismatched = event_for(root, wrong, expected_status=ReferenceFileCandidateRevocationControl(root, key=KEY).status(binding(active)))
            with self.assertRaises(CandidateRevocationError):
                apply_reference_candidate_event(root, event=mismatched, key=KEY, now=NOW)
            self.assertEqual(_state(root)["candidate_binding"], binding(active).as_dict())
            with self.assertRaises(CandidateRevocationError):
                ReferenceFileCandidateRevocationControl(root, key=KEY).status(binding(wrong))

    def test_unsigned_malformed_and_unauthorized_events_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = _environment("bad-event")
            _initialize(root, active)
            signed = event_for(root, active)
            unsigned = {"payload": signed["payload"]}
            with self.assertRaises(CandidateRevocationError):
                apply_reference_candidate_event(root, event=unsigned, key=KEY, now=NOW)
            malformed_payload = {**signed["payload"], "diagnostic": "do not persist"}
            with self.assertRaises(CandidateRevocationError):
                apply_reference_candidate_event(root, event=_sign(malformed_payload, KEY), key=KEY, now=NOW)
            unauthorized_payload = {**signed["payload"], "authority_ref": "unknown_authority"}
            with self.assertRaises(CandidateRevocationError):
                apply_reference_candidate_event(root, event=_sign(unauthorized_payload, KEY), key=KEY, now=NOW)
            self.assertEqual(ReferenceFileCandidateRevocationControl(root, key=KEY).status(binding(active)).status, "CLEAR")

    def test_duplicate_event_is_idempotent_and_conflicting_revision_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = _environment("idempotent")
            _initialize(root, active)
            signed = event_for(root, active)
            first = apply_reference_candidate_event(root, event=signed, key=KEY, now=NOW)
            second = apply_reference_candidate_event(root, event=signed, key=KEY, now=NOW)
            self.assertEqual(first, second)
            self.assertEqual(ReferenceFileCandidateRevocationControl(root, key=KEY).status(binding(active)).revision, 1)
            conflict = event_for(root, active, event_id="incident-1")
            altered = {**conflict["payload"], "evidence_reference": {"kind": "INCIDENT_RECORD", "identity": "f" * 64}}
            with self.assertRaisesRegex(CandidateRevocationError, "conflicts"):
                record_reference_candidate_event(root, event=_sign(altered, KEY), key=KEY, now=NOW)

    def test_optimistic_revision_conflict_and_stale_event_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = _environment("revision")
            _initialize(root, active)
            stale = event_for(root, active, event_id="first")
            competing = event_for(root, active, category="PRIVACY_INCIDENT", event_id="competing")
            record_reference_candidate_event(root, event=stale, key=KEY, now=NOW)
            with self.assertRaisesRegex(CandidateRevocationError, "stale revision"):
                record_reference_candidate_event(root, event=competing, key=KEY, now=NOW)

    def test_concurrent_conflicting_revisions_commit_at_most_one_event(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = _environment("concurrent")
            _initialize(root, active)
            first = event_for(root, active, event_id="race-first")
            second = event_for(root, active, category="PRIVACY_INCIDENT", event_id="race-second")
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(record_reference_candidate_event, root, event=item, key=KEY, now=NOW) for item in (first, second)]
            results = []
            for future in futures:
                try:
                    results.append(future.result())
                except CandidateRevocationError:
                    results.append(None)
            self.assertEqual(sum(item is not None for item in results), 1)
            status = ReferenceFileCandidateRevocationControl(root, key=KEY).status(binding(active))
            self.assertEqual(status.revision, 1)
            self.assertEqual(len(status.active_reason_categories), 1)

    def test_missing_or_unreadable_revocation_authority_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = _environment("outage")
            _initialize(root, active)
            candidate = binding(active)
            provider = ReferenceFileCandidateRevocationControl(root, key=KEY)
            self.assertFalse(candidate_revocation_gate(candidate=candidate, provider=None)[0])
            state_path = next((root / ".k-slide-config" / "candidate-revocations").glob("*/state.json"))
            state_path.unlink()
            with self.assertRaises(CandidateRevocationError):
                provider.status(candidate)
            self.assertFalse(candidate_revocation_gate(candidate=candidate, provider=provider)[0])

    def test_signed_state_identity_drift_is_not_healthy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = _environment("identity-drift")
            _initialize(root, active)
            state_path = next((root / ".k-slide-config" / "candidate-revocations").glob("*/state.json"))
            signed = read_json(state_path)
            signed["payload"]["candidate_binding"]["subject_git_sha"] = "f" * 40
            atomic_write_json(state_path, signed)
            with self.assertRaisesRegex(CandidateRevocationError, "unauthorized or modified"):
                ReferenceFileCandidateRevocationControl(root, key=KEY).status(binding(active))

    def test_revocation_denies_admission_and_direct_signed_cohort_change(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = _environment("no-bypass")
            policy = _initialize(root, active)
            _transition(root, policy, action="SET_STAGE", transition_id="open", stage="FULL")
            signed = event_for(root, active)
            status, _duplicate = record_reference_candidate_event(root, event=signed, key=KEY, now=NOW)
            denied = ReferenceFileRolloutControl(root, key=KEY, cohort_id="alpha", now=NOW).admit(binding(active))
            self.assertEqual((denied.status, denied.reason_code, denied.revocation_state_identity), ("DENIED", "CANDIDATE_REVOKED", status.state_identity))
            current = read_json(root / ".k-slide-config" / "rollout-state.json")
            command = build_transition_command(
                policy_identity=rollout_policy_identity(policy, key=KEY, now=NOW),
                expected_revision=current["payload"]["revision"],
                action="SET_STAGE",
                transition_id="bypass-stage",
                actor_ref="deployment_admin",
                target_stage="FULL",
                target_candidate=None,
                key=KEY,
            )
            with self.assertRaisesRegex(RolloutControlError, "active candidate revocation"):
                transition_reference_rollout_control(root, command=command, key=KEY, now=NOW)
            # A replay of the durable latest event reconciles via the normal
            # signed DISABLE path after a crash between ledger and rollout.
            apply_reference_candidate_event(root, event=signed, key=KEY, now=NOW)
            self.assertEqual((_state(root)["stage"], _state(root)["transition_action"]), ("DISABLED", "DISABLE"))

    def test_recovery_rejects_enabled_primary_after_revoke_transition_crash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = _environment("recover-crash-window")
            policy = _initialize(root, active)
            _transition(root, policy, action="SET_STAGE", transition_id="open-before-revoke-crash", stage="CANARY")
            state_path = root / ".k-slide-config" / "rollout-state.json"
            head_path = root / ".k-slide-config" / "rollout-head.json"
            history_dir = root / ".k-slide-config" / "rollout-history"
            state_before = state_path.read_bytes()
            head_before = head_path.read_bytes()
            history_before = {path.name: path.read_bytes() for path in history_dir.glob("*.json")}

            revoke = event_for(root, active, event_id="crash-window-revoke")
            with patch("k_slide.rollout.transition_reference_rollout_control", side_effect=RolloutControlError("simulated rollout transition failure")):
                with self.assertRaisesRegex(CandidateRevocationError, "recorded"):
                    apply_reference_candidate_event(root, event=revoke, key=KEY, now=NOW)

            revoked = ReferenceFileCandidateRevocationControl(root, key=KEY).status(binding(active))
            self.assertTrue(revoked.revoked)
            self.assertEqual(state_path.read_bytes(), state_before)
            self.assertEqual(head_path.read_bytes(), head_before)
            self.assertEqual({path.name: path.read_bytes() for path in history_dir.glob("*.json")}, history_before)
            self.assertEqual((_state(root)["stage"], _state(root)["admissions_enabled"]), ("CANARY", True))

            recovery = event_for(root, active, action="RECOVER", event_id="crash-window-recover", evidence_kind="REQUALIFICATION_ATTESTATION")
            with self.assertRaisesRegex(CandidateRevocationError, "disabled primary rollout"):
                apply_reference_candidate_event(root, event=recovery, key=KEY, now=NOW)

            still_revoked = ReferenceFileCandidateRevocationControl(root, key=KEY).status(binding(active))
            self.assertTrue(still_revoked.revoked)
            self.assertEqual(still_revoked.revision, revoked.revision)
            self.assertEqual(state_path.read_bytes(), state_before)
            self.assertEqual(head_path.read_bytes(), head_before)
            self.assertEqual({path.name: path.read_bytes() for path in history_dir.glob("*.json")}, history_before)
            admission = ReferenceFileRolloutControl(root, key=KEY, cohort_id="alpha", now=NOW).admit(binding(active))
            self.assertEqual((admission.status, admission.reason_code, admission.revocation_status), ("DENIED", "CANDIDATE_REVOKED", "REVOKED"))

    def test_recovery_from_already_disabled_primary_keeps_rollout_disabled(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = _environment("recover-disabled-primary")
            _initialize(root, active)
            apply_reference_candidate_event(root, event=event_for(root, active, event_id="disabled-revoke"), key=KEY, now=NOW)
            state_before = (root / ".k-slide-config" / "rollout-state.json").read_bytes()
            history_before = tuple(sorted(path.name for path in (root / ".k-slide-config" / "rollout-history").glob("*.json")))

            recovery = event_for(root, active, action="RECOVER", event_id="disabled-recovery", evidence_kind="REQUALIFICATION_ATTESTATION")
            recovered = apply_reference_candidate_event(root, event=recovery, key=KEY, now=NOW)

            self.assertEqual((recovered.status, recovered.active_reason_categories), ("RECOVERED", ()))
            self.assertEqual((root / ".k-slide-config" / "rollout-state.json").read_bytes(), state_before)
            self.assertEqual(tuple(sorted(path.name for path in (root / ".k-slide-config" / "rollout-history").glob("*.json"))), history_before)
            state = _state(root)
            self.assertEqual((state["candidate_binding"], state["stage"], state["admissions_enabled"], state["admitted_cohorts"]), (binding(active).as_dict(), "DISABLED", False, []))
            admission = ReferenceFileRolloutControl(root, key=KEY, cohort_id="alpha", now=NOW).admit(binding(active))
            self.assertEqual((admission.status, admission.reason_code, admission.revocation_status), ("DENIED", "ADMISSIONS_DISABLED", "RECOVERED"))

    def test_failed_restore_keeps_primary_revoked_until_rollout_is_proven(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active, fallback = _environment("recover-restore-failure"), _environment("recover-restore-fallback")
            policy = _initialize(root, active, rollback=fallback)
            _transition(root, policy, action="SET_STAGE", transition_id="open-before-restore-failure", stage="PILOT")
            apply_reference_candidate_event(root, event=event_for(root, active, event_id="restore-failure-revoke"), key=KEY, now=NOW)
            state_path = root / ".k-slide-config" / "rollout-state.json"
            state_before = state_path.read_bytes()
            revocations = ReferenceFileCandidateRevocationControl(root, key=KEY)
            before = revocations.status(binding(active))
            recovery = event_for(root, active, action="RECOVER", event_id="restore-failure-recover", evidence_kind="REQUALIFICATION_ATTESTATION")

            with patch("k_slide.rollout.transition_reference_rollout_control", side_effect=RolloutControlError("simulated RESTORE_CANDIDATE failure")):
                with self.assertRaisesRegex(CandidateRevocationError, "revocation remains active"):
                    apply_reference_candidate_event(root, event=recovery, key=KEY, now=NOW)

            after = revocations.status(binding(active))
            self.assertTrue(after.revoked)
            self.assertEqual(after.revision, before.revision)
            self.assertEqual(state_path.read_bytes(), state_before)
            self.assertEqual((_state(root)["candidate_binding"], _state(root)["stage"]), (binding(fallback).as_dict(), "DISABLED"))

    def test_recovery_requires_requalification_and_restores_only_to_disabled(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active, fallback = _environment("recover"), _environment("recover-fallback")
            policy = _initialize(root, active, rollback=fallback)
            _transition(root, policy, action="SET_STAGE", transition_id="open", stage="PILOT")
            apply_reference_candidate_event(root, event=event_for(root, active), key=KEY, now=NOW)
            revoked = ReferenceFileCandidateRevocationControl(root, key=KEY).status(binding(active))
            with self.assertRaises(CandidateRevocationError):
                build_candidate_control_event(
                    action="RECOVER", candidate=binding(active), actor_ref="release_operator", authority_ref="qualification_authority",
                    event_id="recover-no-proof", expected_revision=revoked.revision, expected_state_identity=revoked.state_identity,
                    previous_event_identity=revoked.event_identity, occurred_at=_timestamp(NOW), reason_categories=["SECURITY_INCIDENT"],
                    evidence_kind="INCIDENT_RECORD", evidence_identity="e" * 64, key=KEY,
                )
            recovery = event_for(root, active, action="RECOVER", event_id="qualified-recovery", evidence_kind="REQUALIFICATION_ATTESTATION")
            recovered = apply_reference_candidate_event(root, event=recovery, key=KEY, now=NOW)
            self.assertEqual((recovered.status, recovered.active_reason_categories), ("RECOVERED", ()))
            state = _state(root)
            self.assertEqual(state["transition_action"], "RESTORE_CANDIDATE")
            self.assertEqual(state["candidate_binding"], binding(active).as_dict())
            self.assertEqual((state["stage"], state["admissions_enabled"], state["admitted_cohorts"]), ("DISABLED", False, []))
            denied = ReferenceFileRolloutControl(root, key=KEY, cohort_id="alpha", now=NOW).admit(binding(active))
            self.assertEqual((denied.status, denied.reason_code, denied.revocation_status), ("DENIED", "ADMISSIONS_DISABLED", "RECOVERED"))

    def test_recovery_bound_to_a_different_candidate_cannot_clear_revocation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active, fallback = _environment("recovery-primary"), _environment("recovery-fallback")
            _initialize(root, active, rollback=fallback)
            apply_reference_candidate_event(root, event=event_for(root, active), key=KEY, now=NOW)
            wrong_status = ReferenceFileCandidateRevocationControl(root, key=KEY).status(binding(fallback))
            signed = build_candidate_control_event(
                action="RECOVER", candidate=binding(fallback), actor_ref="release_operator", authority_ref="qualification_authority",
                event_id="wrong-candidate-recovery", expected_revision=wrong_status.revision,
                expected_state_identity=wrong_status.state_identity, previous_event_identity=wrong_status.event_identity,
                occurred_at=_timestamp(NOW), reason_categories=["SECURITY_INCIDENT"], evidence_kind="REQUALIFICATION_ATTESTATION",
                evidence_identity="e" * 64, key=KEY,
            )
            with self.assertRaisesRegex(CandidateRevocationError, "matching"):
                apply_reference_candidate_event(root, event=signed, key=KEY, now=NOW)
            self.assertTrue(ReferenceFileCandidateRevocationControl(root, key=KEY).status(binding(active)).revoked)

    def test_inflight_run_and_historical_evidence_are_unchanged_by_revocation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = _environment("inflight")
            policy = _initialize(root, active)
            _transition(root, policy, action="SET_STAGE", transition_id="open", stage="PILOT")
            source = root / "slide.png"
            source.write_bytes(b"\x89PNG\r\n\x1a\nsource fixture")
            run = prepare_run(root, explicit_paths=[str(source)], perform_processing=False, environment_identity=active, rollout_control=ReferenceFileRolloutControl(root, key=KEY, cohort_id="alpha", now=NOW))
            admission_path = run / "admission" / "ROLLOUT_ADMISSION.json"
            original_admission = admission_path.read_bytes()
            original_execution = json.loads((run / "EXECUTION_JOB.json").read_text(encoding="utf-8"))
            historical = root / "historical-certification.json"
            historical.write_text('{"evidence_identity":"immutable"}\n', encoding="utf-8")
            history_before = {item.name: item.read_bytes() for item in (root / ".k-slide-config" / "rollout-history").glob("*.json")}
            apply_reference_candidate_event(root, event=event_for(root, active), key=KEY, now=NOW)
            self.assertEqual(admission_path.read_bytes(), original_admission)
            self.assertEqual(json.loads((run / "EXECUTION_JOB.json").read_text(encoding="utf-8")), original_execution)
            self.assertEqual(original_execution["environment_identity"], active.as_dict())
            self.assertEqual(historical.read_text(encoding="utf-8"), '{"evidence_identity":"immutable"}\n')
            history_after = {item.name: item.read_bytes() for item in (root / ".k-slide-config" / "rollout-history").glob("*.json")}
            for name, contents in history_before.items():
                self.assertEqual(history_after[name], contents)
            self.assertEqual(set(history_after) - set(history_before), {"0000000003.json"})
            self.assertEqual(load_state(run).phase, RunPhase.INPUT_VALIDATED)

    def test_revocation_gate_blocks_readiness_and_release_promotion_without_live_authority(self):
        candidate = binding(_environment("promotion-gate"))
        self.assertEqual(candidate_revocation_gate(candidate=candidate, provider=None)[0], False)
        from evals.release import _release_revocation_gate

        ready, detail, exact = _release_revocation_gate(
            Path("."), subject=candidate.subject_git_sha, deployment=candidate.deployment_fingerprint,
            environment_identity=candidate.run_environment_identity_sha256,
        )
        self.assertFalse(ready)
        self.assertIn("unavailable", detail)
        self.assertEqual(exact, candidate)

    def test_production_readiness_fails_on_candidate_revocation(self):
        from k_slide.production import ProductionProfile, production_checks

        environment = _environment("readiness")
        profile = ProductionProfile.from_mapping({
            "schema_version": "1.1", "release_state": "PRODUCTION_CERTIFIED", "opencode_version": "1.2.3",
            "requested_model": "approved:model", "effective_model": "approved:model", "ocr_provider": "paddle",
            "ocr_asset_manifest": "missing-manifest.json", "python_version": "3.11", "paddle_version": "3.0.0",
            "paddleocr_version": "3.0.3", "libreoffice_version": "25.0", "retention_policy": {
                "schema_version": "1.0", "content_retention_days": 30, "operational_metadata_retention_days": 60,
            }, "tenant_isolation": "workspace_per_session", "network_egress": "default_deny",
            "subject_git_sha": binding(environment).subject_git_sha, "deployment_fingerprint": binding(environment).deployment_fingerprint,
            "certification_fingerprint": "c" * 64, "release_manifest": "manifest.json", "release_manifest_sha256": "d" * 64,
            "model_data_attestation": "attestation-1", "candidate_spec": {},
            "run_environment_identity_sha256": binding(environment).run_environment_identity_sha256,
        }, require_resolved_retention=False)

        class RevokedProvider:
            def status(self, candidate):
                return CandidateRevocationStatus(candidate, "e" * 64, 1, "REVOKED", ("SECURITY_INCIDENT",), "f" * 64)

        runtime = SimpleNamespace(
            kslide_version="0.3.5", opencode_version="1.2.3", reported_model_id="approved:model", vision_support=True,
            provider="approved", provider_backend="backend", model_revision="revision", quantization_or_dtype="fp16",
            context_configuration={}, image_preprocessing_settings={}, python_version="3.11", paddle_version="3.0.0",
            paddleocr_version="3.0.3", libreoffice_version="25.0", ocr_provider="paddle",
        )
        with patch("k_slide.production.load_production_profile", return_value=profile), \
             patch("k_slide.candidate_revocation.deployment_candidate_revocation_control", return_value=RevokedProvider()), \
             patch("k_slide.production._execution_behavior_checks", return_value=[]), \
             patch("k_slide.production._candidate_execution_binding_check", return_value={"label": "binding", "status": "PASS", "detail": "test"}), \
             patch("k_slide.production._runtime_identity_checks", return_value=[]), \
             patch("k_slide.production._installed_build_status", return_value=(True, "test")), \
             patch("k_slide.production._vision_evidence_status", return_value=(True, "test")), \
             patch("k_slide.production._manifest_and_fingerprint_status", return_value=[]):
            checks = production_checks(Path.cwd(), runtime)
        revocation_check = next(item for item in checks if item["label"] == "Candidate revocation state")
        self.assertEqual(revocation_check["status"], "FAIL")

    def test_release_manifest_cannot_keep_promotable_state_for_revoked_candidate(self):
        from evals import release as release_module

        environment = _environment("manifest-gate")
        candidate_binding = binding(environment)
        candidate = {"subject_git_sha": candidate_binding.subject_git_sha, "requested_model": "approved:model"}
        policy = release_module.load_model_policy(Path.cwd())
        runtime = SimpleNamespace(opencode_version="1.2.3", reported_model_id="approved:model", provider="approved", vision_support=True)
        split = {"corpus_fingerprint": "corpus", "held_out_fingerprint": "heldout", "corpus_identity": {"schema_version": "1.0", "sets": []}}

        class RevokedProvider:
            def status(self, exact_candidate):
                return CandidateRevocationStatus(exact_candidate, "d" * 64, 1, "REVOKED", ("CRITICAL_VULNERABILITY",), "e" * 64)

        with tempfile.TemporaryDirectory() as directory, \
             patch.object(release_module, "discover_runtime", return_value=runtime), \
             patch.object(release_module, "load_model_policy", return_value=policy), \
             patch.object(release_module, "split_manifest", return_value=split), \
             patch.object(release_module, "_candidate_spec_for_release", return_value=(candidate, candidate_binding.subject_git_sha)), \
             patch.object(release_module, "candidate_completeness", return_value=[]), \
             patch.object(release_module, "_load_records", return_value=({}, [])), \
             patch.object(release_module, "_load_prior_recertification_inputs", return_value=(None, {}, {}, None)), \
             patch.object(release_module, "derive_release_state", return_value=("PRODUCTION_CERTIFIED", [])), \
             patch.object(release_module, "_champion", return_value=(None, None, [])), \
             patch.object(release_module, "canonical_candidate_factors", return_value=candidate), \
             patch.object(release_module, "candidate_deployment_fingerprint", return_value=candidate_binding.deployment_fingerprint), \
             patch.object(release_module, "deployment_candidate_revocation_control", return_value=RevokedProvider()):
            manifest = release_module.build_release_manifest(
                Path(directory), requested_state="PRODUCTION_CERTIFIED", candidate_run_environment_identity_sha256=candidate_binding.run_environment_identity_sha256,
            )
        self.assertEqual(manifest["release_state"], "INTERNAL_VALIDATED")
        self.assertTrue(any("candidate has an active revocation" in item for item in manifest["blocking_reasons"]))

    def test_reference_status_is_candidate_specific_and_signed_rollout_contract_stays_valid(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active, fallback = _environment("identity-primary"), _environment("identity-fallback")
            policy = _initialize(root, active, rollback=fallback)
            _transition(root, policy, action="SET_STAGE", transition_id="open", stage="PILOT")
            status = ReferenceFileCandidateRevocationControl(root, key=KEY).status(binding(active))
            self.assertEqual(status.status, "CLEAR")
            self.assertEqual(rollout_policy_identity(read_json(root / ".k-slide-config" / "rollout-policy.json"), key=KEY, now=NOW), _state(root)["policy_identity"])
            Draft202012Validator(ROLLOUT_SCHEMA).validate(read_json(root / ".k-slide-config" / "rollout-state.json"))
            Draft202012Validator(ROLLOUT_SCHEMA).validate(read_json(root / ".k-slide-config" / "rollout-head.json"))


if __name__ == "__main__":
    unittest.main()
