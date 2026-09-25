from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator

from k_slide.cli import main as cli_main
from k_slide.environment import RunEnvironmentIdentity
from k_slide.ingest import prepare_run
from k_slide.io import atomic_write_json, read_json
from k_slide.rollout import (
    ReferenceFileRolloutControl,
    RolloutAdmission,
    RolloutCandidateBinding,
    RolloutControlError,
    apply_rollout_transition,
    build_rollout_policy,
    build_transition_command,
    deployment_rollout_control,
    initialize_reference_rollout_control,
    rollout_policy_identity,
    transition_reference_rollout_control,
    validate_rollout_admission,
)
from k_slide.state import RunPhase, load_state
from tests.reference_fixtures import reference_environment


KEY = b"ksa34-reference-authority-key-32-bytes-min"
PNG = b"\x89PNG\r\n\x1a\nsynthetic-ksa34-fixture"
NOW = datetime.now(timezone.utc).replace(microsecond=0)


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _environment(seed: str = "current") -> RunEnvironmentIdentity:
    return replace(reference_environment(f"ksa34-{seed}"), ocr_provider="none")


def _stages() -> dict[str, list[str]]:
    return {
        "NAMED_COHORT": ["alpha"],
        "PILOT": ["alpha", "beta"],
        "CANARY": ["alpha", "beta", "gamma"],
        "PHASED": ["alpha", "beta", "delta", "gamma"],
        "FULL": ["alpha", "beta", "delta", "gamma", "zeta"],
    }


def _policy(environment: RunEnvironmentIdentity, *, rollback: RunEnvironmentIdentity | None = None, now: datetime = NOW, revision: int = 1):
    return build_rollout_policy(
        policy_id="kslide-rollout-test",
        candidate=RolloutCandidateBinding.from_environment(environment),
        rollback_target=RolloutCandidateBinding.from_environment(rollback) if rollback else None,
        stage_cohorts=_stages(),
        issued_at=_timestamp(now - timedelta(minutes=1)),
        expires_at=_timestamp(now + timedelta(days=3)),
        key=KEY,
        policy_revision=revision,
    )


def _initialize(root: Path, environment: RunEnvironmentIdentity, *, rollback: RunEnvironmentIdentity | None = None, now: datetime = NOW):
    policy = _policy(environment, rollback=rollback, now=now)
    initialize_reference_rollout_control(root, policy=policy, key=KEY, now=now)
    return policy


def _transition(root: Path, policy: dict, *, action: str, transition_id: str, stage: str | None = None, target: RunEnvironmentIdentity | None = None, now: datetime = NOW):
    current = read_json(root / ".k-slide-config" / "rollout-state.json")["payload"]
    policy_identity = rollout_policy_identity(policy, key=KEY, now=now)
    command = build_transition_command(
        policy_identity=policy_identity,
        expected_revision=current["revision"],
        action=action,
        transition_id=transition_id,
        actor_ref="deployment_admin",
        target_stage=stage,
        target_candidate=RolloutCandidateBinding.from_environment(target) if target else None,
        key=KEY,
    )
    return transition_reference_rollout_control(root, command=command, key=KEY, now=now)


def _control(root: Path, cohort: str = "alpha", *, now: datetime = NOW):
    return ReferenceFileRolloutControl(root, key=KEY, cohort_id=cohort, now=now)


def _state(root: Path) -> dict:
    return read_json(root / ".k-slide-config" / "rollout-state.json")["payload"]


class KSA34RolloutTests(unittest.TestCase):
    def test_named_cohort_inclusion_and_exclusion_are_exact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            environment = _environment()
            policy = _initialize(root, environment)
            _transition(root, policy, action="SET_STAGE", transition_id="open-named", stage="NAMED_COHORT")
            self.assertEqual(_control(root, "alpha").admit(RolloutCandidateBinding.from_environment(environment)).status, "ADMITTED")
            denied = _control(root, "beta").admit(RolloutCandidateBinding.from_environment(environment))
            self.assertEqual((denied.status, denied.reason_code), ("DENIED", "COHORT_NOT_ADMITTED"))

    def test_stage_expansion_and_contraction_require_explicit_transitions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            environment = _environment()
            policy = _initialize(root, environment)
            _transition(root, policy, action="SET_STAGE", transition_id="named", stage="NAMED_COHORT")
            self.assertEqual(_state(root)["admitted_cohorts"], ["alpha"])
            _transition(root, policy, action="SET_STAGE", transition_id="pilot", stage="PILOT")
            self.assertEqual(_state(root)["admitted_cohorts"], ["alpha", "beta"])
            _transition(root, policy, action="SET_STAGE", transition_id="canary", stage="CANARY")
            _transition(root, policy, action="SET_STAGE", transition_id="phased", stage="PHASED")
            _transition(root, policy, action="SET_STAGE", transition_id="full", stage="FULL")
            self.assertEqual(_state(root)["stage"], "FULL")
            _transition(root, policy, action="SET_STAGE", transition_id="contract", stage="PILOT")
            self.assertEqual(_state(root)["admitted_cohorts"], ["alpha", "beta"])

    def test_immediate_disable_is_reversible_for_new_admissions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            environment = _environment()
            policy = _initialize(root, environment)
            _transition(root, policy, action="SET_STAGE", transition_id="open", stage="FULL")
            self.assertEqual(_control(root).admit(RolloutCandidateBinding.from_environment(environment)).status, "ADMITTED")
            _transition(root, policy, action="DISABLE", transition_id="kill")
            disabled = _control(root).admit(RolloutCandidateBinding.from_environment(environment))
            self.assertEqual((disabled.status, disabled.reason_code), ("DENIED", "ADMISSIONS_DISABLED"))
            self.assertEqual((_state(root)["stage"], _state(root)["admissions_enabled"], _state(root)["admitted_cohorts"]), ("DISABLED", False, []))
            _transition(root, policy, action="SET_STAGE", transition_id="reenable", stage="NAMED_COHORT")
            self.assertEqual(_control(root).admit(RolloutCandidateBinding.from_environment(environment)).status, "ADMITTED")

    def test_rollback_selects_only_the_previously_authorized_candidate_and_closes_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            current, prior = _environment("current"), _environment("prior")
            policy = _initialize(root, current, rollback=prior)
            _transition(root, policy, action="SET_STAGE", transition_id="open", stage="PILOT")
            _transition(root, policy, action="ROLLBACK", transition_id="rollback", target=prior)
            state = _state(root)
            self.assertEqual(state["candidate_binding"], RolloutCandidateBinding.from_environment(prior).as_dict())
            self.assertEqual((state["stage"], state["admissions_enabled"]), ("DISABLED", False))
            with self.assertRaises(RolloutControlError):
                _control(root).admit(RolloutCandidateBinding.from_environment(current))
            _transition(root, policy, action="SET_STAGE", transition_id="prior-pilot", stage="PILOT")
            self.assertEqual(_control(root).admit(RolloutCandidateBinding.from_environment(prior)).status, "ADMITTED")
            _transition(root, policy, action="DISABLE", transition_id="stop-prior")
            _transition(root, policy, action="RESTORE_CANDIDATE", transition_id="restore-current", target=current)
            self.assertEqual(_state(root)["candidate_binding"], RolloutCandidateBinding.from_environment(current).as_dict())
            with self.assertRaises(RolloutControlError):
                _control(root).admit(RolloutCandidateBinding.from_environment(prior))

    def test_rollback_target_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            current, prior, wrong = _environment("current"), _environment("prior"), _environment("wrong")
            policy = _initialize(root, current, rollback=prior)
            state = read_json(root / ".k-slide-config" / "rollout-state.json")
            head = read_json(root / ".k-slide-config" / "rollout-head.json")
            policy_identity = rollout_policy_identity(policy, key=KEY, now=NOW)
            command = build_transition_command(
                policy_identity=policy_identity,
                expected_revision=state["payload"]["revision"],
                action="ROLLBACK",
                transition_id="bad-rollback",
                actor_ref="deployment_admin",
                target_stage=None,
                target_candidate=RolloutCandidateBinding.from_environment(wrong),
                key=KEY,
            )
            with self.assertRaisesRegex(RolloutControlError, "rollback target"):
                apply_rollout_transition(policy=policy, state=state, head=head, command=command, key=KEY, now=NOW)

    def test_restart_reloads_authoritative_policy_state_and_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            environment = _environment()
            policy = _initialize(root, environment)
            _transition(root, policy, action="SET_STAGE", transition_id="open", stage="CANARY")
            restarted = _control(root)
            admitted = restarted.admit(RolloutCandidateBinding.from_environment(environment))
            self.assertEqual((admitted.status, admitted.stage, admitted.state_revision), ("ADMITTED", "CANARY", 2))
            _transition(root, policy, action="DISABLE", transition_id="disabled")
            self.assertEqual(_control(root).admit(RolloutCandidateBinding.from_environment(environment)).reason_code, "ADMISSIONS_DISABLED")

    def test_expansion_and_contraction_write_signed_actor_and_time_history(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            environment = _environment()
            policy = _initialize(root, environment)
            _transition(root, policy, action="SET_STAGE", transition_id="open-named", stage="NAMED_COHORT")
            _transition(root, policy, action="SET_STAGE", transition_id="expand-pilot", stage="PILOT")
            _transition(root, policy, action="SET_STAGE", transition_id="contract-named", stage="NAMED_COHORT")
            history_dir = root / ".k-slide-config" / "rollout-history"
            history = [read_json(history_dir / f"{revision:010d}.json")["payload"] for revision in range(1, 5)]
            self.assertEqual([item["transition_action"] for item in history], ["INITIALIZE", "SET_STAGE", "SET_STAGE", "SET_STAGE"])
            self.assertEqual([item["actor_ref"] for item in history], ["deployment_authority", "deployment_admin", "deployment_admin", "deployment_admin"])
            self.assertEqual([item["transition_id"] for item in history], ["initial", "open-named", "expand-pilot", "contract-named"])
            self.assertTrue(all(item["transitioned_at"] == _timestamp(NOW) for item in history))
            self.assertEqual(_control(root).admit(RolloutCandidateBinding.from_environment(environment)).stage, "NAMED_COHORT")

    def test_expired_policy_is_stale(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            environment = _environment()
            policy = _initialize(root, environment)
            _transition(root, policy, action="SET_STAGE", transition_id="open", stage="PILOT")
            expired = NOW + timedelta(days=4)
            with self.assertRaisesRegex(RolloutControlError, "stale"):
                _control(root, now=expired).admit(RolloutCandidateBinding.from_environment(environment))

    def test_unauthorized_policy_or_state_mutation_fails_signature_check(self):
        for filename, mutation in (
            ("rollout-policy.json", lambda value: value["payload"].update(policy_revision=2)),
            ("rollout-state.json", lambda value: value["payload"].update(stage="FULL", admissions_enabled=True, admitted_cohorts=["alpha"])),
        ):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                environment = _environment()
                _initialize(root, environment)
                path = root / ".k-slide-config" / filename
                value = read_json(path)
                mutation(value)
                atomic_write_json(path, value)
                with self.assertRaisesRegex(RolloutControlError, "unauthorized or modified"):
                    _control(root).admit(RolloutCandidateBinding.from_environment(environment))

    def test_unauthorized_history_mutation_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            environment = _environment()
            policy = _initialize(root, environment)
            _transition(root, policy, action="SET_STAGE", transition_id="open", stage="PILOT")
            path = root / ".k-slide-config" / "rollout-history" / "0000000002.json"
            value = read_json(path)
            value["payload"].update(actor_ref="unapproved_actor")
            atomic_write_json(path, value)
            with self.assertRaisesRegex(RolloutControlError, "unauthorized"):
                _control(root).admit(RolloutCandidateBinding.from_environment(environment))

    def test_malformed_missing_control_documents_and_factory_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            environment = _environment()
            _initialize(root, environment)
            atomic_write_json(root / ".k-slide-config" / "rollout-policy.json", {"schema_version": "1.0"})
            with self.assertRaises(RolloutControlError):
                _control(root).admit(RolloutCandidateBinding.from_environment(environment))
            with patch.dict(os.environ, {"KSLIDE_ROLLOUT_CONTROL_FACTORY": "not-a-valid-factory"}):
                with self.assertRaises(RolloutControlError):
                    deployment_rollout_control()

    def test_candidate_mismatch_policy_drift_and_replayed_state_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            environment, other = _environment("current"), _environment("other")
            policy = _initialize(root, environment)
            initial_state = read_json(root / ".k-slide-config" / "rollout-state.json")
            _transition(root, policy, action="SET_STAGE", transition_id="open", stage="PILOT")
            with self.assertRaises(RolloutControlError):
                _control(root).admit(RolloutCandidateBinding.from_environment(other))

            drifted_policy = _policy(environment, now=NOW, revision=2)
            atomic_write_json(root / ".k-slide-config" / "rollout-policy.json", drifted_policy)
            with self.assertRaisesRegex(RolloutControlError, "policy identity"):
                _control(root).admit(RolloutCandidateBinding.from_environment(environment))

            # Restoring the earlier policy while replaying an older signed state
            # cannot roll the monotonic head back with it.
            atomic_write_json(root / ".k-slide-config" / "rollout-policy.json", policy)
            state_path = root / ".k-slide-config" / "rollout-state.json"
            atomic_write_json(state_path, initial_state)
            with self.assertRaisesRegex(RolloutControlError, "stale or replayed"):
                _control(root).admit(RolloutCandidateBinding.from_environment(environment))

    def test_managed_candidate_with_missing_rollout_authority_fails_before_source_access(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            missing_source = root / "must-not-be-read.png"
            with patch.dict(os.environ, {"KSLIDE_ROLLOUT_CONTROL_FACTORY": ""}):
                run = prepare_run(
                    root,
                    explicit_paths=[str(missing_source)],
                    environment_identity=_environment(),
                    perform_processing=False,
                )
            receipt = json.loads((run / "admission" / "ROLLOUT_ADMISSION.json").read_text(encoding="utf-8"))
            self.assertEqual((receipt["status"], receipt["reason_code"]), ("REJECTED", "AUTHORITY_UNAVAILABLE"))
            self.assertEqual(load_state(run).phase, RunPhase.FAILED_INPUT)
            self.assertFalse(missing_source.exists())
            self.assertFalse(any((run / "inputs").iterdir()))

    def test_policy_schema_and_durable_receipt_are_source_free(self):
        schema = json.loads(Path("schemas/rollout-control.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        environment = _environment()
        policy = _policy(environment)
        Draft202012Validator(schema).validate(policy)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_reference_rollout_control(root, policy=policy, key=KEY, now=NOW)
            Draft202012Validator(schema).validate(read_json(root / ".k-slide-config" / "rollout-state.json"))
            Draft202012Validator(schema).validate(read_json(root / ".k-slide-config" / "rollout-head.json"))
            _transition(root, policy, action="SET_STAGE", transition_id="open", stage="PILOT")
            receipt = _control(root).admit(RolloutCandidateBinding.from_environment(environment))
            Draft202012Validator(schema).validate(receipt.as_dict())
            encoded = json.dumps(receipt.as_dict())
            self.assertNotIn("source content", encoded)
            self.assertNotIn("prompt", encoded)

    def test_admission_requires_exact_policy_and_state_identity(self):
        candidate = RolloutCandidateBinding.from_environment(_environment())
        malformed = RolloutAdmission("ADMITTED", "COHORT_ADMITTED", candidate, cohort_id="alpha")
        with self.assertRaisesRegex(RolloutControlError, "missing its authorized policy or state identity"):
            validate_rollout_admission(malformed, candidate)

    def test_inflight_run_keeps_its_bound_identity_when_new_admissions_are_disabled(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "slide.png"
            source.write_bytes(PNG)
            environment = _environment()
            policy = _initialize(root, environment)
            _transition(root, policy, action="SET_STAGE", transition_id="open", stage="PILOT")
            run = prepare_run(root, explicit_paths=[str(source)], perform_processing=False, environment_identity=environment, rollout_control=_control(root))
            admission_path = run / "admission" / "ROLLOUT_ADMISSION.json"
            admission = json.loads(admission_path.read_text(encoding="utf-8"))
            self.assertEqual(admission["status"], "ADMITTED")
            self.assertEqual(admission["rollback_rule"], "BOUND_RUNS_COMPLETE_OR_STOP_ON_IDENTITY_MISMATCH_V1")
            execution = json.loads((run / "EXECUTION_JOB.json").read_text(encoding="utf-8"))
            self.assertEqual(execution["environment_identity"], environment.as_dict())
            _transition(root, policy, action="DISABLE", transition_id="kill")
            self.assertEqual(json.loads(admission_path.read_text(encoding="utf-8")), admission)
            self.assertEqual(load_state(run).phase, RunPhase.INPUT_VALIDATED)

    def test_cli_and_opencode_host_invocation_share_the_engine_rollout_gate(self):
        environment = _environment()
        for host_surface in ("cli", "opencode"):
            with self.subTest(host_surface=host_surface), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                _initialize(root, environment)
                policy = read_json(root / ".k-slide-config" / "rollout-policy.json")
                _transition(root, policy, action="SET_STAGE", transition_id="open", stage="PILOT")
                source = root / "slide.png"
                source.write_bytes(PNG)
                control = _control(root)
                original = prepare_run

                def prepared(workspace: Path, **kwargs):
                    kwargs["environment_identity"] = environment
                    kwargs["perform_processing"] = False
                    kwargs["rollout_control"] = control
                    return original(workspace, **kwargs)

                if host_surface == "cli":
                    args = ["prepare", "--root", str(root), "--json", str(source)]
                else:
                    invocation = {
                        "schema_version": "1.0",
                        "adapter_version": "1.0",
                        "input_refs": [{"source_kind": "workspace_file", "logical_name": "slide.png", "locator": source.as_uri()}],
                    }
                    args = ["prepare", "--root", str(root), "--host-inputs-json", json.dumps(invocation), "--json"]
                output = io.StringIO()
                with patch("k_slide.cli.prepare_run", side_effect=prepared), redirect_stdout(output):
                    code = cli_main(args)
                self.assertEqual(code, 0, output.getvalue())
                result = json.loads(output.getvalue())
                run = root / ".k-slide-runs" / result["run_id"]
                admission = json.loads((run / "admission" / "ROLLOUT_ADMISSION.json").read_text(encoding="utf-8"))
                self.assertEqual((admission["status"], admission["stage"], admission["cohort_id"]), ("ADMITTED", "PILOT", "alpha"))


if __name__ == "__main__":
    unittest.main()
