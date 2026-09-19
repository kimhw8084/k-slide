from __future__ import annotations

import base64
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from k_slide.certification import candidate_deployment_fingerprint
from k_slide.classification_policy import (
    DEFAULT_CLASSIFICATION,
    InferenceDataUsePolicy,
    policy_hash_for_mapping,
    policy_identity_for_mapping,
)
from k_slide.errors import ErrorCode, KSlideError
from k_slide.environment import RunEnvironmentIdentity
from k_slide.host_adapter import HostInputReference, HostInvocation
from k_slide.ingest import prepare_run
from k_slide.evidence_ir import load_evidence
from k_slide.queue import load_queue
from k_slide.execution import sync_workspace_execution
from k_slide.state import load_state
from tests.reference_fixtures import reference_environment


PNG = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=")


def policy(route: str = "gemma-route-test", rules: dict[str, bool] | None = None, version: str = "2026.09.19") -> InferenceDataUsePolicy:
    rules = rules or {DEFAULT_CLASSIFICATION: True, "restricted": False, "internal_only": True}
    digest = policy_hash_for_mapping(inference_route_identity=route, policy_version=version, classification_rules=rules)
    identity = policy_identity_for_mapping(inference_route_identity=route, policy_version=version, policy_hash=digest)
    return InferenceDataUsePolicy.from_mapping(
        {
            "schema_version": "1.0",
            "inference_route_identity": route,
            "policy_version": version,
            "policy_hash": digest,
            "policy_identity": identity,
            "classification_rules": rules,
        }
    )


def environment_for(value: InferenceDataUsePolicy) -> RunEnvironmentIdentity:
    return replace(
        reference_environment(),
        inference_route_identity=value.inference_route_identity,
        inference_data_policy_version=value.policy_version,
        inference_data_policy_hash=value.policy_hash,
        inference_data_policy_identity=value.policy_identity,
    )


class ClassificationAdmissionTests(unittest.TestCase):
    def _write_policy(self, root: Path, value: InferenceDataUsePolicy | dict[str, object]) -> None:
        config = root / ".k-slide-config"
        config.mkdir(exist_ok=True)
        payload = value.as_dict() if isinstance(value, InferenceDataUsePolicy) else value
        (config / "inference-data-use-policy.json").write_text(json.dumps(payload), encoding="utf-8")

    def _source(self, root: Path, name: str = "source.png") -> Path:
        source = root / name
        source.write_bytes(PNG)
        return source

    def test_missing_label_uses_company_confidential_without_normalizing_the_default(self) -> None:
        configured = policy(rules={DEFAULT_CLASSIFICATION: True})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_policy(root, configured)
            self.assertEqual(HostInputReference("workspace_file", "source.png", "source.png").classification, DEFAULT_CLASSIFICATION)
            run = prepare_run(root, explicit_paths=[str(self._source(root))], environment_identity=environment_for(configured))
            manifest = json.loads((run / "RUN_MANIFEST.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["inputs"][0]["classification"], DEFAULT_CLASSIFICATION)
            self.assertEqual(manifest["classification_admission"]["policy_identity"], configured.policy_identity)

    def test_allowed_and_denied_labels_are_exact_and_each_document_is_independent(self) -> None:
        configured = policy()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_policy(root, configured)
            first = self._source(root, "allowed.png")
            second = self._source(root, "denied.png")
            run = prepare_run(
                root,
                host_input_refs=(
                    HostInputReference("workspace_file", first.name, first.as_uri(), "internal_only"),
                    HostInputReference("workspace_file", second.name, second.as_uri(), "restricted"),
                ),
                approved_root=root,
                environment_identity=environment_for(configured),
            )
            state = load_state(run)
            self.assertEqual(state.error_code, ErrorCode.CLASSIFICATION_NOT_APPROVED.value)
            self.assertEqual(state.classification_admission["classifications"], ["internal_only", "restricted"])
            self.assertFalse((run / "RUN_MANIFEST.json").exists())
            self.assertFalse(list((run / "inputs").glob("*")))
            persisted = "\n".join(path.read_text(encoding="utf-8", errors="ignore") for path in run.rglob("*") if path.is_file())
            self.assertNotIn("allowed.png", persisted)
            self.assertNotIn("denied.png", persisted)
            self.assertIn("restricted", persisted)  # exact classification metadata is safe and auditable.
            self.assertNotIn(PNG.decode("latin1"), persisted)
            self.assertFalse(any(path.name.endswith(".json") and "evidence" in str(path) for path in run.rglob("*")))

    def test_unknown_label_malformed_policy_and_route_or_policy_drift_fail_closed(self) -> None:
        configured = policy(rules={DEFAULT_CLASSIFICATION: True})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_policy(root, configured)
            source = self._source(root)
            unknown = prepare_run(
                root,
                host_input_refs=(HostInputReference("workspace_file", source.name, source.as_uri(), "never_declared"),),
                approved_root=root,
                environment_identity=environment_for(configured),
            )
            self.assertEqual(load_state(unknown).error_code, ErrorCode.CLASSIFICATION_UNKNOWN.value)
            malformed_root = Path(tempfile.mkdtemp())
            try:
                (malformed_root / ".k-slide-config").mkdir()
                malformed = configured.as_dict()
                malformed["policy_hash"] = "0" * 64
                (malformed_root / ".k-slide-config" / "inference-data-use-policy.json").write_text(json.dumps(malformed), encoding="utf-8")
                malformed_run = prepare_run(malformed_root, explicit_paths=[str(self._source(malformed_root))], environment_identity=environment_for(configured))
                self.assertEqual(load_state(malformed_run).error_code, ErrorCode.CLASSIFICATION_POLICY_INVALID.value)
            finally:
                for path in sorted(malformed_root.rglob("*"), reverse=True):
                    if path.is_file() or path.is_symlink():
                        path.unlink()
                    elif path.is_dir():
                        path.rmdir()
                malformed_root.rmdir()
            mismatched = replace(environment_for(configured), inference_route_identity="different-route")
            mismatched_run = prepare_run(root, explicit_paths=[str(source)], environment_identity=mismatched)
            self.assertEqual(load_state(mismatched_run).error_code, ErrorCode.CLASSIFICATION_POLICY_ROUTE_MISMATCH.value)
            drifted = replace(environment_for(configured), inference_data_policy_identity="f" * 64)
            drifted_run = prepare_run(root, explicit_paths=[str(source)], environment_identity=drifted)
            self.assertEqual(load_state(drifted_run).error_code, ErrorCode.CLASSIFICATION_POLICY_IDENTITY_MISMATCH.value)

    def test_authoritative_host_metadata_is_versioned_but_tool_supplied_unknown_fields_do_not_change_it(self) -> None:
        payload = {
            "schema_version": "1.0",
            "adapter_version": "1.0",
            "input_refs": [{"source_kind": "workspace_file", "logical_name": "a.png", "locator": "/private/a.png", "classification": "internal_only"}],
        }
        invocation = HostInvocation.from_json(json.dumps(payload))
        self.assertEqual(invocation.input_refs[0].classification, "internal_only")
        self.assertEqual(invocation.input_refs[0].locator, "/private/a.png")

    def test_candidate_fingerprint_changes_for_route_or_exact_policy_identity(self) -> None:
        first = policy("route-a")
        second = policy("route-b")
        base = {"inference_route_identity": first.inference_route_identity, "inference_data_use_policy": first.as_dict()}
        self.assertNotEqual(candidate_deployment_fingerprint(base), candidate_deployment_fingerprint({**base, "inference_route_identity": second.inference_route_identity, "inference_data_use_policy": second.as_dict()}))
        changed_policy = policy("route-a", version="2026.09.20")
        self.assertNotEqual(candidate_deployment_fingerprint(base), candidate_deployment_fingerprint({**base, "inference_data_use_policy": changed_policy.as_dict()}))

    def test_allowed_exact_classification_reaches_engine_evidence_without_reinterpretation(self) -> None:
        configured = policy(rules={"internal_only": True})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_policy(root, configured)
            source = self._source(root)
            run = prepare_run(
                root,
                host_input_refs=(HostInputReference("workspace_file", source.name, source.as_uri(), "internal_only"),),
                approved_root=root,
                perform_processing=True,
                environment_identity=environment_for(configured),
            )
            unit = load_queue(run).work_units[0]
            evidence = load_evidence(run, unit.work_unit_id)
            self.assertEqual(evidence.source["classification"], "internal_only")

    def test_policy_drift_blocks_resume_before_checkpoint_mutation(self) -> None:
        configured = policy(rules={DEFAULT_CLASSIFICATION: True})
        changed = policy(configured.inference_route_identity, rules={DEFAULT_CLASSIFICATION: True, "internal_only": True}, version="2026.09.20")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_policy(root, configured)
            run = prepare_run(root, explicit_paths=[str(self._source(root))], environment_identity=environment_for(configured))
            before = (run / "EXECUTION_JOB.json").read_bytes()
            self._write_policy(root, changed)
            with self.assertRaises(KSlideError) as raised:
                sync_workspace_execution(run, environment_identity=environment_for(configured))
            self.assertEqual(raised.exception.code, ErrorCode.EXECUTION_ENVIRONMENT_MISMATCH)
            self.assertEqual(before, (run / "EXECUTION_JOB.json").read_bytes())


if __name__ == "__main__":
    unittest.main()
