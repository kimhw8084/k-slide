from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from k_slide.authentication import CompanyServiceRequest, authorized_company_service_call
from k_slide.certification import candidate_deployment_fingerprint
from k_slide.egress_policy import (
    EGRESS_CAPABILITY_DURABLE_JOB_CONTROL,
    EGRESS_CAPABILITY_INFERENCE_ROUTE,
    EGRESS_CAPABILITY_NON_CONTENT_TELEMETRY,
    EGRESS_CAPABILITY_SCOPED_STORAGE,
    EGRESS_DATA_CLASS_NON_CONTENT,
    EGRESS_PURPOSE_INFERENCE,
    EGRESS_PURPOSE_JOB_CONTROL,
    EGRESS_PURPOSE_STORAGE,
    EGRESS_PURPOSE_TELEMETRY,
    EgressPolicy,
    egress_policy_hash_for_mapping,
    egress_policy_identity_for_mapping,
    load_egress_policy,
)
from k_slide.environment import ensure_configured_policy_matches_environment
from k_slide.errors import ErrorCode, KSlideError
from k_slide.execution import ExecutionController, ExecutionProfile, WorkspaceRunStore, new_execution_job
from tests.reference_fixtures import reference_environment


def _policy_mapping(*, inference_route: str = "route-v1", service_suffix: str = "v1") -> dict[str, object]:
    capabilities = [
        {"capability_class": EGRESS_CAPABILITY_INFERENCE_ROUTE, "purpose": EGRESS_PURPOSE_INFERENCE, "service_identity": f"inference-service-{service_suffix}", "route_identity": inference_route, "data_class": "source_content"},
        {"capability_class": EGRESS_CAPABILITY_DURABLE_JOB_CONTROL, "purpose": EGRESS_PURPOSE_JOB_CONTROL, "service_identity": f"job-service-{service_suffix}", "route_identity": None, "data_class": "operational_metadata"},
        {"capability_class": EGRESS_CAPABILITY_SCOPED_STORAGE, "purpose": EGRESS_PURPOSE_STORAGE, "service_identity": f"storage-service-{service_suffix}", "route_identity": None, "data_class": "source_content"},
        {"capability_class": EGRESS_CAPABILITY_NON_CONTENT_TELEMETRY, "purpose": EGRESS_PURPOSE_TELEMETRY, "service_identity": f"telemetry-service-{service_suffix}", "route_identity": None, "data_class": EGRESS_DATA_CLASS_NON_CONTENT},
    ]
    version = "2026.09.18"
    policy_hash = egress_policy_hash_for_mapping(policy_version=version, capabilities=capabilities)
    return {
        "schema_version": "1.0",
        "policy_version": version,
        "policy_hash": policy_hash,
        "policy_identity": egress_policy_identity_for_mapping(policy_version=version, policy_hash=policy_hash),
        "default_action": "deny",
        "capabilities": capabilities,
    }


class _Transport:
    def __init__(self) -> None:
        self.calls: list[CompanyServiceRequest] = []

    def call(self, request: CompanyServiceRequest, *, access_key: str) -> object:
        self.calls.append(request)
        return {"accepted": True}


class DefaultDenyEgressTests(unittest.TestCase):
    def test_missing_and_malformed_policy_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(KSlideError) as missing:
                load_egress_policy(root)
            self.assertEqual(missing.exception.code, ErrorCode.EGRESS_POLICY_INVALID)
            (root / ".k-slide-config").mkdir()
            (root / ".k-slide-config" / "egress-policy.json").write_text(json.dumps({"default_action": "allow"}), encoding="utf-8")
            with self.assertRaises(KSlideError) as malformed:
                load_egress_policy(root)
            self.assertEqual(malformed.exception.code, ErrorCode.EGRESS_POLICY_INVALID)

    def test_policy_identities_reject_urls_and_content_markers(self) -> None:
        policy = _policy_mapping()
        policy["capabilities"][0]["route_identity"] = "https://attacker.invalid/route"
        with self.assertRaises(KSlideError):
            EgressPolicy.from_mapping(policy)
        policy = _policy_mapping()
        policy["capabilities"][0]["service_identity"] = "source_text-derived-service"
        with self.assertRaises(KSlideError):
            EgressPolicy.from_mapping(policy)

    def test_unknown_capability_and_wrong_route_or_service_are_denied(self) -> None:
        policy = EgressPolicy.from_mapping(_policy_mapping())
        for args in (
            ("unknown", "purpose"),
            (EGRESS_CAPABILITY_INFERENCE_ROUTE, EGRESS_PURPOSE_INFERENCE, "wrong-route", None),
            (EGRESS_CAPABILITY_SCOPED_STORAGE, EGRESS_PURPOSE_STORAGE, None, "wrong-service"),
        ):
            with self.subTest(args=args), self.assertRaises(KSlideError) as raised:
                policy.authorize(*args[:2], route_identity=args[2] if len(args) > 2 else None, service_identity=args[3] if len(args) > 3 else None)
            self.assertIn(raised.exception.code, {ErrorCode.EGRESS_CAPABILITY_DENIED, ErrorCode.EGRESS_ROUTE_MISMATCH})

    def test_all_four_explicit_capabilities_allow_only_their_closed_purpose(self) -> None:
        policy = EgressPolicy.from_mapping(_policy_mapping())
        self.assertEqual(policy.authorize(EGRESS_CAPABILITY_INFERENCE_ROUTE, EGRESS_PURPOSE_INFERENCE, route_identity="route-v1", service_identity="inference-service-v1", data_class="source_content").service_identity, "inference-service-v1")
        self.assertEqual(policy.authorize(EGRESS_CAPABILITY_DURABLE_JOB_CONTROL, EGRESS_PURPOSE_JOB_CONTROL, service_identity="job-service-v1", data_class="operational_metadata").service_identity, "job-service-v1")
        self.assertEqual(policy.authorize(EGRESS_CAPABILITY_SCOPED_STORAGE, EGRESS_PURPOSE_STORAGE, service_identity="storage-service-v1", data_class="source_content").service_identity, "storage-service-v1")
        self.assertEqual(policy.authorize(EGRESS_CAPABILITY_NON_CONTENT_TELEMETRY, EGRESS_PURPOSE_TELEMETRY, service_identity="telemetry-service-v1", data_class=EGRESS_DATA_CLASS_NON_CONTENT).service_identity, "telemetry-service-v1")
        with self.assertRaises(KSlideError):
            policy.authorize(EGRESS_CAPABILITY_NON_CONTENT_TELEMETRY, EGRESS_PURPOSE_TELEMETRY, data_class="source_content")

    def test_transport_is_not_called_when_egress_admission_or_request_controls_fail(self) -> None:
        policy = EgressPolicy.from_mapping(_policy_mapping())
        transport = _Transport()
        request = CompanyServiceRequest("approved.lookup", {"ordinary": "value"})
        with patch.dict(os.environ, {"AccessKey": "ephemeral-test-key"}, clear=True):
            authorized_company_service_call(transport, request, egress_policy=policy, capability_class=EGRESS_CAPABILITY_SCOPED_STORAGE, purpose=EGRESS_PURPOSE_STORAGE, service_identity="storage-service-v1", data_class="source_content")
            with self.assertRaises(KSlideError):
                authorized_company_service_call(transport, request, egress_policy=policy, capability_class=EGRESS_CAPABILITY_SCOPED_STORAGE, purpose=EGRESS_PURPOSE_STORAGE, service_identity="attacker-service", data_class="source_content")
        self.assertEqual(len(transport.calls), 1)
        with patch.dict(os.environ, {"AccessKey": "ephemeral-test-key"}, clear=True):
            with self.assertRaises(KSlideError):
                authorized_company_service_call(
                    transport,
                    CompanyServiceRequest("telemetry.emit", {"source_text": "untrusted source"}),
                    egress_policy=policy,
                    capability_class=EGRESS_CAPABILITY_NON_CONTENT_TELEMETRY,
                    purpose=EGRESS_PURPOSE_TELEMETRY,
                    service_identity="telemetry-service-v1",
                    data_class=EGRESS_DATA_CLASS_NON_CONTENT,
                )
        self.assertEqual(len(transport.calls), 1)
        with patch.dict(os.environ, {"AccessKey": "ephemeral-test-key"}, clear=True), self.assertRaises(KSlideError):
            authorized_company_service_call(
                transport,
                request,
                egress_policy=None,
                capability_class=EGRESS_CAPABILITY_SCOPED_STORAGE,
                purpose=EGRESS_PURPOSE_STORAGE,
                service_identity="storage-service-v1",
                data_class="source_content",
            )
        self.assertEqual(len(transport.calls), 1)
        with patch.dict(os.environ, {"AccessKey": "ephemeral-test-key"}, clear=True), self.assertRaises(KSlideError):
            authorized_company_service_call(
                transport,
                request,
                egress_policy=EgressPolicy.reference(),
                capability_class=EGRESS_CAPABILITY_SCOPED_STORAGE,
                purpose=EGRESS_PURPOSE_STORAGE,
                service_identity="reference-adapter",
                data_class="source_content",
            )
        self.assertEqual(len(transport.calls), 1)
        for field in ("endpoint", "proxy", "provider", "base_url", "redirect", "transport", "fallback", "model"):
            with self.assertRaises(KSlideError):
                CompanyServiceRequest("approved.lookup", {field: "https://attacker.invalid"})

    def test_policy_source_is_not_business_content_and_is_bound_to_candidate_identity(self) -> None:
        policy = _policy_mapping()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".k-slide-config").mkdir()
            (root / ".k-slide-config" / "egress-policy.json").write_text(json.dumps(policy), encoding="utf-8")
            from k_slide.certification import resolve_candidate_spec

            candidate = resolve_candidate_spec({"candidate_spec_version": "1.1", "network_egress": "default_deny"}, root=root)
            self.assertEqual(candidate["egress_policy_identity"], policy["policy_identity"])
            first = candidate_deployment_fingerprint(candidate)
            changed = dict(candidate)
            changed["egress_policy_identity"] = hashlib.sha256(b"drifted-policy").hexdigest()
            self.assertNotEqual(first, candidate_deployment_fingerprint(changed))

    def test_resume_refuses_egress_identity_drift_before_mutation(self) -> None:
        environment = reference_environment()
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceRunStore(Path(directory) / "run")
            job = new_execution_job("run-egress-drift", profile=ExecutionProfile.WORKSPACE_LOCAL, scope_ref="workspace", store_ref="workspace-store", environment_identity=environment)
            store.create(job)
            drifted = replace(environment, egress_policy_hash="a" * 64, egress_policy_identity="b" * 64)
            with self.assertRaises(KSlideError) as raised:
                ExecutionController(store, environment_identity=drifted).run_step(job.job_id, operation_id="op-egress-drift", step=lambda checkpoint, operation_id: None)
            self.assertEqual(raised.exception.code, ErrorCode.EXECUTION_ENVIRONMENT_MISMATCH)
            unchanged = store.load(job.job_id)
            self.assertEqual(unchanged.revision, 0)
            self.assertEqual(unchanged.lifecycle.value, "QUEUED")


if __name__ == "__main__":
    unittest.main()
