from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

from k_slide.authentication import (
    CompanyServiceAuthenticationRejected,
    CompanyServiceRequest,
    authenticated_company_service_call,
    reference_company_service_call,
)
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
)
from k_slide.errors import ErrorCode, KSlideError
from k_slide.execution import (
    DurableTestRunStore,
    ExecutionProfile,
    FailureClass,
    WorkspaceRunStore,
    classify_operational_failure,
    execution_metadata,
    new_execution_job,
)
from k_slide.host_adapter import authenticated_host_service_call
from k_slide.paas import authenticated_paas_service_call
from k_slide.production import production_checks
from tests.reference_fixtures import reference_environment


def _deployment_policy() -> EgressPolicy:
    capabilities = [
        {
            "capability_class": EGRESS_CAPABILITY_INFERENCE_ROUTE,
            "purpose": EGRESS_PURPOSE_INFERENCE,
            "service_identity": "inference-service-v1",
            "route_identity": "route-v1",
            "data_class": "source_content",
        },
        {
            "capability_class": EGRESS_CAPABILITY_DURABLE_JOB_CONTROL,
            "purpose": EGRESS_PURPOSE_JOB_CONTROL,
            "service_identity": "job-service-v1",
            "route_identity": None,
            "data_class": "operational_metadata",
        },
        {
            "capability_class": EGRESS_CAPABILITY_SCOPED_STORAGE,
            "purpose": EGRESS_PURPOSE_STORAGE,
            "service_identity": "storage-service-v1",
            "route_identity": None,
            "data_class": "source_content",
        },
        {
            "capability_class": EGRESS_CAPABILITY_NON_CONTENT_TELEMETRY,
            "purpose": EGRESS_PURPOSE_TELEMETRY,
            "service_identity": "telemetry-service-v1",
            "route_identity": None,
            "data_class": EGRESS_DATA_CLASS_NON_CONTENT,
        },
    ]
    version = "2026.09.18"
    policy_hash = egress_policy_hash_for_mapping(policy_version=version, capabilities=capabilities)
    return EgressPolicy.from_mapping(
        {
            "schema_version": "1.0",
            "policy_version": version,
            "policy_hash": policy_hash,
            "policy_identity": egress_policy_identity_for_mapping(policy_version=version, policy_hash=policy_hash),
            "default_action": "deny",
            "capabilities": capabilities,
        }
    )


@dataclass(frozen=True)
class _CapturedCall:
    request: CompanyServiceRequest
    access_key: str


class _RawRejection(CompanyServiceAuthenticationRejected):
    def __init__(self, marker: str) -> None:
        self.marker = marker
        super().__init__()

    def __str__(self) -> str:
        return f"adapter rejected credential {self.marker}"


class _ReferenceTransport:
    """Deterministic adapter with an explicit secret-only capture slot."""

    def __init__(self, *, rejection: Exception | None = None, response: object | None = None) -> None:
        self.calls: list[_CapturedCall] = []
        self.rejection = rejection
        self.response = response

    def call(self, request: CompanyServiceRequest, *, access_key: str) -> object:
        self.calls.append(_CapturedCall(request, access_key))
        if self.rejection is not None:
            raise self.rejection
        if self.response is not None:
            return self.response
        return {
            "accepted": True,
            "operation": request.operation,
            "ordinary_data": ["a", "accepted", "request", "/", "   ", "quotes=\"single'"],
        }


class KSA14AuthenticationTransportTests(unittest.TestCase):
    CANARY = 'opaque synthetic canary ::,;="\' / spaces'

    def _assert_absent(self, needle: str, value: object) -> None:
        serialized = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
        # Keep failure diagnostics bounded and never include the credential.
        self.assertFalse(needle in serialized, "synthetic credential was present in a bounded output")

    def _request(self) -> CompanyServiceRequest:
        return CompanyServiceRequest(
            "approved.lookup",
            {"model_packet": {"messages": ["synthetic ordinary request"]}, "request_ref": "request-001"},
        )

    def _call(self, transport: _ReferenceTransport, request: CompanyServiceRequest | None = None) -> object:
        return reference_company_service_call(transport, request or self._request())

    def test_process_access_key_is_the_only_runtime_credential_source(self) -> None:
        transport = _ReferenceTransport()
        with patch.dict(os.environ, {"AccessKey": self.CANARY, "ACCESS_KEY": "wrong-alias", "KSLIDE_ACCESS_KEY": "wrong-alias"}, clear=True):
            self._call(transport)
        self.assertTrue(bool(transport.calls), "reference adapter was not called")
        self.assertTrue(transport.calls[0].access_key == self.CANARY, "process AccessKey was not passed through the secret slot")

        missing_transport = _ReferenceTransport()
        with patch.dict(os.environ, {"ACCESS_KEY": "wrong-alias", "KSLIDE_ACCESS_KEY": "wrong-alias"}, clear=True):
            with self.assertRaises(KSlideError) as raised:
                self._call(missing_transport)
        self.assertEqual(raised.exception.code, ErrorCode.AUTHENTICATION_FAILED)
        self.assertEqual(len(missing_transport.calls), 0)

    def test_opaque_nonempty_values_are_not_matched_against_ordinary_data(self) -> None:
        values = (
            "a",
            "accepted",
            "request",
            "/",
            "   ",
            self.CANARY,
            " token with spaces ",
            "comma,value;semicolon",
            "quotes=\"single'",
            "plus/slash=equals",
            "Bearer-looking value",
        )
        for value in values:
            with self.subTest(value_index=values.index(value)), patch.dict(os.environ, {"AccessKey": value}, clear=True):
                transport = _ReferenceTransport()
                self._call(transport)
                self.assertEqual(len(transport.calls), 1)

    def test_ordinary_response_text_is_not_a_credential_detection_surface(self) -> None:
        values = ("a", "accepted", "request", "/", "   ", 'quotes="single\'')
        for value in values:
            with self.subTest(value=value), patch.dict(os.environ, {"AccessKey": value}, clear=True):
                transport = _ReferenceTransport(response={"ordinary_data": value, "accepted": True})
                response = self._call(transport)
                self.assertEqual(response, {"ordinary_data": value, "accepted": True})
                self.assertEqual(transport.calls[0].access_key, value)

    def test_missing_empty_and_non_string_values_fail_before_transport(self) -> None:
        for environment in ({}, {"AccessKey": ""}, {"AccessKey": None}):
            with self.subTest(environment_kind="missing" if not environment else type(environment["AccessKey"]).__name__):
                transport = _ReferenceTransport()
                with patch("k_slide.authentication.os.environ", environment):
                    with self.assertRaises(KSlideError) as raised:
                        self._call(transport)
                self.assertEqual(raised.exception.code, ErrorCode.AUTHENTICATION_FAILED)
                self.assertEqual(len(transport.calls), 0)
                self._assert_absent(self.CANARY, raised.exception.as_dict())

    def test_explicit_reference_helper_preserves_ksa14_credential_transport(self) -> None:
        request = self._request()
        transport = _ReferenceTransport()
        with patch.dict(os.environ, {"AccessKey": self.CANARY}, clear=True):
            response = reference_company_service_call(transport, request)
        self.assertEqual(len(transport.calls), 1)
        self.assertEqual(transport.calls[0].access_key, self.CANARY)
        self._assert_absent(self.CANARY, transport.calls[0].request.as_dict())
        self._assert_absent(self.CANARY, request.as_dict())
        self._assert_absent(self.CANARY, response)
        self.assertEqual(json.loads(json.dumps(request.as_dict()))["operation"], "approved.lookup")

    def test_host_and_paas_missing_policy_fail_before_access_key_or_transport(self) -> None:
        request = self._request()
        transport = _ReferenceTransport()
        with patch.dict(os.environ, {"AccessKey": self.CANARY}, clear=True), patch(
            "k_slide.authentication.require_access_key", side_effect=AssertionError("AccessKey retrieval must follow egress admission")
        ) as require_access_key:
            for helper in (authenticated_host_service_call, authenticated_paas_service_call):
                with self.subTest(helper=helper.__name__), self.assertRaises(KSlideError) as raised:
                    helper(transport, request, egress_policy=None, service_identity="wrong-service")
                self.assertEqual(raised.exception.code, ErrorCode.EGRESS_POLICY_INVALID)
        require_access_key.assert_not_called()
        self.assertEqual(transport.calls, [])

    def test_host_and_paas_wrong_service_or_capability_fail_before_access_key(self) -> None:
        request = self._request()
        policy = _deployment_policy()
        transport = _ReferenceTransport()
        with patch.dict(os.environ, {"AccessKey": self.CANARY}, clear=True), patch(
            "k_slide.authentication.require_access_key", side_effect=AssertionError("AccessKey retrieval must follow egress admission")
        ) as require_access_key:
            for helper in (authenticated_host_service_call, authenticated_paas_service_call):
                with self.subTest(helper=helper.__name__), self.assertRaises(KSlideError):
                    helper(transport, request, egress_policy=policy, service_identity="wrong-service")
            with self.assertRaises(KSlideError):
                authenticated_company_service_call(
                    transport,
                    request,
                    egress_policy=policy,
                    capability_class="wrong-capability",
                    purpose=EGRESS_PURPOSE_STORAGE,
                    service_identity="storage-service-v1",
                    data_class="source_content",
                )
        require_access_key.assert_not_called()
        self.assertEqual(transport.calls, [])

    def test_guarded_host_and_paas_calls_use_exact_key_after_admission(self) -> None:
        request = self._request()
        policy = _deployment_policy()
        transport = _ReferenceTransport()
        with patch("k_slide.authentication.require_access_key", return_value=self.CANARY) as require_access_key:
            authenticated_host_service_call(transport, request, egress_policy=policy, service_identity="storage-service-v1")
            authenticated_paas_service_call(transport, request, egress_policy=policy, service_identity="job-service-v1")
        self.assertEqual(require_access_key.call_count, 2)
        self.assertEqual([call.access_key for call in transport.calls], [self.CANARY, self.CANARY])

    def test_ordinary_payload_values_cannot_activate_reference_seam(self) -> None:
        transport = _ReferenceTransport()
        request = CompanyServiceRequest("approved.lookup", {"reference_mode": True, "reference_adapter": True})
        with patch.dict(os.environ, {"AccessKey": self.CANARY}, clear=True), patch(
            "k_slide.authentication.require_access_key", side_effect=AssertionError("payload must not select reference mode")
        ) as require_access_key:
            with self.assertRaises(KSlideError) as raised:
                authenticated_company_service_call(transport, request)
        self.assertEqual(raised.exception.code, ErrorCode.EGRESS_POLICY_INVALID)
        require_access_key.assert_not_called()
        self.assertEqual(transport.calls, [])

    def test_canary_does_not_enter_model_run_environment_candidate_telemetry_or_files(self) -> None:
        request = self._request()
        transport = _ReferenceTransport()
        environment = reference_environment()
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"AccessKey": self.CANARY}, clear=True):
            root = Path(directory)
            host_response = reference_company_service_call(transport, request)
            paas_response = reference_company_service_call(transport, request)
            workspace_job = new_execution_job(
                "run-workspace-auth",
                profile=ExecutionProfile.WORKSPACE_LOCAL,
                scope_ref="scope",
                store_ref="workspace-store",
                environment_identity=environment,
            )
            durable_job = new_execution_job(
                "run-durable-auth",
                profile=ExecutionProfile.DURABLE,
                scope_ref="scope",
                store_ref="durable-store",
                environment_identity=environment,
            )
            WorkspaceRunStore(root / "workspace-run").create(workspace_job)
            DurableTestRunStore(root / "durable-run").create(durable_job)
            ordinary_state = {
                "model_packet": request.as_dict(),
                "response": host_response,
                "durable_response": paas_response,
                "run_state": {"run_id": workspace_job.run_id, "phase": "RUNNING"},
                "checkpoint": workspace_job.checkpoint.as_dict(),
                "environment_identity": environment.as_dict(),
                "candidate": {"requested_model": "synthetic/model"},
                "profile": {"execution_profile": "workspace_local"},
                "telemetry": {"event_type": "lifecycle", "error_code": ErrorCode.AUTHENTICATION_FAILED.value},
                "artifact_metadata": {"kind": "ordinary-result"},
            }
            self._assert_absent(self.CANARY, ordinary_state)
            self._assert_absent(self.CANARY, execution_metadata(workspace_job))
            self._assert_absent(self.CANARY, execution_metadata(durable_job))
            for path in root.rglob("*"):
                if path.is_file():
                    self._assert_absent(self.CANARY, path.read_bytes().decode("utf-8", errors="replace"))

    def test_adapter_rejection_is_secret_free_operational_failure(self) -> None:
        transport = _ReferenceTransport(rejection=_RawRejection(self.CANARY))
        with patch.dict(os.environ, {"AccessKey": self.CANARY}, clear=True):
            with self.assertRaises(KSlideError) as raised:
                self._call(transport)
        error = raised.exception
        self.assertEqual(error.code, ErrorCode.AUTHENTICATION_FAILED)
        self.assertEqual(classify_operational_failure(error.code), FailureClass.NOT_RETRYABLE)
        self.assertEqual(len(transport.calls), 1)
        self.assertNotEqual(error.code.value, "NEEDS_REVIEW")
        safe_error = error.as_dict()
        self._assert_absent(self.CANARY, safe_error)
        self._assert_absent(self.CANARY[:8], safe_error)
        self._assert_absent(self.CANARY[-8:], safe_error)
        self._assert_absent(hashlib.sha256(self.CANARY.encode()).hexdigest(), safe_error)
        self.assertEqual(safe_error["message"], "Approved company-service authentication failed.")
        self.assertEqual(safe_error["details"], {"phase": "authentication", "reason": "rejected"})

    def test_transport_failure_and_nonserializable_response_fail_closed_without_adapter_text(self) -> None:
        class _FailureTransport(_ReferenceTransport):
            def call(self, request: CompanyServiceRequest, *, access_key: str) -> object:
                self.calls.append(_CapturedCall(request, access_key))
                raise RuntimeError(f"raw adapter detail {access_key}")

        for transport in (_FailureTransport(), _ReferenceTransport(response=object())):
            with patch.dict(os.environ, {"AccessKey": self.CANARY}, clear=True):
                with self.assertRaises(KSlideError) as raised:
                    self._call(transport)
            self.assertEqual(raised.exception.code, ErrorCode.AUTHENTICATION_FAILED)
            self._assert_absent(self.CANARY, raised.exception.as_dict())

    def test_ordinary_url_values_and_similar_field_names_are_data(self) -> None:
        payload = {
            "source_text": "See https://intranet.example/path",
            "source_url": "https://intranet.example/source",
            "host_metadata": {"hostname": "ordinary-business-value"},
            "token_budget": 512,
            "nested": {"service_endpoint": "https://intranet.example/service", "destination_note": "ordinary"},
        }
        transport = _ReferenceTransport()
        with patch.dict(os.environ, {"AccessKey": self.CANARY}, clear=True):
            response = self._call(transport, CompanyServiceRequest("approved.lookup", payload))
        self.assertEqual(len(transport.calls), 1)
        self.assertEqual(transport.calls[0].request.payload, payload)
        self.assertEqual(response["operation"], "approved.lookup")

    def test_payload_values_cannot_select_or_replace_injected_transport(self) -> None:
        approved = _ReferenceTransport()
        unapproved = _ReferenceTransport()
        with self.assertRaises(KSlideError) as raised:
            CompanyServiceRequest("approved.lookup", {"endpoint": "https://attacker.invalid/service"})
        self.assertEqual(raised.exception.code, ErrorCode.SCHEMA_INVALID)
        self.assertEqual(len(approved.calls), 0)
        self.assertEqual(len(unapproved.calls), 0)

        ordinary_request = CompanyServiceRequest(
            "approved.lookup",
            {"source_url": "https://intranet.example/source", "token_budget": 512},
        )
        with patch.dict(os.environ, {"AccessKey": self.CANARY}, clear=True):
            self._call(approved, ordinary_request)
        self.assertEqual(len(approved.calls), 1)
        self.assertEqual(len(unapproved.calls), 0)

    def test_exact_reserved_credential_and_transport_fields_remain_absent(self) -> None:
        for field in ("access_key", "AccessKey", "token", "authorization", "transport", "endpoint", "host"):
            with self.subTest(field=field):
                with self.assertRaises(KSlideError) as raised:
                    CompanyServiceRequest("approved.lookup", {field: "ordinary"})
                self.assertEqual(raised.exception.code, ErrorCode.SCHEMA_INVALID)

    def test_no_cli_or_second_credential_authority_is_added(self) -> None:
        root = Path(__file__).resolve().parents[1]
        product_source = "\n".join(path.read_text(encoding="utf-8") for path in (root / "src" / "k_slide").rglob("*.py"))
        for forbidden in ("KSLIDE_ACCESS_KEY", "--access-key", "LDAP_BIND", "refresh_token"):
            self.assertNotIn(forbidden, product_source, "an alternate credential authority was introduced")

    def test_production_readiness_is_source_free_and_does_not_claim_live_authentication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime = type("Runtime", (), {"kslide_version": "0.3.5", "opencode_version": "UNSET", "reported_model_id": "UNSET", "vision_support": None})()
            with patch.dict(os.environ, {}, clear=True):
                missing = next(item for item in production_checks(Path(directory), runtime) if item["label"] == "AccessKey readiness")
            self.assertEqual(missing, {"label": "AccessKey readiness", "status": "WARN", "detail": "missing"})
            with patch.dict(os.environ, {"AccessKey": self.CANARY}, clear=True):
                available = next(item for item in production_checks(Path(directory), runtime) if item["label"] == "AccessKey readiness")
            self.assertEqual(available, {"label": "AccessKey readiness", "status": "PASS", "detail": "available"})
            self._assert_absent(self.CANARY, available)


if __name__ == "__main__":
    unittest.main()
