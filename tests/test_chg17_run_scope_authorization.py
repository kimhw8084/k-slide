from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from pathlib import Path

from k_slide.deletion import ReferenceLegalHoldProvider
from k_slide.cli import _status
from k_slide.errors import ErrorCode, KSlideError
from k_slide.paas import (
    AuthorizedScopeContext,
    DurableJobIdentity,
    PaaSController,
    PaaSJobRequest,
    PaaSWorker,
    ReferencePaaSJobService,
    ReferenceWorkerEngine,
)
from k_slide.session import bind_session, resolve_run
from k_slide.worker import main as worker_main
from tests.reference_fixtures import reference_runtime


RUNTIME = reference_runtime()


class RunScopeAuthorizationTests(unittest.TestCase):
    def _context(self, suffix: str) -> AuthorizedScopeContext:
        return AuthorizedScopeContext(f"user-{suffix}", f"workspace-{suffix}", f"scope-{suffix}")

    def _submit(self, service: ReferencePaaSJobService, context: AuthorizedScopeContext, run_id: str = "run-private", *, total: int = 2):
        return PaaSController(service, scope_context=context).submit(
            PaaSJobRequest(run_id, str(context.scope_ref), f"store-{run_id}", RUNTIME, total_work_units=total)
        )

    def _assert_not_found(self, operation) -> None:
        with self.assertRaises(KSlideError) as raised:
            operation()
        self.assertEqual(raised.exception.code, ErrorCode.EXECUTION_NOT_FOUND)
        self.assertEqual(raised.exception.message, "Durable execution is unavailable.")
        self.assertEqual(raised.exception.details, {})

    def test_missing_context_fails_closed_at_every_production_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            service = ReferencePaaSJobService(root)
            owner = self._context("owner")
            receipt = self._submit(service, owner)
            operations = (
                lambda: service.inspect(receipt.identity),
                lambda: service.request_cancellation(receipt.identity),
                lambda: service.claim(receipt.identity, worker_id="worker", runtime_identity=RUNTIME),
                lambda: service.claim_next(worker_id="worker", runtime_identity=RUNTIME),
                lambda: service.open_store(receipt.identity),
                lambda: service.queue(),
                lambda: service.resolve_references(receipt.identity),
                lambda: service.resolve_store(receipt.identity),
                lambda: service.resolve_result(receipt.identity),
                lambda: service.resolve_evidence(receipt.identity),
                lambda: service.content_layout(receipt.identity),
                lambda: service.delete_run(receipt.identity, deletion_id="delete-missing", hold_provider=ReferenceLegalHoldProvider()),
            )
            for operation in operations:
                with self.assertRaises(KSlideError) as raised:
                    operation()
                self.assertEqual(raised.exception.code, ErrorCode.EXECUTION_AUTHORIZATION_REQUIRED)
                self.assertEqual(raised.exception.details, {})

            with self.assertRaises(KSlideError) as raised:
                PaaSController(service).status(receipt.identity)
            self.assertEqual(raised.exception.code, ErrorCode.EXECUTION_AUTHORIZATION_REQUIRED)
            with self.assertRaises(KSlideError) as raised:
                PaaSController(service).reconnect(receipt.identity)
            self.assertEqual(raised.exception.code, ErrorCode.EXECUTION_AUTHORIZATION_REQUIRED)
            with self.assertRaises(KSlideError) as raised:
                PaaSController(service).cancel(receipt.identity)
            self.assertEqual(raised.exception.code, ErrorCode.EXECUTION_AUTHORIZATION_REQUIRED)
            with self.assertRaises(KSlideError) as raised:
                PaaSController(service).queue()
            self.assertEqual(raised.exception.code, ErrorCode.EXECUTION_AUTHORIZATION_REQUIRED)
            with self.assertRaises(KSlideError) as raised:
                PaaSWorker(service, worker_id="worker", runtime_identity=RUNTIME, engine=ReferenceWorkerEngine())
            self.assertEqual(raised.exception.code, ErrorCode.EXECUTION_AUTHORIZATION_REQUIRED)

    def test_request_supplied_context_cannot_create_authority_for_a_normal_controller(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            service = ReferencePaaSJobService(Path(directory))
            owner = self._context("owner")
            request = PaaSJobRequest("run-forged", owner.scope_ref, "store-forged", RUNTIME, scope_context=owner)
            with self.assertRaises(KSlideError) as raised:
                PaaSController(service).submit(request)
            self.assertEqual(raised.exception.code, ErrorCode.EXECUTION_AUTHORIZATION_REQUIRED)
            self.assertEqual(raised.exception.details, {})

    def test_reference_compatibility_is_explicit_and_worker_cli_rejects_unscoped_managed_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            compatibility = ReferencePaaSJobService(root, reference_compatibility=True)
            request = PaaSJobRequest("run-reference", "scope-reference", "store-reference", RUNTIME, total_work_units=1)
            receipt = PaaSController(compatibility).submit(request)
            self.assertEqual(PaaSController(compatibility).status(receipt.identity).identity, receipt.identity)

            output = io.StringIO()
            with redirect_stdout(output):
                code = worker_main(
                    [
                        "--service-root",
                        str(root),
                        "--job-id",
                        receipt.job_id,
                        "--worker-id",
                        "cli-worker",
                        "--runtime-ref",
                        RUNTIME.runtime_ref,
                        "--model-identity",
                        RUNTIME.model_identity,
                        "--ocr-identity",
                        RUNTIME.ocr_identity,
                        "--termbase-identity",
                        RUNTIME.termbase_identity,
                        "--environment-identity-json",
                        json.dumps(RUNTIME.environment_identity.as_dict()),
                    ]
                )
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(output.getvalue())["code"], ErrorCode.EXECUTION_AUTHORIZATION_REQUIRED.value)

    def test_all_cross_scope_and_forged_identity_probes_share_the_same_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            service = ReferencePaaSJobService(root)
            owner = self._context("owner")
            other = self._context("other")
            same_scope_other_actor = AuthorizedScopeContext("user-other", "workspace-other", owner.scope_ref)
            receipt = self._submit(service, owner)
            sibling = self._submit(service, owner, "run-sibling", total=1)
            forged_store = replace(receipt.identity, store_ref="store-forged")
            forged_run = replace(receipt.identity, run_id="run-forged")
            forged_execution = replace(receipt.identity, execution_id="execution-forged")
            nonexistent = DurableJobIdentity("run-absent", "job-absent", "execution-absent", owner.scope_ref, "store-absent")
            probes = (
                lambda: service.inspect(receipt.identity, scope_context=other),
                lambda: service.inspect(receipt.identity, scope_context=same_scope_other_actor),
                lambda: service.inspect(forged_store, scope_context=owner),
                lambda: service.inspect(forged_run, scope_context=owner),
                lambda: service.inspect(forged_execution, scope_context=owner),
                lambda: service.inspect(nonexistent, scope_context=owner),
                lambda: service.request_cancellation(receipt.identity, scope_context=other),
                lambda: service.claim(receipt.identity, worker_id="wrong-worker", runtime_identity=RUNTIME, scope_context=other),
                lambda: service.open_store(receipt.identity, scope_context=other),
                lambda: service.resolve_references(receipt.identity, scope_context=other),
                lambda: service.resolve_store(receipt.identity, scope_context=other),
                lambda: service.resolve_result(receipt.identity, scope_context=other),
                lambda: service.resolve_evidence(receipt.identity, scope_context=other),
                lambda: service.content_layout(receipt.identity, scope_context=other),
                lambda: service.claim_next(worker_id="wrong-worker", runtime_identity=RUNTIME, scope_context=other),
                lambda: PaaSController(service, scope_context=other).status(receipt.identity),
                lambda: PaaSController(service, scope_context=other).reconnect(receipt.identity),
                lambda: PaaSController(service, scope_context=other).cancel(receipt.identity),
                lambda: PaaSWorker(service, worker_id="wrong-worker", runtime_identity=RUNTIME, engine=ReferenceWorkerEngine(), scope_context=other).run_once(receipt.identity),
            )
            for probe in probes:
                self._assert_not_found(probe)

            provider = ReferenceLegalHoldProvider()
            provider.set_release(scope_ref=other.scope_ref, run_ref=receipt.identity.run_id)
            self._assert_not_found(
                lambda: service.delete_run(
                    receipt.identity,
                    deletion_id="delete-forged-scope",
                    scope_context=other,
                    hold_provider=provider,
                )
            )

            scoped_store = service.open_store(receipt.identity, scope_context=owner)
            self._assert_not_found(lambda: scoped_store.load(sibling.job_id))
            self._assert_not_found(lambda: scoped_store.load("job-guessed"))
            self.assertEqual(service.inspect(receipt.identity, scope_context=owner).identity, receipt.identity)

    def test_session_binding_wins_over_explicit_model_run_and_unbound_hosted_session_has_no_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_root = root / ".k-slide-runs"
            run_root.mkdir()
            first = run_root / "k-slide-first"
            second = run_root / "k-slide-second"
            first.mkdir()
            second.mkdir()
            bind_session(run_root, "session-first", first.name)
            bind_session(run_root, "session-second", second.name)

            self.assertEqual(resolve_run(run_root, session_id="session-first"), first.resolve())
            self.assertEqual(resolve_run(run_root, explicit=first.name, session_id="session-first"), first.resolve())
            self.assertIsNone(resolve_run(run_root, explicit=second.name, session_id="session-first"))
            self.assertIsNone(resolve_run(run_root, explicit=second.resolve().as_posix(), session_id="session-first"))
            self.assertEqual(resolve_run(run_root, explicit=second.name), second.resolve())
            self.assertIsNone(resolve_run(run_root, session_id="unbound-hosted-session"))
            self.assertIsNone(resolve_run(run_root, explicit=first.name, session_id="unbound-hosted-session"))
            status = _status(root, second.name, "session-first")
            self.assertEqual(status["status"], "NO_RUN")
            self.assertNotIn("choices", status)


if __name__ == "__main__":
    unittest.main()
