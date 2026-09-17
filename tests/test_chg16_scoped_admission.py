from __future__ import annotations

import multiprocessing
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from k_slide.errors import ErrorCode, KSlideError
from k_slide.execution import (
    EngineStepResult,
    OperationalLifecycle,
    ProgressSnapshot,
    ResultCommitMarker,
    StoreWriteStatus,
    TerminalOutcome,
)
from k_slide.evidence_ir import stable_revision
from k_slide.paas import (
    AuthorizedScopeContext,
    PaaSController,
    PaaSJobRequest,
    PaaSWorker,
    QueueAdmissionState,
    ReferencePaaSJobService,
    ReferencePaaSRunStore,
    ReferenceWorkerEngine,
    ScopedPaaSRunStore,
    RuntimeIdentity,
)
from tests.reference_fixtures import reference_runtime


RUNTIME = reference_runtime()


class _NeedsReviewEngine:
    def operation_id(self, job):
        return f"{job.execution_id}-review-{job.checkpoint.revision + 1}"

    def step(self, checkpoint, operation_id):
        next_checkpoint = replace(
            checkpoint,
            revision=checkpoint.revision + 1,
            engine_phase="NEEDS_REVIEW",
            progress=ProgressSnapshot("NEEDS_REVIEW", 0, checkpoint.progress.total_work_units),
            checkpoint_sha256="",
        )
        return EngineStepResult(next_checkpoint)


def _submit_process(root_text: str, user: str, workspace: str, scope: str, run_id: str, output) -> None:
    root = Path(root_text)
    context = AuthorizedScopeContext(user, workspace, scope)
    service = ReferencePaaSJobService(root)
    receipt = PaaSController(service, scope_context=context).submit(
        PaaSJobRequest(run_id, scope, f"store-{run_id}", RUNTIME, total_work_units=2)
    )
    output.put((run_id, receipt.status.value, receipt.identity.job_id))


def _claim_process(root_text: str, output) -> None:
    context = AuthorizedScopeContext("user-a", "workspace-a", "scope-a")
    worker = PaaSWorker(
        ReferencePaaSJobService(Path(root_text)),
        worker_id="process-worker",
        runtime_identity=RUNTIME,
        engine=ReferenceWorkerEngine(),
        scope_context=context,
    )
    result = worker.run_once()
    output.put(result.status)


class ScopedAdmissionIntegrationTests(unittest.TestCase):
    def _context(self, suffix: str = "a") -> AuthorizedScopeContext:
        return AuthorizedScopeContext(f"user-{suffix}", f"workspace-{suffix}", f"scope-{suffix}")

    def _submit(self, service: ReferencePaaSJobService, context: AuthorizedScopeContext, run_id: str, *, total: int = 1):
        return PaaSController(service, scope_context=context).submit(
            PaaSJobRequest(run_id, str(context.scope_ref), f"store-{run_id}", RUNTIME, total_work_units=total)
        )

    def test_same_scope_multi_process_submissions_are_fifo_with_one_active_slot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = multiprocessing.Queue()
            processes = [
                multiprocessing.Process(
                    target=_submit_process,
                    args=(str(root), "user-a", "workspace-a", "scope-a", f"run-{index}", output),
                )
                for index in range(4)
            ]
            for process in processes:
                process.start()
            for process in processes:
                process.join(timeout=5)
                self.assertFalse(process.is_alive())
                self.assertEqual(process.exitcode, 0)
            submitted = [output.get(timeout=2) for _ in processes]
            self.assertEqual({item[1] for item in submitted}, {StoreWriteStatus.ACCEPTED.value})

            context = self._context()
            queue = ReferencePaaSJobService(root).queue(scope_context=context)
            self.assertEqual(sum(entry.admission_state is QueueAdmissionState.ACTIVE for entry in queue.entries), 1)
            self.assertEqual([entry.sequence for entry in queue.entries], [1, 2, 3, 4])
            self.assertEqual({entry.identity.run_id for entry in queue.entries}, {f"run-{index}" for index in range(4)})
            self.assertEqual(
                [entry.identity.job_id for entry in queue.entries],
                [entry.identity.job_id for entry in ReferencePaaSJobService(root).queue(scope_context=context).entries],
            )

    def test_independent_scopes_have_independent_active_slots(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            service = ReferencePaaSJobService(root)
            first = self._context("a")
            second = self._context("b")
            self._submit(service, first, "run-a")
            self._submit(service, second, "run-b")
            self.assertEqual(ReferencePaaSJobService(root).queue(scope_context=first).active_job_id, "job-run-a")
            self.assertEqual(ReferencePaaSJobService(root).queue(scope_context=second).active_job_id, "job-run-b")

    def test_same_scope_multi_process_claims_share_one_active_job_and_one_committed_step(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            service = ReferencePaaSJobService(root)
            context = self._context()
            first = self._submit(service, context, "run-first", total=3)
            self._submit(service, context, "run-second", total=1)
            output = multiprocessing.Queue()
            processes = [multiprocessing.Process(target=_claim_process, args=(str(root), output)) for _ in range(2)]
            for process in processes:
                process.start()
            for process in processes:
                process.join(timeout=5)
                self.assertFalse(process.is_alive())
                self.assertEqual(process.exitcode, 0)
            statuses = {output.get(timeout=2) for _ in processes}
            self.assertTrue(statuses <= {"ACCEPTED", "REPLAYED", "DONE"})
            self.assertTrue(statuses)
            current = ReferencePaaSJobService(root).open_store(first.identity, scope_context=context).load(first.job_id)
            self.assertLessEqual(len(current.result_markers), 2)
            self.assertEqual(ReferencePaaSJobService(root).queue(scope_context=context).active_job_id, first.job_id)

    def test_restart_preserves_scoped_queue_order_and_observable_progress(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = self._context()
            service = ReferencePaaSJobService(root)
            first = self._submit(service, context, "run-first", total=2)
            second = self._submit(service, context, "run-second", total=1)
            worker = PaaSWorker(service, worker_id="worker-one", runtime_identity=RUNTIME, engine=ReferenceWorkerEngine(), scope_context=context)
            first_step = worker.run_once(first.identity)
            self.assertEqual(first_step.status, "ACCEPTED")
            self.assertEqual(first_step.references, first.references)

            reconstructed = ReferencePaaSJobService(root)
            queue = reconstructed.queue(scope_context=context)
            self.assertEqual(queue.active_job_id, first.job_id)
            self.assertEqual([entry.identity.job_id for entry in queue.queued], [second.job_id])
            self.assertEqual(reconstructed.inspect(first.identity, scope_context=context).progress["completed_work_units"], 1)

            result = PaaSWorker(reconstructed, worker_id="worker-two", runtime_identity=RUNTIME, engine=ReferenceWorkerEngine(), scope_context=context).run_until_terminal(first.identity)
            self.assertEqual(result.status, "DONE")
            self.assertEqual(reconstructed.queue(scope_context=context).active_job_id, second.job_id)

    def test_record_only_admission_reserves_sequence_across_store_create_crash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = self._context()
            service = ReferencePaaSJobService(root)
            with patch.object(ReferencePaaSRunStore, "create", side_effect=RuntimeError("stop before store create")):
                with self.assertRaisesRegex(RuntimeError, "stop before store create"):
                    self._submit(service, context, "run-first")

            recreated = ReferencePaaSJobService(root)
            second = self._submit(recreated, context, "run-second")
            self.assertEqual(second.status, StoreWriteStatus.ACCEPTED)
            before_reconcile = recreated.queue(scope_context=context)
            self.assertEqual([entry.sequence for entry in before_reconcile.entries], [1, 2])
            self.assertIsNone(before_reconcile.active_job_id)

            contradictory_retry = self._submit(recreated, context, "run-first", total=2)
            self.assertEqual(contradictory_retry.status, StoreWriteStatus.CONFLICT)
            first_retry = self._submit(ReferencePaaSJobService(root), context, "run-first")
            self.assertEqual(first_retry.status, StoreWriteStatus.ACCEPTED)
            final = ReferencePaaSJobService(root).queue(scope_context=context)
            self.assertEqual([entry.sequence for entry in final.entries], [1, 2])
            self.assertEqual(len({entry.sequence for entry in final.entries}), 2)
            self.assertEqual([entry.identity.run_id for entry in final.entries], ["run-first", "run-second"])
            self.assertEqual(final.active_job_id, first_retry.job_id)

            reconstructed_again = ReferencePaaSJobService(root)
            self.assertEqual(
                [(entry.sequence, entry.identity.job_id) for entry in reconstructed_again.queue(scope_context=context).entries],
                [(1, first_retry.job_id), (2, second.job_id)],
            )

    def test_needs_review_releases_slot_but_only_explicit_fifo_resume_reacquires_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = self._context()
            service = ReferencePaaSJobService(root)
            first = self._submit(service, context, "run-review")
            second = self._submit(service, context, "run-second")
            third = self._submit(service, context, "run-third")
            review_worker = PaaSWorker(
                service,
                worker_id="review-worker",
                runtime_identity=RUNTIME,
                engine=_NeedsReviewEngine(),
                scope_context=context,
            )
            review = review_worker.run_once(first.identity)
            self.assertEqual(review.status, "NEEDS_REVIEW")
            self.assertEqual(review.job.lifecycle, OperationalLifecycle.COMPLETED)
            self.assertEqual(review.job.terminal_outcome, TerminalOutcome.NEEDS_REVIEW)

            queue = service.queue(scope_context=context)
            self.assertEqual(queue.active_job_id, second.job_id)
            self.assertEqual([entry.admission_state.value for entry in queue.entries], ["TERMINAL", "ACTIVE", "QUEUED"])
            with self.assertRaises(KSlideError) as raised:
                review_worker.run_once(first.identity)
            self.assertEqual(raised.exception.code, ErrorCode.EXECUTION_CONFLICT)

            worker = PaaSWorker(
                service,
                worker_id="fifo-worker",
                runtime_identity=RUNTIME,
                engine=ReferenceWorkerEngine(),
                scope_context=context,
            )
            self.assertEqual(worker.run_until_terminal(second.identity).status, "DONE")
            self.assertEqual(service.queue(scope_context=context).active_job_id, third.job_id)
            self.assertEqual(worker.run_until_terminal(third.identity).status, "DONE")

            reconstructed = ReferencePaaSJobService(root)
            settled = reconstructed.queue(scope_context=context)
            self.assertIsNone(settled.active_job_id)
            self.assertTrue(all(entry.admission_state is QueueAdmissionState.TERMINAL for entry in settled.entries))
            with self.assertRaises(KSlideError) as raised:
                reconstructed.claim_next(worker_id="automatic-worker", runtime_identity=RUNTIME, scope_context=context)
            self.assertEqual(raised.exception.code, ErrorCode.EXECUTION_NOT_FOUND)

            resumed = PaaSWorker(
                reconstructed,
                worker_id="resume-worker",
                runtime_identity=RUNTIME,
                engine=ReferenceWorkerEngine(),
                scope_context=context,
            ).run_until_terminal(first.identity)
            self.assertEqual(resumed.status, "DONE")
            self.assertEqual(resumed.job.terminal_outcome, TerminalOutcome.DONE)
            self.assertIsNone(reconstructed.queue(scope_context=context).active_job_id)

    def test_terminal_and_acknowledged_cancellation_advance_exactly_one_successor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = self._context()
            service = ReferencePaaSJobService(root)
            first = self._submit(service, context, "run-first")
            second = self._submit(service, context, "run-second")
            third = self._submit(service, context, "run-third")
            worker = PaaSWorker(service, worker_id="worker", runtime_identity=RUNTIME, engine=ReferenceWorkerEngine(), scope_context=context)
            self.assertEqual(worker.run_until_terminal(first.identity).status, "DONE")
            queue = service.queue(scope_context=context)
            self.assertEqual(queue.active_job_id, second.job_id)
            self.assertEqual(sum(entry.active for entry in queue.entries), 1)

            PaaSController(service, scope_context=context).cancel(second.identity)
            canceled = worker.run_once(second.identity)
            self.assertEqual(canceled.status, "CANCELED")
            queue_after_cancel = ReferencePaaSJobService(root).queue(scope_context=context)
            self.assertEqual(queue_after_cancel.active_job_id, third.job_id)
            self.assertEqual(sum(entry.active for entry in queue_after_cancel.entries), 1)

    def test_scoped_store_preserves_cas_and_idempotent_result_commit_after_recreation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = self._context()
            service = ReferencePaaSJobService(root)
            receipt = self._submit(service, context, "run-cas")
            first_store = service.open_store(receipt.identity, scope_context=context)
            second_store = ReferencePaaSJobService(root).open_store(receipt.identity, scope_context=context)
            self.assertIsInstance(first_store, ScopedPaaSRunStore)
            job = first_store.load(receipt.job_id)
            checkpoint = replace(
                job.checkpoint,
                revision=1,
                engine_phase="TRANSLATING",
                progress=ProgressSnapshot("TRANSLATING", 0, 1),
                checkpoint_sha256="",
            )
            accepted = first_store.commit_checkpoint(checkpoint, expected_revision=job.revision)
            self.assertEqual(accepted.status, StoreWriteStatus.ACCEPTED)
            stale = second_store.commit_checkpoint(replace(checkpoint, engine_phase="NORMALIZED"), expected_revision=job.revision)
            self.assertEqual(stale.status, StoreWriteStatus.STALE)

            current = second_store.load(receipt.job_id)
            marker = ResultCommitMarker("operation-1", "result", stable_revision({"result": 1}), 0, "2026-01-01T00:00:00Z")
            next_checkpoint = replace(current.checkpoint, revision=current.checkpoint.revision + 1, engine_phase="COMPLETE", progress=ProgressSnapshot("COMPLETE", 1, 1), checkpoint_sha256="")
            committed = second_store.commit_step(next_checkpoint, marker, expected_revision=current.revision)
            self.assertEqual(committed.status, StoreWriteStatus.ACCEPTED)
            replay = first_store.commit_step(next_checkpoint, marker, expected_revision=current.revision)
            self.assertEqual(replay.status, StoreWriteStatus.IDEMPOTENT)
            self.assertEqual(len(first_store.load(receipt.job_id).result_markers), 1)

    def test_wrong_scope_or_guessed_ids_cannot_inspect_cancel_claim_or_resolve(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            service = ReferencePaaSJobService(root)
            owner = self._context("owner")
            other = self._context("other")
            same_scope_other_actor = AuthorizedScopeContext("user-other", "workspace-other", "scope-owner")
            receipt = self._submit(service, owner, "run-private")
            controller = PaaSController(service, scope_context=other)
            for operation in (
                lambda: controller.status(receipt.identity),
                lambda: controller.cancel(receipt.identity),
                lambda: service.claim(receipt.identity, worker_id="wrong-worker", runtime_identity=RUNTIME, scope_context=other),
                lambda: service.open_store(receipt.identity, scope_context=other),
                lambda: service.resolve_result(receipt.identity, scope_context=other),
                lambda: service.resolve_evidence(receipt.identity, scope_context=other),
            ):
                with self.assertRaises(KSlideError) as raised:
                    operation()
                self.assertIn(raised.exception.code, {ErrorCode.EXECUTION_CONFLICT, ErrorCode.EXECUTION_NOT_FOUND})
            with self.assertRaises(KSlideError):
                service.inspect("job-run-private", scope_context=other)
            with self.assertRaises(KSlideError):
                service.inspect("job-run-private", scope_context=same_scope_other_actor)
            with self.assertRaises(KSlideError):
                service.claim_next(worker_id="wrong-worker", runtime_identity=RUNTIME, scope_context=other)
            with self.assertRaises(KSlideError):
                # The pre-KSA-09 compatibility lookup has no access to a
                # scoped namespace when no deployment context is supplied.
                service.inspect(receipt.identity)
            self.assertEqual(service.inspect(receipt.identity, scope_context=owner).identity, receipt.identity)

    def test_persisted_scoped_namespaces_and_control_records_are_source_free(self) -> None:
        secret = "AccessKey=process-only-secret"
        source = "confidential source sentence"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            service = ReferencePaaSJobService(root)
            context = self._context()
            receipt = self._submit(service, context, "run-hygiene")
            queue = service.queue(scope_context=context)
            self.assertEqual(queue.active_job_id, receipt.job_id)
            scope_dirs = list((root / "job-service" / "scopes").iterdir())
            self.assertEqual(len(scope_dirs), 1)
            self.assertTrue((scope_dirs[0] / "admission" / "CONTROL_STATE.json").is_file())
            self.assertTrue((scope_dirs[0] / "admission" / "QUEUE.json").is_file())
            self.assertTrue((scope_dirs[0] / "run-store" / "jobs" / f"{receipt.job_id}.json").is_file())
            serialized = "\n".join(path.read_text(encoding="utf-8") for path in root.rglob("*.json"))
            self.assertNotIn(secret, serialized)
            self.assertNotIn(source, serialized)
            self.assertNotIn("prompt", serialized.lower())
            self.assertNotIn("accesskey", serialized.lower())
            self.assertNotIn("secret", serialized.lower())
            self.assertNotIn("source", serialized.lower())
            self.assertNotIn("content", serialized.lower())
            self.assertNotIn("confidential", serialized.lower())
            refs = service.resolve_references(receipt.identity, scope_context=context)
            self.assertEqual(refs.scope_ref, context.scope_ref)
            self.assertNotEqual(refs.result_ref, refs.evidence_ref)


if __name__ == "__main__":
    unittest.main()
