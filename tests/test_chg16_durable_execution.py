from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from contextlib import contextmanager, redirect_stdout
import io
from pathlib import Path
from threading import Barrier, Event, Lock, Thread

from k_slide.errors import ErrorCode, KSlideError
from k_slide.cli import main
from k_slide.execution import (
    DurableTestRunStore,
    EngineStepResult,
    ExecutionController,
    ExecutionJob,
    ExecutionProfile,
    OperationalLifecycle,
    ProgressSnapshot,
    ResultCommitMarker,
    RetryDisposition,
    RunCheckpoint,
    StoreWriteStatus,
    TerminalOutcome,
    WorkspaceRunStore,
    classify_operational_failure,
    execution_metadata,
    new_execution_job,
)
from k_slide.evidence_ir import stable_revision
from k_slide.ingest import prepare_run
from tests.reference_fixtures import reference_environment


class _DeterministicStep:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def __call__(self, checkpoint: RunCheckpoint, operation_id: str) -> EngineStepResult:
        self.calls.append(operation_id)
        next_revision = checkpoint.revision + 1
        progress = ProgressSnapshot("FAKE_ENGINE_STEP", checkpoint.progress.completed_work_units + 1, checkpoint.progress.total_work_units, None)
        next_checkpoint = replace(checkpoint, revision=next_revision, engine_phase="FAKE_ENGINE_STEP", progress=progress, checkpoint_sha256="")
        marker = ResultCommitMarker(operation_id, "fake-result", stable_revision({"operation_id": operation_id}), attempt=0, committed_at="2026-01-01T00:00:00Z")
        return EngineStepResult(next_checkpoint, marker)


class _CreateRaceGate:
    def __init__(self) -> None:
        self._lock = Lock()
        self._arrivals = 0
        self.peer_arrived = Event()

    def wait_for_peer(self) -> None:
        with self._lock:
            self._arrivals += 1
            if self._arrivals == 2:
                self.peer_arrived.set()
        self.peer_arrived.wait(timeout=1.0)


class _GatedCreateStore(DurableTestRunStore):
    def __init__(self, backing_root: Path, gate: _CreateRaceGate) -> None:
        super().__init__(backing_root)
        self._gate = gate

    def _write(self, job: ExecutionJob) -> None:
        self._gate.wait_for_peer()
        super()._write(job)


class _ProbedDurableStore(DurableTestRunStore):
    def __init__(self, backing_root: Path, entered: Event) -> None:
        super().__init__(backing_root)
        self._entered = entered

    @contextmanager
    def _mutation(self, job_id: str | None = None):
        with super()._mutation(job_id):
            self._entered.set()
            yield


class DurableExecutionContractTests(unittest.TestCase):
    def _profiles(self, root: Path):
        return (
            (ExecutionProfile.WORKSPACE_LOCAL, WorkspaceRunStore(root / "workspace-run")),
            (ExecutionProfile.DURABLE_TEST, DurableTestRunStore(root / "durable-store")),
        )

    def _created(self, store, profile: ExecutionProfile, run_id: str = "run-contract") -> ExecutionJob:
        job = new_execution_job(
            run_id,
            profile=profile,
            scope_ref="opaque-scope",
            store_ref=f"store-{profile.value}",
            total_work_units=3,
            max_attempts=2,
        )
        result = store.create(job)
        self.assertEqual(result.status, StoreWriteStatus.ACCEPTED)
        return result.job

    def test_both_profiles_share_creation_lifecycle_checkpoint_and_replay_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for profile, store in self._profiles(root):
                job = self._created(store, profile, run_id=f"run-{profile.value}")
                self.assertEqual(job.lifecycle, OperationalLifecycle.QUEUED)
                self.assertEqual(job.run_id, f"run-{profile.value}")
                self.assertTrue(job.job_id.startswith("job-"))
                self.assertTrue(job.execution_id.startswith("execution-"))

                step = _DeterministicStep()
                controller = ExecutionController(store)
                accepted = controller.run_step(job.job_id, operation_id="operation-001", step=step)
                self.assertEqual(accepted.status, "ACCEPTED")
                self.assertEqual(step.calls, ["operation-001"])
                self.assertEqual(accepted.job.lifecycle, OperationalLifecycle.RUNNING)
                self.assertEqual(accepted.job.checkpoint.revision, 1)
                self.assertEqual(len(accepted.job.result_markers), 1)

                retrying = store.record_retry(accepted.job.job_id, expected_revision=accepted.job.revision, error_code=ErrorCode.INTERNAL.value)
                self.assertEqual(retrying.job.lifecycle, OperationalLifecycle.RETRYING)

                recreated = WorkspaceRunStore(store.root) if profile is ExecutionProfile.WORKSPACE_LOCAL else DurableTestRunStore(store.root)
                reloaded = recreated.load(job.job_id)
                self.assertEqual(reloaded.run_id, job.run_id)
                replayed = ExecutionController(recreated).run_step(reloaded.job_id, operation_id="operation-001", step=step)
                self.assertEqual(replayed.status, "REPLAYED")
                self.assertFalse(replayed.engine_called)
                self.assertEqual(step.calls, ["operation-001"])

                completed = recreated.transition_operational(
                    replayed.job.job_id,
                    expected_revision=replayed.job.revision,
                    lifecycle=OperationalLifecycle.COMPLETED,
                    terminal_outcome=TerminalOutcome.DONE,
                )
                self.assertEqual(completed.status, StoreWriteStatus.ACCEPTED)
                self.assertEqual(completed.job.terminal_outcome, TerminalOutcome.DONE)
                self.assertEqual(completed.job.lifecycle, OperationalLifecycle.COMPLETED)

    def test_checkpoint_is_monotonic_cas_protected_and_replay_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceRunStore(Path(directory) / "run")
            job = self._created(store, ExecutionProfile.WORKSPACE_LOCAL)
            checkpoint = replace(
                job.checkpoint,
                revision=1,
                engine_phase="NORMALIZED",
                progress=ProgressSnapshot("NORMALIZED", 0, 3),
                engine_state_revision=4,
                queue_revision="a" * 64,
                checkpoint_sha256="",
            )
            committed = store.commit_checkpoint(checkpoint, expected_revision=job.revision)
            self.assertEqual(committed.status, StoreWriteStatus.ACCEPTED)
            replay = store.commit_checkpoint(checkpoint, expected_revision=job.revision)
            self.assertEqual(replay.status, StoreWriteStatus.IDEMPOTENT)
            self.assertEqual(replay.job.checkpoint.revision, 1)

            stale = replace(checkpoint, engine_phase="EXTRACTED", progress=ProgressSnapshot("EXTRACTED", 1, 3), checkpoint_sha256="")
            stale_result = store.commit_checkpoint(stale, expected_revision=job.revision)
            self.assertEqual(stale_result.status, StoreWriteStatus.STALE)
            self.assertEqual(store.load(job.job_id).checkpoint.engine_phase, "NORMALIZED")

    def test_durable_recreated_stores_share_per_job_guard_without_global_serialization(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "durable"
            first = DurableTestRunStore(root)
            second = DurableTestRunStore(root)
            job_one = ExecutionJob.new(
                run_id="run-lock-one",
                profile=ExecutionProfile.DURABLE_TEST,
                scope_ref="opaque-scope",
                store_ref="opaque-store",
                job_id="job-lock-one",
                execution_id="execution-lock-one",
            )
            job_two = ExecutionJob.new(
                run_id="run-lock-two",
                profile=ExecutionProfile.DURABLE_TEST,
                scope_ref="opaque-scope",
                store_ref="opaque-store",
                job_id="job-lock-two",
                execution_id="execution-lock-two",
            )
            self.assertEqual(first.create(job_one).status, StoreWriteStatus.ACCEPTED)
            self.assertEqual(first.create(job_two).status, StoreWriteStatus.ACCEPTED)

            held = Event()
            release = Event()
            entered = Event()
            errors: list[BaseException] = []

            def hold_same_job() -> None:
                try:
                    with first._mutation(job_one.job_id):
                        held.set()
                        release.wait(timeout=2.0)
                except BaseException as exc:  # pragma: no cover - surfaced below
                    errors.append(exc)

            def enter_same_job() -> None:
                try:
                    with second._mutation(job_one.job_id):
                        entered.set()
                except BaseException as exc:  # pragma: no cover - surfaced below
                    errors.append(exc)

            holder = Thread(target=hold_same_job)
            contender = Thread(target=enter_same_job)
            holder.start()
            self.assertTrue(held.wait(timeout=2.0))
            contender.start()
            try:
                self.assertFalse(entered.wait(timeout=0.25))
            finally:
                release.set()
                holder.join(timeout=2.0)
                contender.join(timeout=2.0)
            self.assertTrue(entered.is_set())
            self.assertFalse(holder.is_alive())
            self.assertFalse(contender.is_alive())
            self.assertEqual(errors, [])

            different_attempted = Event()
            different_entered = Event()

            def enter_different_job() -> None:
                try:
                    different_attempted.set()
                    with second._mutation(job_two.job_id):
                        different_entered.set()
                except BaseException as exc:  # pragma: no cover - surfaced below
                    errors.append(exc)

            with first._mutation(job_one.job_id):
                different = Thread(target=enter_different_job)
                different.start()
                self.assertTrue(different_attempted.wait(timeout=2.0))
                self.assertTrue(different_entered.wait(timeout=2.0))
                different.join(timeout=2.0)
            self.assertFalse(different.is_alive())
            self.assertEqual(errors, [])

    def test_independent_durable_stores_reject_conflicting_same_revision_writers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "durable"
            winner_store = DurableTestRunStore(root)
            contender_entered = Event()
            contender_store = _ProbedDurableStore(root, contender_entered)
            job = self._created(winner_store, ExecutionProfile.DURABLE_TEST, run_id="run-cas")

            checkpoint_one = replace(
                job.checkpoint,
                revision=1,
                engine_phase="WRITER_ONE",
                progress=ProgressSnapshot("WRITER_ONE", 1, 3, "unit-one"),
                metadata={"cursor": "writer-one"},
                checkpoint_sha256="",
            )
            checkpoint_one = replace(checkpoint_one, checkpoint_sha256=checkpoint_one.computed_sha256())
            candidate_one = replace(
                job,
                lifecycle=OperationalLifecycle.RUNNING,
                revision=1,
                checkpoint=checkpoint_one,
                updated_at="2026-01-01T00:00:01Z",
            )
            checkpoint_two = replace(
                job.checkpoint,
                revision=1,
                engine_phase="WRITER_TWO",
                progress=ProgressSnapshot("WRITER_TWO", 1, 3, "unit-two"),
                metadata={"cursor": "writer-two"},
                checkpoint_sha256="",
            )
            checkpoint_two = replace(checkpoint_two, checkpoint_sha256=checkpoint_two.computed_sha256())
            candidate_two = replace(
                job,
                lifecycle=OperationalLifecycle.RUNNING,
                revision=1,
                checkpoint=checkpoint_two,
                updated_at="2026-01-01T00:00:02Z",
            )

            held = Event()
            release = Event()
            results: list = []
            errors: list[BaseException] = []

            def hold_guard() -> None:
                try:
                    with winner_store._mutation(job.job_id):
                        held.set()
                        release.wait(timeout=2.0)
                except BaseException as exc:  # pragma: no cover - surfaced below
                    errors.append(exc)

            def commit_contender() -> None:
                try:
                    results.append(contender_store.commit_job(candidate_two, expected_revision=job.revision))
                except BaseException as exc:  # pragma: no cover - surfaced below
                    errors.append(exc)

            holder = Thread(target=hold_guard)
            contender = Thread(target=commit_contender)
            holder.start()
            self.assertTrue(held.wait(timeout=2.0))
            contender.start()
            try:
                self.assertFalse(contender_entered.wait(timeout=0.25))
            finally:
                release.set()
                holder.join(timeout=2.0)
                contender.join(timeout=2.0)
            self.assertFalse(holder.is_alive())
            self.assertFalse(contender.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].status, StoreWriteStatus.ACCEPTED)

            stale = winner_store.commit_job(candidate_one, expected_revision=job.revision)
            self.assertEqual(stale.status, StoreWriteStatus.STALE)

            reloaded = DurableTestRunStore(root).load(job.job_id)
            self.assertEqual(reloaded.as_dict(), candidate_two.as_dict())
            self.assertEqual(reloaded.revision, 1)
            self.assertEqual(reloaded.checkpoint.metadata, {"cursor": "writer-two"})

    def test_independent_durable_store_create_races_keep_idempotency_and_conflict_semantics(self) -> None:
        def run_create_race(store_one, job_one: ExecutionJob, store_two, job_two: ExecutionJob) -> list:
            results: list = []
            errors: list[BaseException] = []
            start = Barrier(3)

            def create(store, job) -> None:
                try:
                    start.wait(timeout=2.0)
                    results.append(store.create(job))
                except BaseException as exc:  # pragma: no cover - surfaced below
                    errors.append(exc)

            first = Thread(target=create, args=(store_one, job_one))
            second = Thread(target=create, args=(store_two, job_two))
            first.start()
            second.start()
            start.wait(timeout=2.0)
            first.join(timeout=3.0)
            second.join(timeout=3.0)
            self.assertFalse(first.is_alive())
            self.assertFalse(second.is_alive())
            self.assertEqual(errors, [])
            return results

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "identical"
            identical = ExecutionJob.new(
                run_id="run-create-identical",
                profile=ExecutionProfile.DURABLE_TEST,
                scope_ref="opaque-scope",
                store_ref="opaque-store",
                job_id="job-create-identical",
                execution_id="execution-create-identical",
            )
            gate = _CreateRaceGate()
            results = run_create_race(
                _GatedCreateStore(root, gate),
                identical,
                _GatedCreateStore(root, gate),
                identical,
            )
            self.assertCountEqual([item.status for item in results], [StoreWriteStatus.ACCEPTED, StoreWriteStatus.IDEMPOTENT])
            self.assertEqual(len(list((root / "jobs").glob("*.json"))), 1)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "incompatible"
            first_job = ExecutionJob.new(
                run_id="run-create-one",
                profile=ExecutionProfile.DURABLE_TEST,
                scope_ref="opaque-scope",
                store_ref="opaque-store",
                job_id="job-create-conflict",
                execution_id="execution-create-one",
            )
            second_job = ExecutionJob.new(
                run_id="run-create-two",
                profile=ExecutionProfile.DURABLE_TEST,
                scope_ref="opaque-scope",
                store_ref="opaque-store",
                job_id="job-create-conflict",
                execution_id="execution-create-two",
            )
            gate = _CreateRaceGate()
            results = run_create_race(
                _GatedCreateStore(root, gate),
                first_job,
                _GatedCreateStore(root, gate),
                second_job,
            )
            self.assertCountEqual([item.status for item in results], [StoreWriteStatus.ACCEPTED, StoreWriteStatus.CONFLICT])
            self.assertEqual(len(list((root / "jobs").glob("*.json"))), 1)

    def test_restart_resume_uses_last_committed_checkpoint_and_preserves_ordered_unit_refs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for profile, store in self._profiles(root):
                job = self._created(store, profile, run_id=f"run-order-{profile.value}")
                checkpoint = replace(
                    job.checkpoint,
                    revision=1,
                    engine_phase="TRANSLATING",
                    progress=ProgressSnapshot("TRANSLATING", 1, 3, "doc-001-page-0001"),
                    engine_state_revision=8,
                    queue_revision="b" * 64,
                    metadata={"cursor": "unit-001"},
                    checkpoint_sha256="",
                )
                first = store.commit_checkpoint(checkpoint, expected_revision=job.revision)
                self.assertTrue(first.accepted)
                recreated = WorkspaceRunStore(store.root) if profile is ExecutionProfile.WORKSPACE_LOCAL else DurableTestRunStore(store.root)
                resumed = recreated.load(job.job_id)
                self.assertEqual(resumed.run_id, job.run_id)
                self.assertEqual(resumed.checkpoint.progress.current_work_unit, "doc-001-page-0001")
                self.assertEqual(resumed.checkpoint.progress.completed_work_units, 1)
                self.assertEqual(resumed.checkpoint.metadata, {"cursor": "unit-001"})
                self.assertEqual(resumed.checkpoint.queue_revision, "b" * 64)

    def test_corrupt_missing_and_unknown_version_state_fail_closed_without_source_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = DurableTestRunStore(root / "durable")
            job = self._created(store, ExecutionProfile.DURABLE_TEST)
            path = store._path_for(job.job_id)
            path.write_text("{\"schema_version\":", encoding="utf-8")
            with self.assertRaises(KSlideError) as raised:
                DurableTestRunStore(root / "durable").load(job.job_id)
            self.assertEqual(raised.exception.code, ErrorCode.STATE_CORRUPT)
            self.assertNotIn(str(root), json.dumps(raised.exception.as_dict()))

            path.unlink()
            with self.assertRaises(KSlideError) as raised:
                store.load(job.job_id)
            self.assertEqual(raised.exception.code, ErrorCode.EXECUTION_NOT_FOUND)

            store.create(job)
            value = json.loads(path.read_text(encoding="utf-8"))
            value["schema_version"] = "99.0"
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(KSlideError) as raised:
                store.load(job.job_id)
            self.assertIn(raised.exception.code, {ErrorCode.STATE_CORRUPT, ErrorCode.EXECUTION_UNSUPPORTED_VERSION})

    def test_cancellation_survives_recreation_is_idempotent_and_cannot_be_review(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = DurableTestRunStore(root / "durable")
            job = self._created(store, ExecutionProfile.DURABLE_TEST)
            requested = store.request_cancellation(job.job_id, expected_revision=job.revision)
            self.assertEqual(requested.status, StoreWriteStatus.ACCEPTED)
            recreated = DurableTestRunStore(root / "durable")
            pending = recreated.load(job.job_id)
            self.assertTrue(pending.cancellation.requested)
            self.assertEqual(recreated.request_cancellation(job.job_id, expected_revision=0).status, StoreWriteStatus.IDEMPOTENT)
            step = _DeterministicStep()
            canceled = ExecutionController(recreated).run_step(job.job_id, operation_id="never-started", step=step)
            self.assertEqual(canceled.status, "CANCELED")
            self.assertEqual(canceled.job.lifecycle, OperationalLifecycle.CANCELED)
            self.assertEqual(canceled.job.terminal_outcome, TerminalOutcome.CANCELED)
            self.assertNotEqual(canceled.job.terminal_outcome, TerminalOutcome.NEEDS_REVIEW)
            self.assertEqual(step.calls, [])

    def test_semantic_review_is_resumable_but_is_not_cancellation_or_processing_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceRunStore(Path(directory) / "run")
            job = self._created(store, ExecutionProfile.WORKSPACE_LOCAL)
            started = store.transition_operational(job.job_id, expected_revision=job.revision, lifecycle=OperationalLifecycle.RUNNING)
            review = store.transition_operational(started.job.job_id, expected_revision=started.job.revision, lifecycle=OperationalLifecycle.COMPLETED, terminal_outcome=TerminalOutcome.NEEDS_REVIEW)
            self.assertEqual(review.job.resume_eligibility.value, "ELIGIBLE")
            step = _DeterministicStep()
            resumed = ExecutionController(store).run_step(job.job_id, operation_id="repair-001", step=step)
            self.assertEqual(resumed.status, "ACCEPTED")
            self.assertEqual(resumed.job.lifecycle, OperationalLifecycle.RETRYING)
            self.assertEqual(resumed.job.terminal_outcome, TerminalOutcome.NONE)

    def test_retry_state_is_bounded_restartable_and_exhaustion_is_processing_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = DurableTestRunStore(root / "durable")
            job = self._created(store, ExecutionProfile.DURABLE_TEST)
            first = store.record_retry(job.job_id, expected_revision=job.revision, error_code=ErrorCode.INTERNAL.value)
            self.assertEqual(first.status, StoreWriteStatus.ACCEPTED)
            self.assertEqual(first.job.retry.attempt, 1)
            self.assertEqual(first.job.retry.disposition, RetryDisposition.RETRYABLE)
            recreated = DurableTestRunStore(root / "durable")
            exhausted = recreated.record_retry(job.job_id, expected_revision=first.job.revision, error_code=ErrorCode.INTERNAL.value)
            self.assertEqual(exhausted.status, StoreWriteStatus.ACCEPTED)
            self.assertEqual(exhausted.job.retry.disposition, RetryDisposition.EXHAUSTED)
            self.assertEqual(exhausted.job.lifecycle, OperationalLifecycle.PROCESSING_FAILED)
            self.assertEqual(exhausted.job.terminal_outcome, TerminalOutcome.PROCESSING_FAILED)
            self.assertEqual(recreated.record_retry(job.job_id, expected_revision=0, error_code=ErrorCode.INTERNAL.value).status, StoreWriteStatus.IDEMPOTENT)

    def test_adversarial_canaries_are_rejected_from_control_metadata_and_errors(self) -> None:
        secret = "AccessKey=synthetic-secret"
        source = "source-content-fixture"
        with self.assertRaises(KSlideError) as raised:
            new_execution_job(secret, profile=ExecutionProfile.DURABLE_TEST, scope_ref="opaque-scope", store_ref="opaque-store")
        self.assertNotIn(secret, str(raised.exception))
        with self.assertRaises(KSlideError) as raised:
            RunCheckpoint.initial(run_id="run-safe", job_id="job-safe", execution_id="execution-safe").__class__(
                run_id="run-safe",
                job_id="job-safe",
                execution_id="execution-safe",
                revision=1,
                engine_phase="RUNNING",
                progress=ProgressSnapshot("RUNNING", 0, 0),
                metadata={"source_text": source},
            )
        self.assertNotIn(source, str(raised.exception))

        with tempfile.TemporaryDirectory() as directory:
            store = DurableTestRunStore(Path(directory) / "durable")
            job = self._created(store, ExecutionProfile.DURABLE_TEST)
            with self.assertRaises(KSlideError) as raised:
                store.record_retry(job.job_id, expected_revision=job.revision, error_code=secret)
            self.assertNotIn(secret, json.dumps(raised.exception.as_dict()))
            serialized = json.dumps(execution_metadata(store.load(job.job_id)))
            self.assertNotIn(secret, serialized)
            self.assertNotIn(source, serialized)

    def test_failure_classifier_keeps_semantic_verification_out_of_operational_retry(self) -> None:
        self.assertEqual(classify_operational_failure(ErrorCode.INTERNAL), "RETRYABLE")
        self.assertEqual(classify_operational_failure(ErrorCode.VERIFICATION_FAILED), "SEMANTIC_REPAIR")
        self.assertEqual(classify_operational_failure(ErrorCode.INPUT_NOT_FOUND), "NOT_RETRYABLE")
        with tempfile.TemporaryDirectory() as directory:
            store = DurableTestRunStore(Path(directory) / "durable")
            job = self._created(store, ExecutionProfile.DURABLE_TEST)
            with self.assertRaises(KSlideError):
                store.record_retry(job.job_id, expected_revision=job.revision, error_code=ErrorCode.VERIFICATION_FAILED.value)

    def test_workspace_status_exposes_only_source_free_execution_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "slide.png"
            source.write_bytes(b"\x89PNG\r\n\x1a\nstatus-fixture")
            run = prepare_run(root, explicit_paths=[str(source)], environment_identity=reference_environment())
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(main(["status", "--root", str(root), "--run", run.name, "--json"]), 0)
            value = json.loads(output.getvalue())
            execution = value["execution"]
            self.assertEqual(execution["job_id"], f"job-{run.name}")
            self.assertEqual(execution["profile"], "workspace_local")
            self.assertEqual(execution["engine_phase"], "INPUT_VALIDATED")
            self.assertNotIn(str(source), output.getvalue())


if __name__ == "__main__":
    unittest.main()
