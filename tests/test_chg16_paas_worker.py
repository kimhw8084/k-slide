from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from k_slide.errors import ErrorCode, KSlideError
from k_slide.execution import (
    EngineStepResult,
    ExecutionProfile,
    OperationalLifecycle,
    ProgressSnapshot,
    RunCheckpoint,
    StoreWriteStatus,
    TerminalOutcome,
    new_execution_job,
    run_store_for_profile,
)
from k_slide.paas import (
    PaaSController,
    PaaSJobRequest,
    PaaSWorker,
    ReferencePaaSJobService,
    ReferencePaaSRunStore,
    ReferenceWorkerEngine,
    RuntimeIdentity,
)
from tests.reference_fixtures import reference_runtime


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = reference_runtime()


class _FailingEngine:
    def __init__(self, code: ErrorCode) -> None:
        self.code = code
        self.calls = 0

    def operation_id(self, job):
        return f"{job.execution_id}-failure-{job.checkpoint.revision + 1}"

    def step(self, checkpoint: RunCheckpoint, operation_id: str) -> EngineStepResult:
        self.calls += 1
        raise KSlideError(self.code, "synthetic failure")


class _ReviewEngine:
    def operation_id(self, job):
        return f"{job.execution_id}-review-{job.checkpoint.revision + 1}"

    def step(self, checkpoint: RunCheckpoint, operation_id: str) -> EngineStepResult:
        next_checkpoint = replace(
            checkpoint,
            revision=checkpoint.revision + 1,
            engine_phase="NEEDS_REVIEW",
            progress=ProgressSnapshot("NEEDS_REVIEW", 0, checkpoint.progress.total_work_units),
            checkpoint_sha256="",
        )
        return EngineStepResult(next_checkpoint)


def _submit(service: ReferencePaaSJobService, *, run_id: str = "run-paas", total: int = 2, max_attempts: int = 3):
    return PaaSController(service).submit(
        PaaSJobRequest(
            run_id=run_id,
            scope_ref="opaque-scope",
            store_ref="opaque-store",
            runtime_identity=RUNTIME,
            total_work_units=total,
            max_attempts=max_attempts,
        )
    )


def _worker_process(root: Path, job_id: str, *, until_terminal: bool = False) -> subprocess.CompletedProcess[str]:
    command = [
        sys.executable,
        "-m",
        "k_slide.worker",
        "--service-root",
        str(root),
        "--job-id",
        job_id,
        "--worker-id",
        "independent-worker",
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
    if until_terminal:
        command.append("--until-terminal")
    environment = {**os.environ, "PYTHONPATH": str(ROOT / "src") + os.pathsep + str(ROOT)}
    return subprocess.run(command, cwd=ROOT, env=environment, capture_output=True, text=True, check=False)


class PaaSWorkerIntegrationTests(unittest.TestCase):
    def test_submission_is_prompt_and_reconnectable_without_worker_lifetime(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            service = ReferencePaaSJobService(root)
            receipt = _submit(service)
            self.assertEqual(receipt.status, StoreWriteStatus.ACCEPTED)
            self.assertTrue(receipt.job_id)
            repeated = _submit(service)
            self.assertEqual(repeated.status, StoreWriteStatus.IDEMPOTENT)
            queued = service.inspect(receipt.identity)
            self.assertEqual(queued.lifecycle, OperationalLifecycle.QUEUED)
            self.assertEqual(queued.progress["completed_work_units"], 0)

            first = _worker_process(root, receipt.job_id)
            self.assertEqual(first.returncode, 0, first.stderr)
            first_status = json.loads(first.stdout)
            self.assertEqual(first_status["status"], "ACCEPTED")
            self.assertEqual(first_status["progress"]["completed_work_units"], 1)

            # The original controller/browser is gone. A reconstructed
            # controller observes the same durable job and its progress.
            reconstructed = PaaSController(ReferencePaaSJobService(root))
            observed = reconstructed.reconnect(receipt.identity)
            self.assertEqual(observed.lifecycle, OperationalLifecycle.RUNNING)
            self.assertEqual(observed.progress["completed_work_units"], 1)

            second = _worker_process(root, receipt.job_id, until_terminal=True)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(json.loads(second.stdout)["status"], "DONE")
            self.assertEqual(reconstructed.status(receipt.identity).terminal_outcome, TerminalOutcome.DONE)

    def test_durable_profile_uses_paas_adapter_not_the_ksa06_test_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = run_store_for_profile(ExecutionProfile.DURABLE, Path(directory))
            self.assertIsInstance(store, ReferencePaaSRunStore)
            job = new_execution_job("run-profile", profile=ExecutionProfile.DURABLE, scope_ref="scope", store_ref="store")
            self.assertEqual(store.create(job).status, StoreWriteStatus.ACCEPTED)

    def test_worker_interruption_restarts_from_last_committed_checkpoint_without_duplicate_markers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            service = ReferencePaaSJobService(root)
            receipt = _submit(service, run_id="run-interrupt", total=2)
            interrupt_code = """
from k_slide.paas import PaaSWorker, ReferencePaaSJobService, RuntimeIdentity
class Interrupting:
    def operation_id(self, job):
        return f'{job.execution_id}-interrupt-{job.checkpoint.revision + 1}'
    def step(self, checkpoint, operation_id):
        raise KeyboardInterrupt()
service = ReferencePaaSJobService(__import__('pathlib').Path(__import__('sys').argv[1]))
from tests.reference_fixtures import reference_runtime
runtime = reference_runtime()
PaaSWorker(service, worker_id='interrupted-worker', runtime_identity=runtime, engine=Interrupting()).run_once(__import__('sys').argv[2])
"""
            environment = {**os.environ, "PYTHONPATH": str(ROOT / "src") + os.pathsep + str(ROOT)}
            interrupted = subprocess.run([sys.executable, "-c", interrupt_code, str(root), receipt.job_id], cwd=ROOT, env=environment, capture_output=True, text=True, check=False)
            self.assertNotEqual(interrupted.returncode, 0)
            after_interrupt = service.inspect(receipt.identity)
            self.assertEqual(after_interrupt.checkpoint_revision, 0)
            self.assertEqual(after_interrupt.lifecycle, OperationalLifecycle.RUNNING)

            resumed = _worker_process(root, receipt.job_id, until_terminal=True)
            self.assertEqual(resumed.returncode, 0, resumed.stderr)
            self.assertEqual(json.loads(resumed.stdout)["status"], "DONE")
            store = service.open_store(receipt.identity)
            job = store.load(receipt.job_id)
            self.assertEqual(job.checkpoint.revision, 2)
            self.assertEqual(len(job.result_markers), 2)
            replay = PaaSWorker(service, worker_id="reconnected-worker", runtime_identity=RUNTIME, engine=ReferenceWorkerEngine()).run_once(receipt.identity)
            self.assertEqual(replay.status, "DONE")
            self.assertEqual(len(service.open_store(receipt.identity).load(receipt.job_id).result_markers), 2)

    def test_cancellation_crosses_controller_worker_process_boundary_and_is_acknowledged(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            service = ReferencePaaSJobService(root)
            receipt = _submit(service, run_id="run-cancel", total=3)
            requested = PaaSController(service).cancel(receipt.identity)
            self.assertEqual(requested.cancellation["requested"], True)
            self.assertEqual(requested.cancellation["acknowledged"], False)
            result = _worker_process(root, receipt.job_id)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["status"], "CANCELED")
            reconstructed = ReferencePaaSJobService(root)
            status = reconstructed.inspect(receipt.identity)
            self.assertEqual(status.lifecycle, OperationalLifecycle.CANCELED)
            self.assertEqual(status.terminal_outcome, TerminalOutcome.CANCELED)
            self.assertTrue(status.cancellation["acknowledged"])

    def test_retryable_failures_are_bounded_and_nonretryable_failures_are_processing_failed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            service = ReferencePaaSJobService(root)
            receipt = _submit(service, run_id="run-retry", total=1, max_attempts=2)
            failing = _FailingEngine(ErrorCode.INTERNAL)
            result = PaaSWorker(service, worker_id="retry-worker", runtime_identity=RUNTIME, engine=failing).run_until_terminal(receipt.identity, max_steps=4)
            self.assertEqual(result.status, "PROCESSING_FAILED")
            self.assertEqual(result.failure_class.value, "RETRYABLE")
            self.assertEqual(result.job.retry.attempt, 2)
            self.assertEqual(failing.calls, 2)

            nonretry_receipt = _submit(service, run_id="run-nonretry", total=1)
            nonretry = PaaSWorker(service, worker_id="nonretry-worker", runtime_identity=RUNTIME, engine=_FailingEngine(ErrorCode.INPUT_NOT_FOUND)).run_once(nonretry_receipt.identity)
            self.assertEqual(nonretry.status, "PROCESSING_FAILED")
            self.assertEqual(nonretry.failure_class.value, "NOT_RETRYABLE")
            self.assertEqual(nonretry.job.retry.disposition.value, "NOT_RETRYABLE")

    def test_semantic_review_and_semantic_failure_do_not_become_processing_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            service = ReferencePaaSJobService(root)
            review_receipt = _submit(service, run_id="run-review", total=1)
            review = PaaSWorker(service, worker_id="review-worker", runtime_identity=RUNTIME, engine=_ReviewEngine()).run_once(review_receipt.identity)
            self.assertEqual(review.status, "NEEDS_REVIEW")
            self.assertEqual(review.job.lifecycle, OperationalLifecycle.COMPLETED)
            self.assertEqual(review.job.terminal_outcome, TerminalOutcome.NEEDS_REVIEW)

            semantic_receipt = _submit(service, run_id="run-semantic", total=1)
            semantic = PaaSWorker(service, worker_id="semantic-worker", runtime_identity=RUNTIME, engine=_FailingEngine(ErrorCode.VERIFICATION_FAILED)).run_once(semantic_receipt.identity)
            self.assertEqual(semantic.status, "SEMANTIC_REPAIR")
            self.assertEqual(semantic.failure_class.value, "SEMANTIC_REPAIR")
            self.assertNotEqual(semantic.job.terminal_outcome, TerminalOutcome.PROCESSING_FAILED)

    def test_runtime_binding_is_exact_and_mismatch_fails_closed_without_identity_switch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            service = ReferencePaaSJobService(root)
            receipt = _submit(service, run_id="run-binding")
            mismatched = RuntimeIdentity("runtime-other", RUNTIME.model_identity, RUNTIME.ocr_identity, RUNTIME.termbase_identity, environment_identity=RUNTIME.environment_identity)
            worker = PaaSWorker(service, worker_id="wrong-runtime", runtime_identity=mismatched, engine=ReferenceWorkerEngine())
            with self.assertRaises(KSlideError) as raised:
                worker.run_once(receipt.identity)
            self.assertEqual(raised.exception.code, ErrorCode.EXECUTION_CONFLICT)
            self.assertEqual(service.inspect(receipt.identity).lifecycle, OperationalLifecycle.QUEUED)

    def test_recreated_paas_store_preserves_cas_stale_and_idempotent_results(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            service = ReferencePaaSJobService(root)
            receipt = _submit(service, run_id="run-cas-paas", total=1)
            first_store = service.open_store(receipt.identity)
            second_store = ReferencePaaSRunStore(root / "job-service" / "run-store")
            job = first_store.load(receipt.job_id)
            first_checkpoint = replace(
                job.checkpoint,
                revision=1,
                engine_phase="TRANSLATING",
                progress=ProgressSnapshot("TRANSLATING", 0, 1),
                checkpoint_sha256="",
            )
            second_checkpoint = replace(
                job.checkpoint,
                revision=1,
                engine_phase="NORMALIZED",
                progress=ProgressSnapshot("NORMALIZED", 0, 1),
                checkpoint_sha256="",
            )
            accepted = first_store.commit_checkpoint(first_checkpoint, expected_revision=job.revision)
            self.assertEqual(accepted.status, StoreWriteStatus.ACCEPTED)
            stale = second_store.commit_checkpoint(second_checkpoint, expected_revision=job.revision)
            self.assertEqual(stale.status, StoreWriteStatus.STALE)
            replay = second_store.commit_checkpoint(first_checkpoint, expected_revision=job.revision)
            self.assertEqual(replay.status, StoreWriteStatus.IDEMPOTENT)
            self.assertEqual(service.inspect(receipt.identity).engine_phase, "TRANSLATING")

    def test_access_key_and_source_references_never_enter_paas_records_or_status(self) -> None:
        secret = "AccessKey=synthetic-paas-secret"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            service = ReferencePaaSJobService(root)
            receipt = _submit(service, run_id="run-hygiene")
            serialized = "\n".join(path.read_text(encoding="utf-8") for path in root.rglob("*.json"))
            self.assertNotIn(secret, serialized)
            self.assertNotIn(str(root), serialized)
            self.assertNotIn(secret, json.dumps(service.inspect(receipt.identity).as_dict()))
            with self.assertRaises(KSlideError) as raised:
                RuntimeIdentity(secret, "model-pinned", "ocr-pinned", "termbase-pinned")
            self.assertNotIn(secret, str(raised.exception))


if __name__ == "__main__":
    unittest.main()
