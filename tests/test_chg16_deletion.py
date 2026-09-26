from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from k_slide.deletion import (
    DeletionArtifactClass,
    DeletionOutcome,
    DeletionState,
    LegalHoldStatus,
    ReferenceLegalHoldProvider,
    cleanup_operational_metadata,
    delete_scoped_run,
    delete_workspace_run,
)
from k_slide.errors import ErrorCode, KSlideError
from k_slide.evidence_ir import stable_revision
from k_slide.execution import ExecutionJob, ExecutionProfile, OperationalLifecycle, TerminalOutcome, WorkspaceRunStore
from k_slide.io import atomic_write_json
from k_slide.paas import AuthorizedScopeContext, DurableJobIdentity, PaaSController, PaaSJobRequest, PaaSWorker, ReferencePaaSJobService, ReferenceWorkerEngine
from k_slide.retention import cleanup_expired_runs
from k_slide.retention_policy import RetentionPolicy
from k_slide.storage import StorageArtifact, StorageLayout
from k_slide.telemetry import TelemetryEvent, TelemetryEventType, TelemetryLifecycle, TelemetryMachineId, TelemetryReference, TelemetryReferenceKind, TelemetryWriter
from tests.reference_fixtures import reference_runtime


class CHG16DeletionTests(unittest.TestCase):
    def _context(self) -> AuthorizedScopeContext:
        return AuthorizedScopeContext("admin-ref", "workspace-ref", "workspace")

    def _provider(self, run_ref: str) -> ReferenceLegalHoldProvider:
        provider = ReferenceLegalHoldProvider()
        provider.set_release(scope_ref="workspace", run_ref=run_ref)
        return provider

    def _operational_root(self, root: Path) -> Path:
        operational = root.parent / f"central-{root.name}"
        operational.mkdir()
        return operational

    def _workspace_run(self, root: Path, run_id: str = "run-delete", created_at: str = "2020-01-01T00:00:00Z") -> Path:
        run = root / ".k-slide-runs" / run_id
        run.mkdir(parents=True, mode=0o700)
        (run / "RUN_STATE.json").write_text(
            json.dumps({"run_id": run_id, "phase": "COMPLETE", "created_at": created_at, "updated_at": created_at}),
            encoding="utf-8",
        )
        for relative in (
            "inputs/source-001.png", "normalized/slide.png", "native/slide.json", "regions/r.png", "evidence/unit.json",
            "translations/unit.json", "ir/unit.json", "verification/summary.json", "05_final_report.md", "metrics.json",
            "RUN_COMPLETE.md", "unknown-run-object.bin",
        ):
            path = run / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("Korean 검토 prompt AccessKey=canary", encoding="utf-8")
        return run

    def test_explicit_delete_removes_run_content_and_keeps_only_source_free_audit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = self._workspace_run(root)
            provider = self._provider(run.name)
            operational = self._operational_root(root)
            result = delete_workspace_run(root, run_ref=run.name, deletion_id="delete-1", scope_context=self._context(), hold_provider=provider, operational_root=operational)
            self.assertEqual(result.outcome, DeletionOutcome.COMPLETE)
            self.assertFalse(run.exists())
            audit = next(operational.glob("_deletions/workspace/run-delete/delete-1.json")).read_text(encoding="utf-8")
            self.assertNotIn("Korean", audit)
            self.assertNotIn("prompt", audit)
            self.assertNotIn("AccessKey", audit)
            self.assertNotIn(str(root), audit)

    def test_hold_unknown_blocks_and_fresh_release_allows_same_request(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = self._workspace_run(root)
            provider = ReferenceLegalHoldProvider(default_status=LegalHoldStatus.UNKNOWN)
            operational = self._operational_root(root)
            blocked = delete_workspace_run(root, run_ref=run.name, deletion_id="delete-hold", scope_context=self._context(), hold_provider=provider, operational_root=operational)
            self.assertEqual(blocked.outcome, DeletionOutcome.BLOCKED)
            self.assertTrue(run.exists())
            provider.set_hold(scope_ref="workspace", run_ref=run.name)
            self.assertEqual(delete_workspace_run(root, run_ref=run.name, deletion_id="delete-hold", scope_context=self._context(), hold_provider=provider, operational_root=operational).outcome, DeletionOutcome.BLOCKED)
            provider.set_release(scope_ref="workspace", run_ref=run.name)
            self.assertEqual(delete_workspace_run(root, run_ref=run.name, deletion_id="delete-hold", scope_context=self._context(), hold_provider=provider, operational_root=operational).outcome, DeletionOutcome.COMPLETE)

    def test_partial_retry_and_dry_run_do_not_replay_completed_targets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = self._workspace_run(root, "run-partial")
            provider = self._provider(run.name)
            operational = self._operational_root(root)
            self.assertEqual(delete_workspace_run(root, run_ref=run.name, deletion_id="dry", scope_context=self._context(), hold_provider=provider, operational_root=operational, dry_run=True).outcome, DeletionOutcome.PLANNED)
            self.assertTrue(run.exists())
            calls = 0

            def fail_once(_candidate):
                nonlocal calls
                calls += 1
                return calls == 1

            partial = delete_workspace_run(root, run_ref=run.name, deletion_id="partial", scope_context=self._context(), hold_provider=provider, operational_root=operational, failure_injector=fail_once)
            self.assertEqual(partial.state, DeletionState.PARTIAL)
            with self.assertRaises(KSlideError) as fenced:
                StorageLayout.for_workspace(run).write_text(StorageArtifact.REPORT, "resurrected.md", "must be fenced")
            self.assertEqual(fenced.exception.code, ErrorCode.EXECUTION_CONFLICT)
            self.assertFalse((run / "resurrected.md").exists())
            complete = delete_workspace_run(root, run_ref=run.name, deletion_id="partial", scope_context=self._context(), hold_provider=provider, operational_root=operational)
            self.assertEqual(complete.outcome, DeletionOutcome.COMPLETE)
            self.assertFalse(run.exists())
            self.assertEqual(delete_workspace_run(root, run_ref=run.name, deletion_id="partial", scope_context=self._context(), hold_provider=provider, operational_root=operational).outcome, DeletionOutcome.COMPLETE)

    def test_retention_and_operational_metadata_ttls_are_separate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = self._workspace_run(root, "run-expired")
            provider = self._provider(run.name)
            operational = self._operational_root(root)
            result = cleanup_expired_runs(root, RetentionPolicy("1.0", 1, 100), now=datetime(2026, 1, 20, tzinfo=timezone.utc), scope_context=self._context(), hold_provider=provider, operational_root=operational)
            self.assertEqual({item["run_id"] for item in result["removed"]}, {run.name})
            audit = operational / "_deletions"
            self.assertTrue(list(audit.rglob("*.json")))
            cleanup_operational_metadata(root, RetentionPolicy("1.0", 100, 1), scope_context=self._context(), hold_provider=provider, operational_root=operational, now=datetime.now(timezone.utc) + timedelta(days=2))
            self.assertFalse(list(audit.rglob("*.json")))

    def test_scoped_paas_deletion_invalidates_content_and_references(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = AuthorizedScopeContext("user-a", "workspace-a", "scope-a")
            service = ReferencePaaSJobService(root)
            receipt = PaaSController(service, scope_context=context).submit(PaaSJobRequest("run-paas-delete", "scope-a", "store-paas-delete", reference_runtime(), total_work_units=1))
            PaaSWorker(service, worker_id="worker-a", runtime_identity=reference_runtime(), engine=ReferenceWorkerEngine(), scope_context=context).run_until_terminal(receipt.identity)
            content = service.content_layout(receipt.identity, scope_context=context)
            content.write_text(StorageArtifact.SOURCE_SNAPSHOT, "inputs/source.png", "content")
            provider = ReferenceLegalHoldProvider()
            provider.set_release(scope_ref="scope-a", run_ref="run-paas-delete")
            result = service.delete_run(receipt.identity, deletion_id="delete-paas", scope_context=context, hold_provider=provider)
            self.assertEqual(result.outcome, DeletionOutcome.COMPLETE)
            self.assertFalse(content.durable_root.exists())
            with self.assertRaises(Exception):
                service.resolve_references(receipt.identity, scope_context=context)
            self.assertIsNone(service.queue(scope_context=context).active_job_id)

    def test_scoped_complete_replay_uses_typed_identity_after_control_removal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = AuthorizedScopeContext("user-replay", "workspace-replay", "scope-replay")
            service = ReferencePaaSJobService(root)
            receipt = PaaSController(service, scope_context=context).submit(PaaSJobRequest("run-replay", "scope-replay", "store-replay", reference_runtime(), total_work_units=1))
            PaaSWorker(service, worker_id="worker-replay", runtime_identity=reference_runtime(), engine=ReferenceWorkerEngine(), scope_context=context).run_until_terminal(receipt.identity)
            content = service.content_layout(receipt.identity, scope_context=context)
            content.write_text(StorageArtifact.SOURCE_SNAPSHOT, "inputs/source.png", "content")
            provider = ReferenceLegalHoldProvider()
            provider.set_release(scope_ref="scope-replay", run_ref="run-replay")
            first = service.delete_run(receipt.identity, deletion_id="delete-replay", scope_context=context, hold_provider=provider)
            self.assertEqual(first.outcome, DeletionOutcome.COMPLETE)
            control = service._scope_control_path(context)
            queue = service._scope_queue_path(context)
            control_before = control.read_bytes()
            queue_before = queue.read_bytes()
            self.assertFalse(service._scope_record_path(context, receipt.job_id).exists())
            self.assertFalse((service._scope_root(context) / "run-store" / "jobs" / f"{receipt.job_id}.json").exists())
            self.assertFalse(content.durable_root.exists())

            replay = service.delete_run(receipt.identity, deletion_id="delete-replay", scope_context=context, hold_provider=provider)
            self.assertEqual(replay.outcome, DeletionOutcome.COMPLETE)
            self.assertEqual(control_before, control.read_bytes())
            self.assertEqual(queue_before, queue.read_bytes())
            with self.assertRaises(KSlideError) as different_id:
                service.delete_run(receipt.identity, deletion_id="delete-replay-again", scope_context=context, hold_provider=provider)
            self.assertEqual(different_id.exception.code, ErrorCode.EXECUTION_CONFLICT)
            mismatching_identity = DurableJobIdentity(
                "different-run",
                receipt.identity.job_id,
                receipt.identity.execution_id,
                receipt.identity.scope_ref,
                receipt.identity.store_ref,
            )
            with self.assertRaises(KSlideError) as mismatching_typed_identity:
                service.delete_run(mismatching_identity, deletion_id="delete-replay", scope_context=context, hold_provider=provider)
            self.assertEqual(mismatching_typed_identity.exception.code, ErrorCode.EXECUTION_NOT_FOUND)
            self.assertEqual(mismatching_typed_identity.exception.details, {})

    def test_completed_scoped_replay_rejects_recreated_generation_without_touching_new_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = AuthorizedScopeContext("user-reuse", "workspace-reuse", "scope-reuse")
            service = ReferencePaaSJobService(root)
            controller = PaaSController(service, scope_context=context)
            original = controller.submit(PaaSJobRequest("run-reuse", "scope-reuse", "store-reuse", reference_runtime("old"), total_work_units=1))
            PaaSWorker(service, worker_id="worker-reuse", runtime_identity=reference_runtime("old"), engine=ReferenceWorkerEngine(), scope_context=context).run_until_terminal(original.identity)
            provider = ReferenceLegalHoldProvider()
            provider.set_release(scope_ref="scope-reuse", run_ref="run-reuse")
            first = service.delete_run(original.identity, deletion_id="delete-reuse", scope_context=context, hold_provider=provider)
            self.assertEqual(first.outcome, DeletionOutcome.COMPLETE)

            recreated = controller.submit(
                PaaSJobRequest(
                    "run-reuse",
                    "scope-reuse",
                    "store-reuse",
                    reference_runtime("new"),
                    total_work_units=1,
                    job_id=original.identity.job_id,
                    execution_id=original.identity.execution_id,
                )
            )
            self.assertEqual(recreated.identity, original.identity)
            content = service.content_layout(recreated.identity, scope_context=context)
            content.write_text(StorageArtifact.SOURCE_SNAPSHOT, "inputs/recreated.txt", "new generation content")
            record_path = service._scope_record_path(context, recreated.job_id)
            job_path = service._scope_root(context) / "run-store" / "jobs" / f"{recreated.job_id}.json"
            control = service._scope_control_path(context)
            queue = service._scope_queue_path(context)
            before = {path: path.read_bytes() for path in (record_path, job_path, control, queue)}
            content_before = (content.durable_root / "inputs" / "recreated.txt").read_bytes()

            stale = service.delete_run(original.identity, deletion_id="delete-reuse", scope_context=context, hold_provider=provider)
            self.assertEqual(stale.outcome, DeletionOutcome.BLOCKED)
            self.assertEqual(stale.error_code, "TARGET_IDENTITY_MISMATCH")
            self.assertTrue((content.durable_root / "inputs" / "recreated.txt").is_file())
            self.assertEqual(content_before, (content.durable_root / "inputs" / "recreated.txt").read_bytes())
            self.assertEqual(before, {path: path.read_bytes() for path in (record_path, job_path, control, queue)})

    def test_completed_workspace_replay_with_no_recreated_generation_stays_complete(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = self._workspace_run(root, "run-workspace-replay")
            operational = self._operational_root(root)
            provider = self._provider(run.name)
            first = delete_workspace_run(root, run_ref=run.name, deletion_id="delete-workspace-replay", scope_context=self._context(), hold_provider=provider, operational_root=operational)
            self.assertEqual(first.outcome, DeletionOutcome.COMPLETE)
            audit = operational / "_deletions" / "workspace" / run.name / "delete-workspace-replay.json"
            audit_before = audit.read_bytes()
            replay = delete_workspace_run(root, run_ref=run.name, deletion_id="delete-workspace-replay", scope_context=self._context(), hold_provider=provider, operational_root=operational)
            self.assertEqual(replay.outcome, DeletionOutcome.COMPLETE)
            self.assertEqual(audit_before, audit.read_bytes())

    def test_completed_workspace_replay_rejects_recreated_generation_without_touching_new_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = self._workspace_run(root, "run-workspace-reuse")
            operational = self._operational_root(root)
            provider = self._provider(run.name)
            first = delete_workspace_run(root, run_ref=run.name, deletion_id="delete-workspace-reuse", scope_context=self._context(), hold_provider=provider, operational_root=operational)
            self.assertEqual(first.outcome, DeletionOutcome.COMPLETE)

            recreated = self._workspace_run(root, run.name, created_at="2021-01-01T00:00:00Z")
            store = WorkspaceRunStore(recreated)
            job = ExecutionJob.new(run_id=recreated.name, profile=ExecutionProfile.WORKSPACE_LOCAL, scope_ref="workspace", store_ref="store-workspace-reuse")
            created = store.create(job).job
            state_before = (recreated / "RUN_STATE.json").read_bytes()
            job_before = (recreated / "EXECUTION_JOB.json").read_bytes()

            stale = delete_workspace_run(root, run_ref=run.name, deletion_id="delete-workspace-reuse", scope_context=self._context(), hold_provider=provider, operational_root=operational)
            self.assertEqual(stale.outcome, DeletionOutcome.BLOCKED)
            self.assertEqual(stale.error_code, "TARGET_IDENTITY_MISMATCH")
            self.assertTrue(recreated.exists())
            self.assertEqual(state_before, (recreated / "RUN_STATE.json").read_bytes())
            self.assertEqual(job_before, (recreated / "EXECUTION_JOB.json").read_bytes())
            self.assertEqual(store.load(created.job_id).lifecycle, OperationalLifecycle.QUEUED)

    def test_scoped_late_failure_retries_after_admission_and_job_are_gone(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = AuthorizedScopeContext("user-late", "workspace-late", "scope-late")
            service = ReferencePaaSJobService(root)
            receipt = PaaSController(service, scope_context=context).submit(PaaSJobRequest("run-late", "scope-late", "store-late", reference_runtime(), total_work_units=1))
            PaaSWorker(service, worker_id="worker-late", runtime_identity=reference_runtime(), engine=ReferenceWorkerEngine(), scope_context=context).run_until_terminal(receipt.identity)
            content = service.content_layout(receipt.identity, scope_context=context)
            content.write_text(StorageArtifact.SOURCE_SNAPSHOT, "inputs/source.png", "content")
            provider = ReferenceLegalHoldProvider()
            provider.set_release(scope_ref="scope-late", run_ref="run-late")

            partial = delete_scoped_run(
                service,
                identity=receipt.identity,
                scope_context=context,
                deletion_id="delete-late",
                hold_provider=provider,
                failure_injector=lambda candidate: candidate.artifact_class is DeletionArtifactClass.SOURCE_SNAPSHOT,
            )
            self.assertEqual(partial.outcome, DeletionOutcome.PARTIAL)
            self.assertFalse(service._scope_record_path(context, receipt.job_id).exists())
            self.assertFalse((service._scope_root(context) / "run-store" / "jobs" / f"{receipt.job_id}.json").exists())
            self.assertTrue(content.durable_root.exists())

            complete = delete_scoped_run(service, identity=receipt.identity, scope_context=context, deletion_id="delete-late", hold_provider=provider)
            self.assertEqual(complete.outcome, DeletionOutcome.COMPLETE)
            self.assertFalse(content.durable_root.exists())

    def test_workspace_late_failure_retries_after_run_state_and_job_are_gone(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = self._workspace_run(root, "run-workspace-late")
            store = WorkspaceRunStore(run)
            job = ExecutionJob.new(run_id=run.name, profile=ExecutionProfile.WORKSPACE_LOCAL, scope_ref="workspace", store_ref="store-workspace")
            created = store.create(job).job
            running = store.transition_operational(created.job_id, expected_revision=created.revision, lifecycle=OperationalLifecycle.RUNNING).job
            store.transition_operational(running.job_id, expected_revision=running.revision, lifecycle=OperationalLifecycle.COMPLETED, terminal_outcome=TerminalOutcome.DONE)
            (run / "WORK_QUEUE.json").write_text("queue", encoding="utf-8")
            operational = self._operational_root(root)
            provider = self._provider(run.name)

            partial = delete_workspace_run(
                root,
                run_ref=run.name,
                deletion_id="delete-workspace-late",
                scope_context=self._context(),
                hold_provider=provider,
                operational_root=operational,
                failure_injector=lambda candidate: candidate.artifact_class is DeletionArtifactClass.WORK_QUEUE,
            )
            self.assertEqual(partial.outcome, DeletionOutcome.PARTIAL)
            self.assertFalse((run / "RUN_STATE.json").exists())
            self.assertFalse((run / "EXECUTION_JOB.json").exists())
            self.assertTrue(run.exists())

            complete = delete_workspace_run(root, run_ref=run.name, deletion_id="delete-workspace-late", scope_context=self._context(), hold_provider=provider, operational_root=operational)
            self.assertEqual(complete.outcome, DeletionOutcome.COMPLETE)
            self.assertFalse(run.exists())

    def test_stale_scoped_generation_rejects_new_control_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = AuthorizedScopeContext("user-generation", "workspace-generation", "scope-generation")
            service = ReferencePaaSJobService(root)
            receipt = PaaSController(service, scope_context=context).submit(PaaSJobRequest("run-generation", "scope-generation", "store-generation", reference_runtime("a"), total_work_units=1))
            PaaSWorker(service, worker_id="worker-generation", runtime_identity=reference_runtime("a"), engine=ReferenceWorkerEngine(), scope_context=context).run_until_terminal(receipt.identity)
            content = service.content_layout(receipt.identity, scope_context=context)
            content.write_text(StorageArtifact.SOURCE_SNAPSHOT, "inputs/source.png", "content")
            provider = ReferenceLegalHoldProvider()
            provider.set_release(scope_ref="scope-generation", run_ref="run-generation")
            record_path = service._scope_record_path(context, receipt.job_id)
            original_record = json.loads(record_path.read_text(encoding="utf-8"))
            partial = delete_scoped_run(
                service,
                identity=receipt.identity,
                scope_context=context,
                deletion_id="delete-generation",
                hold_provider=provider,
                failure_injector=lambda candidate: candidate.artifact_class is DeletionArtifactClass.SOURCE_SNAPSHOT,
            )
            self.assertEqual(partial.outcome, DeletionOutcome.PARTIAL)

            # The public submit boundary remains fenced during PARTIAL.  An
            # external control-plane resurrection is simulated below only to
            # prove that the stale deletion does not consume it.
            replacement_runtime = reference_runtime("b")
            replacement_job = ExecutionJob.new(
                run_id=receipt.identity.run_id,
                profile=ExecutionProfile.DURABLE,
                scope_ref=receipt.identity.scope_ref,
                store_ref=receipt.identity.store_ref,
                job_id=receipt.identity.job_id,
                execution_id=receipt.identity.execution_id,
                total_work_units=1,
                environment_identity=replacement_runtime.environment(),
            )
            service._scoped_store(context).create(replacement_job)
            record = original_record
            record["runtime_identity"] = replacement_runtime.as_dict()
            record["environment_identity"] = replacement_runtime.environment().as_dict()
            unsigned = dict(record)
            unsigned.pop("record_sha256")
            record["record_sha256"] = stable_revision(unsigned)
            atomic_write_json(record_path, record, mode=0o600)
            stale = delete_scoped_run(service, identity=receipt.identity, scope_context=context, deletion_id="delete-generation", hold_provider=provider)
            self.assertEqual(stale.outcome, DeletionOutcome.BLOCKED)
            self.assertEqual(stale.error_code, "TARGET_IDENTITY_MISMATCH")
            self.assertTrue(content.durable_root.exists())

    def test_missing_authority_and_reference_default_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = self._workspace_run(root, "run-authority")
            operational = self._operational_root(root)
            with self.assertRaises(KSlideError) as missing_context:
                delete_workspace_run(root, run_ref=run.name, deletion_id="missing-context", hold_provider=self._provider(run.name), operational_root=operational)
            self.assertEqual(missing_context.exception.code, ErrorCode.EXECUTION_CONFLICT)
            with self.assertRaises(KSlideError) as missing_hold:
                delete_workspace_run(root, run_ref=run.name, deletion_id="missing-hold", scope_context=self._context(), operational_root=operational)
            self.assertEqual(missing_hold.exception.code, ErrorCode.LEGAL_HOLD_UNKNOWN)
            blocked = delete_workspace_run(root, run_ref=run.name, deletion_id="default-unknown", scope_context=self._context(), hold_provider=ReferenceLegalHoldProvider(), operational_root=operational)
            self.assertEqual(blocked.outcome, DeletionOutcome.BLOCKED)
            self.assertTrue(run.exists())

    def test_target_identity_is_independent_of_business_filenames_and_bytes(self) -> None:
        def preview(root: Path, relative: str, content: str) -> dict[DeletionArtifactClass, str]:
            run = root / ".k-slide-runs" / "run-opaque"
            run.mkdir(parents=True)
            (run / "RUN_STATE.json").write_text(json.dumps({"run_id": "run-opaque", "phase": "COMPLETE"}), encoding="utf-8")
            target = run / relative
            target.parent.mkdir(parents=True)
            target.write_text(content, encoding="utf-8")
            operational = root.parent / f"central-{root.name}"
            operational.mkdir()
            result = delete_workspace_run(root, run_ref="run-opaque", deletion_id="delete-opaque", scope_context=self._context(), hold_provider=self._provider("run-opaque"), operational_root=operational, dry_run=True)
            return {item.artifact_class: item.target_ref for item in result.targets}

        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            left = preview(Path(first), "inputs/business-a.txt", "Korean text A")
            right = preview(Path(second), "inputs/business-b.txt", "different bytes and prompt AccessKey")
            self.assertEqual(left[DeletionArtifactClass.SOURCE_SNAPSHOT], right[DeletionArtifactClass.SOURCE_SNAPSHOT])

    def test_operational_cleanup_expires_audits_and_central_telemetry_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            operational_service = root.parent / f"central-{root.name}"
            writer = TelemetryWriter(operational_service)
            run_ref = TelemetryReference.from_internal(TelemetryReferenceKind.RUN, TelemetryMachineId.new(TelemetryReferenceKind.RUN))
            provider = ReferenceLegalHoldProvider()
            provider.set_release(scope_ref="workspace", run_ref=run_ref.canonical)
            def event(timestamp: str) -> TelemetryEvent:
                return TelemetryEvent(
                    TelemetryEventType.LIFECYCLE,
                    TelemetryReference.from_internal(TelemetryReferenceKind.EVENT, TelemetryMachineId.new(TelemetryReferenceKind.EVENT)),
                    timestamp,
                    run_ref=run_ref,
                    lifecycle=TelemetryLifecycle.COMPLETED,
                )
            writer.write(event("2026-01-01T00:00:00Z"))
            writer.write(event("2026-01-02T00:00:00Z"))
            content = root / ".k-slide-runs" / "content" / "source.txt"
            content.parent.mkdir(parents=True)
            content.write_text("business content", encoding="utf-8")
            result = cleanup_operational_metadata(
                root,
                RetentionPolicy("1.0", 100, 1),
                scope_context=self._context(),
                hold_provider=provider,
                operational_root=operational_service / "telemetry",
                now=datetime(2026, 1, 3, tzinfo=timezone.utc),
            )
            self.assertEqual(len(result["expired_telemetry"]), 1)
            self.assertEqual(len(TelemetryWriter(operational_service).records()), 1)
            self.assertTrue(content.is_file())

    def test_retention_dry_run_reports_planned_separately_from_removed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = self._workspace_run(root, "run-dry-retention")
            operational = self._operational_root(root)
            result = cleanup_expired_runs(
                root,
                RetentionPolicy("1.0", 1, 100),
                now=datetime(2026, 1, 20, tzinfo=timezone.utc),
                dry_run=True,
                scope_context=self._context(),
                hold_provider=self._provider(run.name),
                operational_root=operational,
            )
            self.assertEqual(result["removed"], [])
            self.assertEqual({item["run_id"] for item in result["planned"]}, {run.name})
            self.assertTrue(run.exists())
            self.assertFalse(list(operational.rglob("*.json")))


if __name__ == "__main__":
    unittest.main()
