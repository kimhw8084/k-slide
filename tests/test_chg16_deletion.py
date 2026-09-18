from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from dataclasses import replace
from pathlib import Path

from k_slide.errors import ErrorCode, KSlideError
from k_slide.deletion import (
    DeletionOutcome,
    DeletionState,
    LegalHoldStatus,
    ReferenceLegalHoldProvider,
    cleanup_operational_metadata,
    delete_workspace_run,
)
from k_slide.paas import AuthorizedScopeContext, PaaSController, PaaSJobRequest, PaaSWorker, ReferencePaaSJobService, ReferenceWorkerEngine
from k_slide.execution import ExecutionProfile, OperationalLifecycle, TerminalOutcome, WorkspaceRunStore, new_execution_job
from k_slide.retention import cleanup_expired_runs
from k_slide.retention_policy import RetentionPolicy
from k_slide.storage import StorageArtifact
from k_slide.telemetry import TelemetryEvent, TelemetryEventType, TelemetryMachineId, TelemetryReference, TelemetryReferenceKind, TelemetryWriter
from tests.reference_fixtures import reference_runtime


class CHG16DeletionTests(unittest.TestCase):
    def _context(self) -> AuthorizedScopeContext:
        return AuthorizedScopeContext("admin-ref", "workspace-ref", "workspace")

    def _operational_root(self, root: Path) -> Path:
        central = Path(tempfile.mkdtemp(prefix=f"central-{root.name}-", dir=root.parent))
        self.addCleanup(shutil.rmtree, central, ignore_errors=True)
        return central

    @staticmethod
    def _release(provider: ReferenceLegalHoldProvider, run_ref: str) -> None:
        provider.set_release(scope_ref="workspace", run_ref=run_ref)

    def _workspace_run(self, root: Path, run_id: str = "run-delete") -> Path:
        run = root / ".k-slide-runs" / run_id
        run.mkdir(parents=True, mode=0o700)
        (run / "RUN_STATE.json").write_text(
            json.dumps({"run_id": run_id, "phase": "COMPLETE", "created_at": "2020-01-01T00:00:00Z", "updated_at": "2020-01-01T00:00:00Z"}),
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
            provider = ReferenceLegalHoldProvider()
            self._release(provider, run.name)
            operational = self._operational_root(root)
            result = delete_workspace_run(root, run_ref=run.name, deletion_id="delete-1", scope_context=self._context(), hold_provider=provider, operational_metadata_root=operational)
            self.assertEqual(result.outcome, DeletionOutcome.COMPLETE)
            self.assertFalse(run.exists())
            audit = (operational / "telemetry" / "deletions" / "delete-1.json").read_text(encoding="utf-8")
            self.assertNotIn("Korean", audit)
            self.assertNotIn("prompt", audit)
            self.assertNotIn("AccessKey", audit)
            self.assertNotIn(str(root), audit)
            self.assertFalse((root / ".k-slide-runs" / "_deletions").exists())

    def test_deletion_fails_closed_without_authority_and_reference_defaults_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = self._workspace_run(root, "run-authority")
            operational = self._operational_root(root)
            provider = ReferenceLegalHoldProvider()
            self.assertEqual(provider.lookup(scope_ref="workspace", run_ref=run.name).status, LegalHoldStatus.UNKNOWN)
            with self.assertRaises(KSlideError) as missing_hold:
                delete_workspace_run(root, run_ref=run.name, deletion_id="missing-hold", scope_context=self._context(), operational_metadata_root=operational)
            self.assertEqual(missing_hold.exception.code, ErrorCode.LEGAL_HOLD_UNKNOWN)
            with self.assertRaises(KSlideError) as missing_root:
                delete_workspace_run(root, run_ref=run.name, deletion_id="missing-root", scope_context=self._context(), hold_provider=provider)
            self.assertEqual(missing_root.exception.code, ErrorCode.DELETION_INVALID)
            self.assertTrue(run.exists())

    def test_hold_unknown_blocks_and_fresh_release_allows_same_request(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = self._workspace_run(root)
            provider = ReferenceLegalHoldProvider(default_status=LegalHoldStatus.UNKNOWN)
            operational = self._operational_root(root)
            blocked = delete_workspace_run(root, run_ref=run.name, deletion_id="delete-hold", scope_context=self._context(), hold_provider=provider, operational_metadata_root=operational)
            self.assertEqual(blocked.outcome, DeletionOutcome.BLOCKED)
            self.assertTrue(run.exists())
            provider.set_hold(scope_ref="workspace", run_ref=run.name)
            self.assertEqual(delete_workspace_run(root, run_ref=run.name, deletion_id="delete-hold", scope_context=self._context(), hold_provider=provider, operational_metadata_root=operational).outcome, DeletionOutcome.BLOCKED)
            provider.set_release(scope_ref="workspace", run_ref=run.name)
            self.assertEqual(delete_workspace_run(root, run_ref=run.name, deletion_id="delete-hold", scope_context=self._context(), hold_provider=provider, operational_metadata_root=operational).outcome, DeletionOutcome.COMPLETE)

    def test_partial_retry_and_dry_run_do_not_replay_completed_targets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = self._workspace_run(root, "run-partial")
            provider = ReferenceLegalHoldProvider()
            self._release(provider, run.name)
            operational = self._operational_root(root)
            self.assertEqual(delete_workspace_run(root, run_ref=run.name, deletion_id="dry", scope_context=self._context(), hold_provider=provider, operational_metadata_root=operational, dry_run=True).outcome, DeletionOutcome.PLANNED)
            self.assertTrue(run.exists())
            calls = 0

            def fail_once(_candidate):
                nonlocal calls
                calls += 1
                return calls == 1

            partial = delete_workspace_run(root, run_ref=run.name, deletion_id="partial", scope_context=self._context(), hold_provider=provider, operational_metadata_root=operational, failure_injector=fail_once)
            self.assertEqual(partial.state, DeletionState.PARTIAL)
            complete = delete_workspace_run(root, run_ref=run.name, deletion_id="partial", scope_context=self._context(), hold_provider=provider, operational_metadata_root=operational)
            self.assertEqual(complete.outcome, DeletionOutcome.COMPLETE)
            self.assertFalse(run.exists())
            self.assertEqual(delete_workspace_run(root, run_ref=run.name, deletion_id="partial", scope_context=self._context(), hold_provider=provider, operational_metadata_root=operational).outcome, DeletionOutcome.COMPLETE)

    def test_target_identity_is_class_level_and_ignores_business_names_and_bytes(self) -> None:
        results = []
        for filename, content in (("business-a.txt", "Korean source A"), ("business-b.txt", "different AccessKey content B")):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                run = self._workspace_run(root, "run-opaque")
                extra = run / filename
                extra.write_text(content, encoding="utf-8")
                provider = ReferenceLegalHoldProvider()
                self._release(provider, run.name)
                result = delete_workspace_run(root, run_ref=run.name, deletion_id="opaque-delete", scope_context=self._context(), hold_provider=provider, operational_metadata_root=self._operational_root(root), dry_run=True)
                results.append(tuple((item.artifact_class.value, item.target_ref) for item in result.targets))
        self.assertEqual(results[0], results[1])
        self.assertTrue(all("business" not in target_ref and "AccessKey" not in target_ref for _, target_ref in results[0]))

    def test_partial_deletion_fences_workspace_semantic_and_execution_writes_but_allows_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = self._workspace_run(root, "run-fenced")
            run_state = json.loads((run / "RUN_STATE.json").read_text(encoding="utf-8"))
            run_state["mode"] = "test"
            (run / "RUN_STATE.json").write_text(json.dumps(run_state), encoding="utf-8")
            store = WorkspaceRunStore(run)
            job = new_execution_job(run.name, profile=ExecutionProfile.WORKSPACE_LOCAL, scope_ref="workspace", store_ref="workspace-store")
            job = replace(job, lifecycle=OperationalLifecycle.COMPLETED, terminal_outcome=TerminalOutcome.DONE)
            store.create(job)
            provider = ReferenceLegalHoldProvider()
            self._release(provider, run.name)
            operational = self._operational_root(root)
            partial = delete_workspace_run(root, run_ref=run.name, deletion_id="fence", scope_context=self._context(), hold_provider=provider, operational_metadata_root=operational, failure_injector=lambda _candidate: True)
            self.assertEqual(partial.state, DeletionState.PARTIAL)
            self.assertEqual(store.load(job.job_id).job_id, job.job_id)
            with self.assertRaises(KSlideError) as execution_write:
                store.commit_job(replace(job, revision=job.revision + 1), expected_revision=job.revision)
            self.assertEqual(execution_write.exception.code, ErrorCode.EXECUTION_CONFLICT)
            with self.assertRaises(KSlideError) as semantic_write:
                from k_slide.state import load_state, save_state
                state = load_state(run)
                save_state(run, replace(state))
            self.assertEqual(semantic_write.exception.code, ErrorCode.EXECUTION_CONFLICT)
            complete = delete_workspace_run(root, run_ref=run.name, deletion_id="fence", scope_context=self._context(), hold_provider=provider, operational_metadata_root=operational)
            self.assertEqual(complete.outcome, DeletionOutcome.COMPLETE)

    def test_operational_cleanup_expires_typed_telemetry_with_metadata_ttl(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            operational = self._operational_root(root)
            writer = TelemetryWriter(operational)
            old_event = TelemetryEvent(TelemetryEventType.LIFECYCLE, TelemetryReference.from_internal(TelemetryReferenceKind.EVENT, TelemetryMachineId.new(TelemetryReferenceKind.EVENT)), "2026-01-01T00:00:00Z")
            new_event = TelemetryEvent(TelemetryEventType.LIFECYCLE, TelemetryReference.from_internal(TelemetryReferenceKind.EVENT, TelemetryMachineId.new(TelemetryReferenceKind.EVENT)), "2026-01-19T00:00:00Z")
            self.assertTrue(writer.write(old_event))
            self.assertTrue(writer.write(new_event))
            result = cleanup_operational_metadata(root, RetentionPolicy("1.0", 1, 10), operational_metadata_root=operational, now=datetime(2026, 1, 20, tzinfo=timezone.utc))
            self.assertEqual(result["telemetry_expired"], [str(old_event.event_id)])
            self.assertEqual(tuple(event.event_id for event in writer.records()), (new_event.event_id,))

    def test_retention_and_operational_metadata_ttls_are_separate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = self._workspace_run(root, "run-expired")
            provider = ReferenceLegalHoldProvider()
            self._release(provider, run.name)
            operational = self._operational_root(root)
            result = cleanup_expired_runs(root, RetentionPolicy("1.0", 1, 100), now=datetime(2026, 1, 20, tzinfo=timezone.utc), hold_provider=provider, scope_context=self._context(), operational_metadata_root=operational)
            self.assertEqual({item["run_id"] for item in result["removed"]}, {run.name})
            audit = operational / "telemetry" / "deletions"
            self.assertTrue(list(audit.glob("*.json")))
            cleanup_operational_metadata(root, RetentionPolicy("1.0", 100, 1), operational_metadata_root=operational, now=datetime.now(timezone.utc) + timedelta(days=2))
            self.assertFalse(list(audit.glob("*.json")))

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
            provider.set_release(scope_ref="scope-a", run_ref=receipt.identity.run_id)
            result = service.delete_run(receipt.identity, deletion_id="delete-paas", scope_context=context, hold_provider=provider)
            self.assertEqual(result.outcome, DeletionOutcome.COMPLETE)
            self.assertFalse(content.durable_root.exists())
            with self.assertRaises(Exception):
                service.resolve_references(receipt.identity, scope_context=context)
            self.assertIsNone(service.queue(scope_context=context).active_job_id)


if __name__ == "__main__":
    unittest.main()
