from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from k_slide.deletion import (
    DeletionOutcome,
    DeletionState,
    LegalHoldStatus,
    ReferenceLegalHoldProvider,
    cleanup_operational_metadata,
    delete_workspace_run,
)
from k_slide.paas import AuthorizedScopeContext, PaaSController, PaaSJobRequest, PaaSWorker, ReferencePaaSJobService, ReferenceWorkerEngine
from k_slide.retention import cleanup_expired_runs
from k_slide.retention_policy import RetentionPolicy
from k_slide.storage import StorageArtifact
from tests.reference_fixtures import reference_runtime


class CHG16DeletionTests(unittest.TestCase):
    def _context(self) -> AuthorizedScopeContext:
        return AuthorizedScopeContext("admin-ref", "workspace-ref", "workspace")

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
            result = delete_workspace_run(root, run_ref=run.name, deletion_id="delete-1", scope_context=self._context(), hold_provider=provider)
            self.assertEqual(result.outcome, DeletionOutcome.COMPLETE)
            self.assertFalse(run.exists())
            audit = (root / ".k-slide-runs" / "_deletions" / "delete-1.json").read_text(encoding="utf-8")
            self.assertNotIn("Korean", audit)
            self.assertNotIn("prompt", audit)
            self.assertNotIn("AccessKey", audit)
            self.assertNotIn(str(root), audit)

    def test_hold_unknown_blocks_and_fresh_release_allows_same_request(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = self._workspace_run(root)
            provider = ReferenceLegalHoldProvider(default_status=LegalHoldStatus.UNKNOWN)
            blocked = delete_workspace_run(root, run_ref=run.name, deletion_id="delete-hold", scope_context=self._context(), hold_provider=provider)
            self.assertEqual(blocked.outcome, DeletionOutcome.BLOCKED)
            self.assertTrue(run.exists())
            provider.set_hold(scope_ref="workspace", run_ref=run.name)
            self.assertEqual(delete_workspace_run(root, run_ref=run.name, deletion_id="delete-hold", scope_context=self._context(), hold_provider=provider).outcome, DeletionOutcome.BLOCKED)
            provider.set_release(scope_ref="workspace", run_ref=run.name)
            self.assertEqual(delete_workspace_run(root, run_ref=run.name, deletion_id="delete-hold", scope_context=self._context(), hold_provider=provider).outcome, DeletionOutcome.COMPLETE)

    def test_partial_retry_and_dry_run_do_not_replay_completed_targets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = self._workspace_run(root, "run-partial")
            provider = ReferenceLegalHoldProvider()
            self.assertEqual(delete_workspace_run(root, run_ref=run.name, deletion_id="dry", scope_context=self._context(), hold_provider=provider, dry_run=True).outcome, DeletionOutcome.PLANNED)
            self.assertTrue(run.exists())
            calls = 0

            def fail_once(_candidate):
                nonlocal calls
                calls += 1
                return calls == 1

            partial = delete_workspace_run(root, run_ref=run.name, deletion_id="partial", scope_context=self._context(), hold_provider=provider, failure_injector=fail_once)
            self.assertEqual(partial.state, DeletionState.PARTIAL)
            complete = delete_workspace_run(root, run_ref=run.name, deletion_id="partial", scope_context=self._context(), hold_provider=provider)
            self.assertEqual(complete.outcome, DeletionOutcome.COMPLETE)
            self.assertFalse(run.exists())
            self.assertEqual(delete_workspace_run(root, run_ref=run.name, deletion_id="partial", scope_context=self._context(), hold_provider=provider).outcome, DeletionOutcome.COMPLETE)

    def test_retention_and_operational_metadata_ttls_are_separate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = self._workspace_run(root, "run-expired")
            result = cleanup_expired_runs(root, RetentionPolicy("1.0", 1, 100), now=datetime(2026, 1, 20, tzinfo=timezone.utc))
            self.assertEqual({item["run_id"] for item in result["removed"]}, {run.name})
            audit = root / ".k-slide-runs" / "_deletions"
            self.assertTrue(list(audit.glob("*.json")))
            cleanup_operational_metadata(root, RetentionPolicy("1.0", 100, 1), now=datetime.now(timezone.utc) + timedelta(days=2))
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
            result = service.delete_run(receipt.identity, deletion_id="delete-paas", scope_context=context, hold_provider=ReferenceLegalHoldProvider())
            self.assertEqual(result.outcome, DeletionOutcome.COMPLETE)
            self.assertFalse(content.durable_root.exists())
            with self.assertRaises(Exception):
                service.resolve_references(receipt.identity, scope_context=context)
            self.assertIsNone(service.queue(scope_context=context).active_job_id)


if __name__ == "__main__":
    unittest.main()
