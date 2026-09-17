from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from k_slide.errors import ErrorCode, KSlideError
from k_slide.paas import (
    AuthorizedScopeContext,
    PaaSController,
    PaaSJobRequest,
    PaaSWorker,
    ReferencePaaSJobService,
    ReferenceWorkerEngine,
)
from k_slide.storage import (
    STORAGE_POLICY,
    StorageArtifact,
    StorageLayout,
    StoragePlane,
    StorageReference,
)
from k_slide.telemetry import TelemetryEvent, TelemetryEventType, TelemetryWriter
from tests.reference_fixtures import reference_runtime


class StoragePlaneContractTests(unittest.TestCase):
    def test_policy_inventory_assigns_every_artifact_class_to_exactly_one_plane(self) -> None:
        self.assertEqual(set(STORAGE_POLICY.values()), set(StoragePlane))
        self.assertEqual(len(STORAGE_POLICY), len(StorageArtifact))
        self.assertEqual(len(StoragePlane), 3)

    def test_workspace_roots_and_references_are_separate_and_typed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / ".k-slide-runs" / "run-1"
            run.mkdir(parents=True)
            layout = StorageLayout.for_workspace(run)
            self.assertEqual(len({path.resolve() for path in layout.roots.values()}), 3)
            durable = layout.write_text(StorageArtifact.SOURCE_SNAPSHOT, "inputs/source-001.png", "source")
            scratch = layout.write_text(StorageArtifact.CONVERSION_STAGING, "conversion/input.tmp", "scratch")
            self.assertTrue(durable.is_file())
            self.assertTrue(scratch.is_file())
            durable_ref = layout.reference(StorageArtifact.SOURCE_SNAPSHOT, "inputs/source-001.png")
            self.assertEqual(durable_ref.plane, StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA)
            self.assertEqual(layout.resolve(durable_ref, authorized_scope_ref="workspace"), durable)
            with self.assertRaises(KSlideError):
                layout.resolve(durable_ref, expected_plane=StoragePlane.EPHEMERAL_PROCESSING_SCRATCH)

    def test_scratch_cleanup_is_complete_and_does_not_touch_authoritative_planes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / ".k-slide-runs" / "run-1"
            run.mkdir(parents=True)
            layout = StorageLayout.for_workspace(run)
            layout.write_text(StorageArtifact.RUN_STATE, "RUN_STATE.json", "durable")
            writer = TelemetryWriter(root, layout=layout)
            writer.write(TelemetryEvent(TelemetryEventType.LIFECYCLE, "event-1", "2026-01-01T00:00:00Z", run_ref="run-1", lifecycle="RUNNING"))
            layout.write_text(StorageArtifact.CONVERSION_STAGING, "nested/a.tmp", "scratch")
            layout.cleanup_scratch()
            self.assertFalse(layout.scratch_root.exists())
            self.assertTrue((run / "RUN_STATE.json").is_file())
            self.assertEqual(len(writer.records()), 1)
            layout.write_text(StorageArtifact.TRANSIENT_RENDER_WORK, "recreated/b.tmp", "new scratch")
            self.assertTrue(layout.scratch_root.is_dir())

    def test_scoped_durable_run_reconnects_after_scratch_destruction_without_duplicate_commit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = AuthorizedScopeContext("user-a", "workspace-a", "scope-a")
            service = ReferencePaaSJobService(root)
            receipt = PaaSController(service, scope_context=context).submit(
                PaaSJobRequest("run-reconnect", "scope-a", "store-reconnect", reference_runtime(), total_work_units=2)
            )
            scope_root = service._scope_root(context)
            layout = StorageLayout.for_scoped_reference(service_root=root, durable_root=scope_root, scope_ref="scope-a", run_ref=receipt.job_id)
            layout.write_text(StorageArtifact.CONVERSION_STAGING, "work/temporary.bin", "scratch")
            first = PaaSWorker(service, worker_id="worker-a", runtime_identity=reference_runtime(), engine=ReferenceWorkerEngine(), scope_context=context).run_once(receipt.identity)
            self.assertEqual(first.status, "ACCEPTED")
            layout.cleanup_scratch()
            resumed = PaaSWorker(ReferencePaaSJobService(root), worker_id="worker-b", runtime_identity=reference_runtime(), engine=ReferenceWorkerEngine(), scope_context=context).run_until_terminal(receipt.identity)
            self.assertEqual(resumed.status, "DONE")
            current = ReferencePaaSJobService(root).open_store(receipt.identity, scope_context=context).load(receipt.job_id)
            self.assertEqual(len(current.result_markers), 2)
            self.assertTrue((scope_root / "run-store" / "jobs" / f"{receipt.job_id}.json").is_file())

    def test_scope_and_reference_resolution_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            owner = AuthorizedScopeContext("user-a", "workspace-a", "scope-a")
            other = AuthorizedScopeContext("user-b", "workspace-b", "scope-b")
            service = ReferencePaaSJobService(root)
            receipt = PaaSController(service, scope_context=owner).submit(
                PaaSJobRequest("run-private", "scope-a", "store-private", reference_runtime())
            )
            scope_root = service._scope_root(owner)
            layout = StorageLayout.for_scoped_reference(service_root=root, durable_root=scope_root, scope_ref="scope-a", run_ref=receipt.job_id)
            reference = layout.reference(StorageArtifact.EXECUTION_JOB, f"run-store/jobs/{receipt.job_id}.json")
            with self.assertRaises(KSlideError) as raised:
                layout.resolve(reference, authorized_scope_ref=other.scope_ref)
            self.assertEqual(raised.exception.code, ErrorCode.EXECUTION_CONFLICT)
            with self.assertRaises(KSlideError):
                service.resolve_store(receipt.identity, scope_context=other)
            with self.assertRaises(KSlideError):
                StorageReference(StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA, StorageArtifact.SOURCE_SNAPSHOT, "../outside", "scope-a", receipt.job_id)

    def test_symlink_alias_and_traversal_attempts_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside_directory:
            root = Path(directory)
            outside = Path(outside_directory) / "outside.txt"
            outside.write_text("outside", encoding="utf-8")
            run = root / ".k-slide-runs" / "run-1"
            run.mkdir(parents=True)
            layout = StorageLayout.for_workspace(run)
            with self.assertRaises(KSlideError):
                layout.path(StorageArtifact.SOURCE_SNAPSHOT, "../outside.txt")
            (run / "alias").symlink_to(outside)
            with self.assertRaises(KSlideError):
                layout.path(StorageArtifact.SOURCE_SNAPSHOT, "alias/file.txt")


class TelemetryBoundaryTests(unittest.TestCase):
    def test_allowlisted_non_content_event_classes_are_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            writer = TelemetryWriter(Path(directory))
            for index, event_type in enumerate(TelemetryEventType, start=1):
                self.assertTrue(writer.write(TelemetryEvent(
                    event_type,
                    f"event-{index}",
                    "2026-01-01T00:00:00Z",
                    deployment_ref="deployment-1",
                    runtime_ref="runtime-1",
                    model_ref="model-1",
                    run_ref="run-1",
                    worker_ref="worker-1",
                    lifecycle="RUNNING",
                    error_code="KSLIDE_INTERNAL" if event_type is TelemetryEventType.ERROR else None,
                    stage="TRANSLATING",
                    duration_ms=3,
                    count=2,
                    resource_units=4,
                    retry_attempt=1,
                )))
            self.assertEqual(len(writer.records()), len(TelemetryEventType))

    def test_unknown_nested_content_and_secret_fields_are_rejected_before_persistence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            writer = TelemetryWriter(Path(directory))
            rejected = (
                {"event_type": "error", "event_id": "event-1", "occurred_at": "2026-01-01T00:00:00Z", "error": {"source_text": "secret source"}},
                {"event_type": "error", "event_id": "event-2", "occurred_at": "2026-01-01T00:00:00Z", "stage": "AccessKey=canary"},
                {"event_type": "error", "event_id": "event-3", "occurred_at": "2026-01-01T00:00:00Z", "unknown": "value"},
                {"event_type": "error", "event_id": "event-4", "occurred_at": "2026-01-01T00:00:00Z", "count": b"secret"},
            )
            for event in rejected:
                with self.assertRaises(KSlideError):
                    writer.write(event)
            self.assertFalse(writer.event_path.exists())

    def test_telemetry_reference_cannot_resolve_durable_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            layout = StorageLayout.for_service(root)
            writer = TelemetryWriter(root)
            writer.write(TelemetryEvent(TelemetryEventType.ERROR, "event-1", "2026-01-01T00:00:00Z", run_ref="run-opaque", error_code="KSLIDE_INTERNAL"))
            telemetry_ref = layout.reference(StorageArtifact.TELEMETRY_EVENT, "events.jsonl")
            self.assertEqual(layout.resolve(telemetry_ref, expected_plane=StoragePlane.CENTRAL_NON_CONTENT_OPERATIONAL_TELEMETRY), writer.event_path)
            with self.assertRaises(KSlideError):
                layout.resolve(telemetry_ref, expected_plane=StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA)


if __name__ == "__main__":
    unittest.main()
