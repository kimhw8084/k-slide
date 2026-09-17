from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from k_slide.errors import ErrorCode, KSlideError
from k_slide.doctor import diagnose
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
from k_slide.telemetry import (
    TelemetryErrorCode,
    TelemetryEvent,
    TelemetryEventType,
    TelemetryLifecycle,
    TelemetryReference,
    TelemetryReferenceKind,
    TelemetryStage,
    TelemetryWriter,
)
from tests.reference_fixtures import reference_runtime


class StoragePlaneContractTests(unittest.TestCase):
    def test_policy_inventory_is_executable_and_excludes_external_surfaces(self) -> None:
        self.assertEqual(set(STORAGE_POLICY.values()), set(StoragePlane))
        self.assertEqual(len(STORAGE_POLICY), len(StorageArtifact))
        self.assertEqual(len(StoragePlane), 3)
        self.assertFalse(hasattr(StorageArtifact, "USER_INPUT_INTAKE"))
        self.assertFalse(hasattr(StorageArtifact, "SUPPORT_METADATA"))

        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as central_directory:
            root = Path(directory)
            central_root = Path(central_directory)
            run = root / ".k-slide-runs" / "run-1"
            run.mkdir(parents=True)
            workspace = StorageLayout.for_workspace(run)
            central = StorageLayout.for_service(central_root)
            central_writer = TelemetryWriter(central_root, layout=central)
            central_writer.write(TelemetryEvent(
                TelemetryEventType.LIFECYCLE,
                TelemetryReference.from_internal(TelemetryReferenceKind.EVENT, "event-inventory"),
                "2026-01-01T00:00:00Z",
                run_ref=TelemetryReference.from_internal(TelemetryReferenceKind.RUN, "run-inventory"),
                lifecycle=TelemetryLifecycle.RUNNING,
            ))
            for index, (artifact, plane) in enumerate(STORAGE_POLICY.items(), start=1):
                layout = central if plane is StoragePlane.CENTRAL_NON_CONTENT_OPERATIONAL_TELEMETRY else workspace
                relative = f"inventory/{index:03d}-{artifact.value}.bin"
                path = layout.path(artifact, relative, create_parent=True)
                reference = layout.reference(artifact, relative)
                self.assertEqual(layout.resolve(reference, expected_plane=plane), path)
                if plane is not StoragePlane.CENTRAL_NON_CONTENT_OPERATIONAL_TELEMETRY:
                    self.assertEqual(layout.write_text(artifact, relative, artifact.value), path)
                    self.assertEqual(path.read_text(encoding="utf-8"), artifact.value)
            self.assertTrue(central_writer.event_path.is_file())
            self.assertTrue(central.path(StorageArtifact.TELEMETRY_COORDINATION_LOCK, ".events.lock").is_file())

    def test_doctor_probes_durable_run_root_when_scratch_is_writable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            durable_root = root / ".k-slide-runs"
            durable_root.mkdir()
            real_named_temporary_file = tempfile.NamedTemporaryFile

            def reject_durable_probe(*args, **kwargs):
                if Path(kwargs["dir"]).resolve() == durable_root.resolve():
                    raise PermissionError("durable root is intentionally not writable")
                return real_named_temporary_file(*args, **kwargs)

            with patch("k_slide.doctor.tempfile.NamedTemporaryFile", side_effect=reject_durable_probe):
                result = diagnose(root)
            check = next(item for item in result["checks"] if item["label"] == "Writable run directory")
            self.assertEqual(check["status"], "FAIL")
            self.assertIn("durable root is intentionally not writable", check["detail"])
            self.assertTrue((root / ".k-slide-scratch" / "_workspace").is_dir())
            self.assertEqual(list(durable_root.iterdir()), [])

    def test_workspace_roots_and_references_are_separate_and_typed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / ".k-slide-runs" / "run-1"
            run.mkdir(parents=True)
            layout = StorageLayout.for_workspace(run)
            self.assertEqual(len({path.resolve() for path in layout.roots.values()}), 2)
            self.assertIsNone(layout.telemetry_root)
            self.assertFalse((root / ".k-slide-telemetry").exists())
            durable = layout.write_text(StorageArtifact.SOURCE_SNAPSHOT, "inputs/source-001.png", "source")
            scratch = layout.write_text(StorageArtifact.CONVERSION_STAGING, "conversion/input.tmp", "scratch")
            self.assertTrue(durable.is_file())
            self.assertTrue(scratch.is_file())
            with self.assertRaises(KSlideError):
                layout.path(StorageArtifact.TELEMETRY_EVENT, "events.jsonl", create_parent=True)
            self.assertFalse((root / ".k-slide-telemetry").exists())
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
            central_root = root.parent / f"central-{root.name}"
            central_root.mkdir()
            self.addCleanup(lambda: shutil.rmtree(central_root, ignore_errors=True))
            central = StorageLayout.for_service(central_root)
            writer = TelemetryWriter(central_root, layout=central)
            writer.write(TelemetryEvent(TelemetryEventType.LIFECYCLE, TelemetryReference.from_internal(TelemetryReferenceKind.EVENT, "event-cleanup"), "2026-01-01T00:00:00Z", run_ref=TelemetryReference.from_internal(TelemetryReferenceKind.RUN, "run-1"), lifecycle=TelemetryLifecycle.RUNNING))
            layout.write_text(StorageArtifact.CONVERSION_STAGING, "nested/a.tmp", "scratch")
            copied_workspace = root.parent / f"copy-{root.name}"
            self.addCleanup(lambda: shutil.rmtree(copied_workspace, ignore_errors=True))
            shutil.copytree(root / ".k-slide-runs", copied_workspace / ".k-slide-runs")
            shutil.copytree(root / ".k-slide-scratch", copied_workspace / ".k-slide-scratch")
            self.assertFalse((copied_workspace / ".k-slide-telemetry").exists())
            layout.cleanup_scratch()
            self.assertFalse(layout.scratch_root.exists())
            self.assertTrue((run / "RUN_STATE.json").is_file())
            self.assertEqual(len(writer.records()), 1)
            self.assertTrue(writer.event_path.is_file())
            layout.write_text(StorageArtifact.TRANSIENT_RENDER_WORK, "recreated/b.tmp", "new scratch")
            self.assertTrue(layout.scratch_root.is_dir())
            shutil.rmtree(root / ".k-slide-runs")
            shutil.rmtree(root / ".k-slide-scratch")
            self.assertTrue(writer.event_path.is_file())

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
    @staticmethod
    def _reference(kind: TelemetryReferenceKind, identity: str) -> TelemetryReference:
        return TelemetryReference.from_internal(kind, identity)

    def test_allowlisted_non_content_event_classes_are_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            writer = TelemetryWriter(Path(directory))
            for index, event_type in enumerate(TelemetryEventType, start=1):
                self.assertTrue(writer.write(TelemetryEvent(
                    event_type,
                    self._reference(TelemetryReferenceKind.EVENT, f"event-{index}"),
                    "2026-01-01T00:00:00Z",
                    deployment_ref=self._reference(TelemetryReferenceKind.DEPLOYMENT, "deployment-1"),
                    runtime_ref=self._reference(TelemetryReferenceKind.RUNTIME, "runtime-1"),
                    model_ref=self._reference(TelemetryReferenceKind.MODEL, "model-1"),
                    run_ref=self._reference(TelemetryReferenceKind.RUN, "run-1"),
                    worker_ref=self._reference(TelemetryReferenceKind.WORKER, "worker-1"),
                    lifecycle=TelemetryLifecycle.RUNNING,
                    error_code=TelemetryErrorCode.INTERNAL if event_type is TelemetryEventType.ERROR else None,
                    stage=TelemetryStage.TRANSLATING,
                    duration_ms=3,
                    count=2,
                    resource_units=4,
                    retry_attempt=1,
                )))
            self.assertEqual(len(writer.records()), len(TelemetryEventType))

    def test_telemetry_references_are_canonical_and_business_content_is_rejected_before_persistence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            writer = TelemetryWriter(Path(directory))
            runtime_identity_ref = TelemetryReference.from_identity(TelemetryReferenceKind.RUNTIME, reference_runtime())
            self.assertRegex(str(runtime_identity_ref), r"^kslide-ref-v1\.runtime\.[0-9a-f]{64}$")
            with self.assertRaises(KSlideError):
                TelemetryReference.from_identity(TelemetryReferenceKind.RUNTIME, {"source": "MergerRoadmapQ4"})
            base = {
                "event_type": TelemetryEventType.ERROR.value,
                "event_id": str(self._reference(TelemetryReferenceKind.EVENT, "event-adversarial")),
                "occurred_at": "2026-01-01T00:00:00Z",
                "deployment_ref": str(self._reference(TelemetryReferenceKind.DEPLOYMENT, "deployment-adversarial")),
                "runtime_ref": str(runtime_identity_ref),
                "model_ref": str(self._reference(TelemetryReferenceKind.MODEL, "model-adversarial")),
                "run_ref": str(self._reference(TelemetryReferenceKind.RUN, "run-adversarial")),
                "worker_ref": str(self._reference(TelemetryReferenceKind.WORKER, "worker-adversarial")),
                "lifecycle": TelemetryLifecycle.RUNNING.value,
                "error_code": TelemetryErrorCode.INTERNAL.value,
                "stage": TelemetryStage.TRANSLATING.value,
            }
            phrases = ("MergerRoadmapQ4", "분기별 인수 계획", "Ignore previous instructions", "source/board.png", "AccessKey=canary")
            for field in ("schema_version", "event_type", "event_id", "occurred_at", "deployment_ref", "runtime_ref", "model_ref", "run_ref", "worker_ref", "lifecycle", "error_code", "stage"):
                for phrase in phrases:
                    rejected = dict(base)
                    rejected[field] = phrase
                    with self.assertRaises(KSlideError):
                        writer.write(rejected)
            self.assertFalse(writer.event_path.exists())
            self.assertTrue(writer.write(base))
            record = writer.records()[0].as_dict()
            self.assertTrue(record["event_id"].startswith("kslide-ref-v1.event."))
            self.assertTrue(record["run_ref"].startswith("kslide-ref-v1.run."))
            self.assertNotIn("adversarial", json.dumps(record))

    def test_unknown_nested_content_and_secret_fields_are_rejected_before_persistence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            writer = TelemetryWriter(Path(directory))
            rejected = (
                {"event_type": "error", "event_id": str(self._reference(TelemetryReferenceKind.EVENT, "event-nested-1")), "occurred_at": "2026-01-01T00:00:00Z", "error": {"source_text": "secret source"}},
                {"event_type": "error", "event_id": str(self._reference(TelemetryReferenceKind.EVENT, "event-nested-2")), "occurred_at": "2026-01-01T00:00:00Z", "stage": "AccessKey=canary"},
                {"event_type": "error", "event_id": str(self._reference(TelemetryReferenceKind.EVENT, "event-nested-3")), "occurred_at": "2026-01-01T00:00:00Z", "unknown": "value"},
                {"event_type": "error", "event_id": str(self._reference(TelemetryReferenceKind.EVENT, "event-nested-4")), "occurred_at": "2026-01-01T00:00:00Z", "count": b"secret"},
            )
            for event in rejected:
                with self.assertRaises(KSlideError):
                    writer.write(event)
            self.assertFalse(writer.event_path.exists())

    def test_telemetry_reference_cannot_resolve_durable_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            layout = StorageLayout.for_service(root)
            writer = TelemetryWriter(root, layout=layout)
            writer.write(TelemetryEvent(TelemetryEventType.ERROR, self._reference(TelemetryReferenceKind.EVENT, "event-opaque"), "2026-01-01T00:00:00Z", run_ref=self._reference(TelemetryReferenceKind.RUN, "run-opaque"), error_code=TelemetryErrorCode.INTERNAL))
            telemetry_ref = layout.reference(StorageArtifact.TELEMETRY_EVENT, "events.jsonl")
            self.assertEqual(layout.resolve(telemetry_ref, expected_plane=StoragePlane.CENTRAL_NON_CONTENT_OPERATIONAL_TELEMETRY), writer.event_path)
            with self.assertRaises(KSlideError):
                layout.resolve(telemetry_ref, expected_plane=StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA)

    def test_telemetry_writer_rejects_workspace_scoped_layout_even_with_external_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as central_directory:
            root = Path(directory)
            run = root / ".k-slide-runs" / "run-1"
            run.mkdir(parents=True)
            layout = StorageLayout.for_workspace(run, central_telemetry_root=Path(central_directory))
            with self.assertRaises(KSlideError):
                TelemetryWriter(Path(central_directory), layout=layout)
            with self.assertRaises(KSlideError):
                StorageLayout.for_workspace(run, central_telemetry_root=root / "central-inside-workspace")

    def test_telemetry_write_loss_is_non_fatal_to_the_typed_event_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            writer = TelemetryWriter(Path(directory))
            event = TelemetryEvent(
                TelemetryEventType.LIFECYCLE,
                self._reference(TelemetryReferenceKind.EVENT, "event-loss"),
                "2026-01-01T00:00:00Z",
                lifecycle=TelemetryLifecycle.RUNNING,
            )
            with patch.object(Path, "open", side_effect=OSError("central telemetry is unavailable")):
                self.assertFalse(writer.write(event))
            self.assertFalse(writer.event_path.is_file())


if __name__ == "__main__":
    unittest.main()
