from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from k_slide.errors import ErrorCode, KSlideError
from k_slide.doctor import diagnose
from k_slide.evidence_ir import load_evidence
from k_slide.extraction import extract_run
from k_slide.ingest import prepare_run
from k_slide.normalization import normalize_run
from k_slide.state import load_state
from k_slide.paas import (
    AuthorizedScopeContext,
    DurableJobIdentity,
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
    TelemetryMachineId,
    TelemetryReference,
    TelemetryReferenceKind,
    TelemetryStage,
    TelemetryWriter,
)
from tests.reference_fixtures import reference_environment, reference_runtime


class StoragePlaneContractTests(unittest.TestCase):
    def test_policy_inventory_matches_independently_managed_objects(self) -> None:
        self.assertEqual(set(STORAGE_POLICY.values()), set(StoragePlane))
        self.assertEqual(len(STORAGE_POLICY), len(StorageArtifact))
        self.assertEqual(len(StoragePlane), 3)
        self.assertEqual(
            set(StorageArtifact),
            {
                StorageArtifact.SOURCE_SNAPSHOT, StorageArtifact.SOURCE_MANIFEST, StorageArtifact.INPUT_INVENTORY,
                StorageArtifact.RUN_MANIFEST, StorageArtifact.RECOVERY_GUIDE, StorageArtifact.SESSION_BINDING,
                StorageArtifact.RUNTIME_METADATA, StorageArtifact.RUN_STATE, StorageArtifact.WORK_QUEUE,
                StorageArtifact.EXECUTION_JOB, StorageArtifact.ADMISSION_RECORD, StorageArtifact.ADMISSION_QUEUE,
                StorageArtifact.ADMISSION_CONTROL, StorageArtifact.NORMALIZED_RENDER, StorageArtifact.NATIVE_EXTRACTION,
                StorageArtifact.NORMALIZATION_MANIFEST, StorageArtifact.NORMALIZATION_ERROR, StorageArtifact.REGION_CROP,
                StorageArtifact.OCR_METADATA, StorageArtifact.EVIDENCE_IR, StorageArtifact.EXTRACTION_ERROR,
                StorageArtifact.TRANSLATION_PATCH, StorageArtifact.CANONICAL_IR, StorageArtifact.REPORT,
                StorageArtifact.VERIFICATION, StorageArtifact.METRICS, StorageArtifact.FAILURE_MARKER,
                StorageArtifact.COMPLETION_MARKER, StorageArtifact.COORDINATION_LOCK,
                StorageArtifact.TELEMETRY_COORDINATION_LOCK, StorageArtifact.CONVERSION_STAGING,
                StorageArtifact.TELEMETRY_EVENT, StorageArtifact.DELETION_AUDIT,
            },
        )
        self.assertFalse(hasattr(StorageArtifact, "USER_INPUT_INTAKE"))
        self.assertFalse(hasattr(StorageArtifact, "SUPPORT_METADATA"))
        self.assertFalse(hasattr(StorageArtifact, "DURABLE_CHECKPOINT"))
        self.assertFalse(hasattr(StorageArtifact, "RESULT_COMMIT_MARKER"))
        self.assertFalse(hasattr(StorageArtifact, "ENVIRONMENT_BINDING"))
        self.assertFalse(hasattr(StorageArtifact, "OCR_EVIDENCE"))
        self.assertFalse(hasattr(StorageArtifact, "TRANSIENT_RENDER_WORK"))
        self.assertFalse(hasattr(StorageArtifact, "TRANSIENT_OCR_WORKSPACE"))

    def test_workspace_pipeline_produces_and_resolves_real_artifacts(self) -> None:
        from PIL import Image

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "review.png"
            Image.new("RGB", (1200, 800), "white").save(source)
            environment = reference_environment()
            run = prepare_run(root, explicit_paths=[str(source)], environment_identity=environment)
            normalize_run(run, environment_identity=environment)
            evidence = extract_run(run, environment_identity=environment)[0]
            layout = StorageLayout.for_workspace(run)

            produced = {
                StorageArtifact.SOURCE_SNAPSHOT: "inputs/source-001.png",
                StorageArtifact.SOURCE_MANIFEST: "00_run_manifest.md",
                StorageArtifact.INPUT_INVENTORY: "00_input_inventory.json",
                StorageArtifact.RUN_MANIFEST: "RUN_MANIFEST.json",
                StorageArtifact.RECOVERY_GUIDE: "RUN_RECOVERY_GUIDE.md",
                StorageArtifact.RUNTIME_METADATA: "RUNTIME_METADATA.json",
                StorageArtifact.RUN_STATE: "RUN_STATE.json",
                StorageArtifact.WORK_QUEUE: "WORK_QUEUE.json",
                StorageArtifact.NORMALIZED_RENDER: "normalized/doc-001-image-0001.png",
                StorageArtifact.NATIVE_EXTRACTION: "native/doc-001-image-0001.json",
                StorageArtifact.NORMALIZATION_MANIFEST: "normalized/DOCUMENT_MANIFEST.json",
                StorageArtifact.REGION_CROP: evidence.regions[0].crop_original_path,
                StorageArtifact.OCR_METADATA: "OCR_METADATA.json",
                StorageArtifact.EVIDENCE_IR: "evidence/doc-001-image-0001.json",
                StorageArtifact.METRICS: "metrics.json",
            }
            for artifact, relative_path in produced.items():
                path = layout.path(artifact, relative_path)
                reference = layout.reference(artifact, relative_path)
                self.assertEqual(layout.resolve(reference, expected_plane=StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA), path)
                self.assertTrue(path.is_file(), f"missing producer output for {artifact.value}: {path}")
            self.assertEqual(layout.reference(StorageArtifact.CONVERSION_STAGING, "office/doc-001").plane, StoragePlane.EPHEMERAL_PROCESSING_SCRATCH)

    def test_conditional_failure_marker_is_produced_by_failed_input_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = prepare_run(root, environment_identity=reference_environment())
            layout = StorageLayout.for_workspace(run)
            failure = layout.path(StorageArtifact.FAILURE_MARKER, "RUN_FAILED.md")
            self.assertTrue(failure.is_file())
            self.assertEqual(load_state(run).phase.value, "FAILED_INPUT")

    @unittest.skipUnless(importlib.util.find_spec("fitz"), "PyMuPDF is optional in the base development environment")
    def test_pptx_conversion_uses_the_real_conversion_staging_class(self) -> None:
        import fitz

        from k_slide.normalization import _render_pptx

        class FakeProcess:
            returncode = 0

            def __init__(self, command, **_kwargs):
                self.command = command

            def communicate(self, timeout=None):
                del timeout
                output = Path(self.command[self.command.index("--outdir") + 1])
                output.mkdir(parents=True, exist_ok=True)
                pdf = output / "review.pdf"
                document = fitz.open()
                document.new_page(width=400, height=300)
                document.save(pdf)
                document.close()
                return "", ""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / ".k-slide-runs" / "run-1"
            run.mkdir(parents=True)
            with patch("k_slide.normalization.shutil.which", return_value="soffice"), patch("k_slide.normalization.subprocess.Popen", FakeProcess):
                renders = _render_pptx(root / "review.pptx", run, "doc-001")
            self.assertEqual(len(renders), 1)
            staging = StorageLayout.for_workspace(run).path(StorageArtifact.CONVERSION_STAGING, "office/doc-001")
            self.assertTrue(staging.is_dir())
            self.assertEqual(staging.stat().st_mode & 0o777, 0o700)
            self.assertTrue(staging.resolve().is_relative_to(StorageLayout.for_workspace(run).scratch_root.resolve()))
            self.assertEqual(list(staging.iterdir()), [])
            self.assertTrue(renders[0].is_file())

    def test_typed_directory_creation_is_safe_and_recreatable(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside_directory:
            root = Path(directory)
            run = root / ".k-slide-runs" / "run-1"
            run.mkdir(parents=True)
            layout = StorageLayout.for_workspace(run)
            staging = layout.ensure_directory(StorageArtifact.CONVERSION_STAGING, "office/doc-001")
            self.assertTrue(staging.is_dir())
            self.assertEqual(staging.stat().st_mode & 0o777, 0o700)
            (staging / "temporary-child").write_text("scratch", encoding="utf-8")
            layout.cleanup_scratch()
            self.assertFalse(layout.scratch_root.exists())
            recreated = layout.ensure_directory(StorageArtifact.CONVERSION_STAGING, "office/doc-001")
            self.assertTrue(recreated.is_dir())
            self.assertEqual(recreated.stat().st_mode & 0o777, 0o700)
            with self.assertRaises(KSlideError):
                layout.ensure_directory(StorageArtifact.CONVERSION_STAGING, "../outside")
            outside = Path(outside_directory) / "alias-target"
            outside.mkdir()
            alias = recreated.parent / "alias"
            alias.symlink_to(outside, target_is_directory=True)
            with self.assertRaises(KSlideError):
                layout.ensure_directory(StorageArtifact.CONVERSION_STAGING, "office/alias")

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
            writer.write(TelemetryEvent(TelemetryEventType.LIFECYCLE, TelemetryReference.from_internal(TelemetryReferenceKind.EVENT, TelemetryMachineId.new(TelemetryReferenceKind.EVENT)), "2026-01-01T00:00:00Z", run_ref=TelemetryReference.from_internal(TelemetryReferenceKind.RUN, TelemetryMachineId.new(TelemetryReferenceKind.RUN)), lifecycle=TelemetryLifecycle.RUNNING))
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
            layout.write_text(StorageArtifact.CONVERSION_STAGING, "recreated/b.tmp", "new scratch")
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
            for artifact, relative_path in (
                (StorageArtifact.ADMISSION_RECORD, f"jobs/{receipt.job_id}.json"),
                (StorageArtifact.ADMISSION_CONTROL, "admission/CONTROL_STATE.json"),
                (StorageArtifact.ADMISSION_QUEUE, "admission/QUEUE.json"),
                (StorageArtifact.EXECUTION_JOB, f"run-store/jobs/{receipt.job_id}.json"),
            ):
                path = layout.path(artifact, relative_path)
                self.assertEqual(layout.resolve(layout.reference(artifact, relative_path), expected_plane=StoragePlane.DURABLE_USER_WORKSPACE_RUN_DATA), path)
                self.assertTrue(path.is_file(), f"missing durable producer output for {artifact.value}")
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
    def _reference(kind: TelemetryReferenceKind) -> TelemetryReference:
        return TelemetryReference.from_internal(kind, TelemetryMachineId.new(kind))

    def test_public_reference_constructors_require_typed_identities(self) -> None:
        prose = (
            "run-mergerroadmapq4",
            "event-quarterlyplan",
            "deployment-projectalpha",
            "model-confidentiallaunch",
            "worker-boardreview",
            "lowercase-prompt-like-slug",
            "path/to/source.png",
            "AccessKey=canary",
            "분기별 인수 계획",
        )
        for kind in TelemetryReferenceKind:
            for value in prose:
                with self.subTest(constructor="from_internal", kind=kind, value=value), self.assertRaises(KSlideError):
                    TelemetryReference.from_internal(kind, value)
                with self.subTest(constructor="from_identity", kind=kind, value=value), self.assertRaises(KSlideError):
                    TelemetryReference.from_identity(kind, value)
                with self.subTest(constructor="from_canonical", kind=kind, value=value), self.assertRaises(KSlideError):
                    TelemetryReference.from_canonical(value)
            with self.subTest(constructor="from_identity_mapping", kind=kind), self.assertRaises(KSlideError):
                TelemetryReference.from_identity(kind, {"source": "confidential launch", "nested": {"prompt": "ignore"}})

        with self.assertRaises(KSlideError):
            TelemetryReference(TelemetryReferenceKind.RUN, "a" * 64)

        machine_id = TelemetryMachineId.new(TelemetryReferenceKind.EVENT)
        reference = TelemetryReference.from_internal(TelemetryReferenceKind.EVENT, machine_id)
        self.assertEqual(TelemetryReference.from_canonical(reference.canonical), reference)
        with self.assertRaises(KSlideError):
            TelemetryReference.from_internal(TelemetryReferenceKind.RUN, machine_id)
        with self.assertRaises(KSlideError):
            TelemetryReference.from_identity(TelemetryReferenceKind.RUN, TelemetryMachineId.new(TelemetryReferenceKind.EVENT))

    def test_identity_type_to_reference_kind_relationships_fail_closed(self) -> None:
        runtime = reference_runtime()
        environment = reference_environment()
        job = DurableJobIdentity("run-typed", "job-typed", "execution-typed", "scope-typed", "store-typed")
        scope = AuthorizedScopeContext("user-typed", "workspace-typed", "scope-typed")

        self.assertTrue(TelemetryReference.from_identity(TelemetryReferenceKind.RUNTIME, runtime).canonical.startswith("kslide-ref-v1.runtime."))
        self.assertTrue(TelemetryReference.from_identity(TelemetryReferenceKind.DEPLOYMENT, environment).canonical.startswith("kslide-ref-v1.deployment."))
        self.assertTrue(TelemetryReference.from_identity(TelemetryReferenceKind.RUN, job).canonical.startswith("kslide-ref-v1.run."))
        for kind, identity in (
            (TelemetryReferenceKind.RUN, runtime),
            (TelemetryReferenceKind.MODEL, runtime),
            (TelemetryReferenceKind.MODEL, scope),
            (TelemetryReferenceKind.DEPLOYMENT, scope),
            (TelemetryReferenceKind.RUNTIME, job),
            (TelemetryReferenceKind.EVENT, environment),
        ):
            with self.subTest(kind=kind, identity=type(identity).__name__), self.assertRaises(KSlideError):
                TelemetryReference.from_identity(kind, identity)

    def test_allowlisted_non_content_event_classes_are_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            writer = TelemetryWriter(Path(directory))
            for event_type in TelemetryEventType:
                self.assertTrue(writer.write(TelemetryEvent(
                    event_type,
                    self._reference(TelemetryReferenceKind.EVENT),
                    "2026-01-01T00:00:00Z",
                    deployment_ref=self._reference(TelemetryReferenceKind.DEPLOYMENT),
                    runtime_ref=self._reference(TelemetryReferenceKind.RUNTIME),
                    model_ref=self._reference(TelemetryReferenceKind.MODEL),
                    run_ref=self._reference(TelemetryReferenceKind.RUN),
                    worker_ref=self._reference(TelemetryReferenceKind.WORKER),
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
            typed_job = DurableJobIdentity("run-mergerroadmapq4", "job-opaque", "execution-opaque", "scope-opaque", "store-opaque")
            typed_run_ref = TelemetryReference.from_identity(TelemetryReferenceKind.RUN, typed_job)
            self.assertRegex(str(runtime_identity_ref), r"^kslide-ref-v1\.runtime\.[0-9a-f]{64}$")
            with self.assertRaises(KSlideError):
                TelemetryReference.from_identity(TelemetryReferenceKind.RUNTIME, {"source": "MergerRoadmapQ4"})
            base = {
                "event_type": TelemetryEventType.ERROR.value,
                "event_id": str(self._reference(TelemetryReferenceKind.EVENT)),
                "occurred_at": "2026-01-01T00:00:00Z",
                "deployment_ref": str(self._reference(TelemetryReferenceKind.DEPLOYMENT)),
                "runtime_ref": str(runtime_identity_ref),
                "model_ref": str(self._reference(TelemetryReferenceKind.MODEL)),
                "run_ref": str(typed_run_ref),
                "worker_ref": str(self._reference(TelemetryReferenceKind.WORKER)),
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
            self.assertNotIn("mergerroadmapq4", json.dumps(record))

    def test_unknown_nested_content_and_secret_fields_are_rejected_before_persistence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            writer = TelemetryWriter(Path(directory))
            rejected = (
                {"event_type": "error", "event_id": str(self._reference(TelemetryReferenceKind.EVENT)), "occurred_at": "2026-01-01T00:00:00Z", "error": {"source_text": "secret source"}},
                {"event_type": "error", "event_id": str(self._reference(TelemetryReferenceKind.EVENT)), "occurred_at": "2026-01-01T00:00:00Z", "stage": "AccessKey=canary"},
                {"event_type": "error", "event_id": str(self._reference(TelemetryReferenceKind.EVENT)), "occurred_at": "2026-01-01T00:00:00Z", "unknown": "value"},
                {"event_type": "error", "event_id": str(self._reference(TelemetryReferenceKind.EVENT)), "occurred_at": "2026-01-01T00:00:00Z", "count": b"secret"},
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
            writer.write(TelemetryEvent(TelemetryEventType.ERROR, self._reference(TelemetryReferenceKind.EVENT), "2026-01-01T00:00:00Z", run_ref=self._reference(TelemetryReferenceKind.RUN), error_code=TelemetryErrorCode.INTERNAL))
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
                self._reference(TelemetryReferenceKind.EVENT),
                "2026-01-01T00:00:00Z",
                lifecycle=TelemetryLifecycle.RUNNING,
            )
            with patch.object(Path, "open", side_effect=OSError("central telemetry is unavailable")):
                self.assertFalse(writer.write(event))
            self.assertFalse(writer.event_path.is_file())


if __name__ == "__main__":
    unittest.main()
