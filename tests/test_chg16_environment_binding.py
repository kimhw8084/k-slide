from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from k_slide.environment import RunEnvironmentIdentity
from k_slide.errors import ErrorCode, KSlideError
from k_slide.cli import _next, _status, _submit
from k_slide.execution import ExecutionController, ExecutionProfile, WorkspaceRunStore, new_execution_job, sync_workspace_execution
from k_slide.extraction import extract_run
from k_slide.ingest import prepare_run
from k_slide.normalization import normalize_run
from k_slide.paas import (
    AuthorizedScopeContext,
    PaaSController,
    PaaSJobRequest,
    PaaSWorker,
    ReferencePaaSJobService,
    ReferenceWorkerEngine,
    RuntimeIdentity,
)
from k_slide.queue import WorkUnitStatus, load_queue, save_queue
from k_slide.evidence_ir import EvidenceIR, EvidenceRegion, save_evidence
from k_slide.state import RunPhase, load_state, save_state
from k_slide.verify import finalize_run, verify_run


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _environment(seed: str = "a") -> RunEnvironmentIdentity:
    return RunEnvironmentIdentity(
        kslide_source_revision=(seed * 40)[:40],
        candidate_identity=_sha(f"candidate-{seed}"),
        candidate_version="1.0",
        kslide_version="0.3.5",
        runtime_artifact_identity=_sha(f"artifact-{seed}"),
        runtime_image_identity=f"sha256:{_sha(f'image-{seed}')}",
        runtime_build_identity=_sha(f"build-{seed}"),
        runtime_manifest_sha256=_sha(f"manifest-{seed}"),
        runtime_sbom_sha256=_sha(f"sbom-{seed}"),
        target_model_identity="google/gemma-4-31b-it",
        effective_model_identity="google/gemma-4-31b-it",
        model_config_identity=_sha(f"model-config-{seed}"),
        semantic_config_identity=_sha(f"semantic-config-{seed}"),
        ocr_asset_identity=_sha(f"ocr-assets-{seed}"),
        ocr_config_identity=_sha(f"ocr-config-{seed}"),
        ocr_provider="paddle",
        termbase_identity=_sha(f"termbase-{seed}"),
        termbase_version="1.0",
    )


def _runtime(environment: RunEnvironmentIdentity) -> RuntimeIdentity:
    return RuntimeIdentity(
        runtime_ref=environment.runtime_image_identity,
        model_identity=environment.effective_model_identity,
        ocr_identity=environment.ocr_asset_identity,
        termbase_identity=environment.termbase_identity,
        environment_identity=environment,
    )


class _CountingEngine(ReferenceWorkerEngine):
    def __init__(self) -> None:
        self.calls = 0

    def step(self, checkpoint, operation_id):
        self.calls += 1
        return super().step(checkpoint, operation_id)


class EnvironmentBindingTests(unittest.TestCase):
    def _reference_service(self, root: Path) -> ReferencePaaSJobService:
        return ReferencePaaSJobService(root, reference_compatibility=True)

    def _submit(self, root: Path, environment: RunEnvironmentIdentity, *, scope: AuthorizedScopeContext | None = None, run_id: str = "run-environment", total: int = 2):
        service = self._reference_service(root)
        runtime = _runtime(environment)
        request = PaaSJobRequest(
            run_id=run_id,
            scope_ref=scope.scope_ref if scope else "scope",
            store_ref=f"store-{run_id}",
            runtime_identity=runtime,
            environment_identity=environment,
            total_work_units=total,
        )
        return PaaSController(service, scope_context=scope, reference_mode=scope is None).submit(request)

    def test_creation_persists_one_complete_identity_and_recreation_is_field_equivalent(self) -> None:
        environment = _environment()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt = self._submit(root, environment)
            service = self._reference_service(root)
            job = service.open_store(receipt.identity).load(receipt.job_id)
            self.assertEqual(job.environment_identity, environment)
            self.assertEqual(job.checkpoint.environment_identity_sha256, environment.identity_sha256)
            recreated = self._reference_service(root).open_store(receipt.identity).load(receipt.job_id)
            self.assertEqual(recreated.environment_identity.as_dict(), environment.as_dict())
            self.assertEqual(recreated.environment_identity.identity_sha256, environment.identity_sha256)
            status = self._reference_service(root).inspect(receipt.identity).as_dict()
            self.assertEqual(status["environment_identity"], environment.as_dict())
            self.assertEqual(status["environment_identity_sha256"], environment.identity_sha256)

    def test_recreated_worker_resumes_checkpoint_and_result_commit_once(self) -> None:
        environment = _environment()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt = self._submit(root, environment)
            first_engine = _CountingEngine()
            first = PaaSWorker(self._reference_service(root), worker_id="worker-one", runtime_identity=_runtime(environment), engine=first_engine).run_once(receipt.identity)
            self.assertEqual(first.status, "ACCEPTED")
            self.assertEqual(first_engine.calls, 1)
            self.assertEqual(len(first.job.result_markers), 1)

            second_engine = _CountingEngine()
            resumed = PaaSWorker(self._reference_service(root), worker_id="worker-two", runtime_identity=_runtime(environment), engine=second_engine).run_until_terminal(receipt.identity)
            self.assertEqual(resumed.status, "DONE")
            self.assertEqual(second_engine.calls, 1)
            committed = self._reference_service(root).open_store(receipt.identity).load(receipt.job_id)
            self.assertEqual(len(committed.result_markers), 2)
            replay = PaaSWorker(self._reference_service(root), worker_id="worker-three", runtime_identity=_runtime(environment), engine=_CountingEngine()).run_once(receipt.identity)
            self.assertEqual(replay.status, "DONE")
            self.assertEqual(len(self._reference_service(root).open_store(receipt.identity).load(receipt.job_id).result_markers), 2)

    def test_rolling_upgrade_binds_new_runs_only_and_cannot_rewrite_old_binding(self) -> None:
        old_environment = _environment("a")
        new_environment = _environment("b")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old_receipt = self._submit(root, old_environment, run_id="run-old")
            new_receipt = self._submit(root, new_environment, run_id="run-new")
            service = self._reference_service(root)
            old_before = service.open_store(old_receipt.identity).load(old_receipt.job_id)
            new_job = service.open_store(new_receipt.identity).load(new_receipt.job_id)
            self.assertEqual(old_before.environment_identity, old_environment)
            self.assertEqual(new_job.environment_identity, new_environment)
            self.assertNotEqual(old_before.environment_identity.identity_sha256, new_job.environment_identity.identity_sha256)
            before = {path: path.read_bytes() for path in root.rglob("*.json")}
            with self.assertRaises(KSlideError) as raised:
                PaaSWorker(
                    service,
                    worker_id="upgraded-worker",
                    runtime_identity=_runtime(new_environment),
                    engine=_CountingEngine(),
                ).run_once(old_receipt.identity)
            self.assertEqual(raised.exception.code, ErrorCode.EXECUTION_ENVIRONMENT_MISMATCH)
            self.assertEqual(old_before.environment_identity, service.open_store(old_receipt.identity).load(old_receipt.job_id).environment_identity)
            self.assertEqual(before, {path: path.read_bytes() for path in root.rglob("*.json")})

    def test_workspace_controller_uses_the_same_fail_closed_binding_before_state_mutation(self) -> None:
        environment = _environment()
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceRunStore(Path(directory) / "run")
            job = new_execution_job(
                "run-workspace-environment",
                profile=ExecutionProfile.WORKSPACE_LOCAL,
                scope_ref="workspace",
                store_ref="workspace-store",
                environment_identity=environment,
            )
            store.create(job)
            wrong = replace(environment, runtime_build_identity=_sha("different-build"))
            with self.assertRaises(KSlideError) as raised:
                ExecutionController(store, environment_identity=wrong).run_step(
                    job.job_id,
                    operation_id="operation-workspace",
                    step=ReferenceWorkerEngine().step,
                )
            self.assertEqual(raised.exception.code, ErrorCode.EXECUTION_ENVIRONMENT_MISMATCH)
            unchanged = store.load(job.job_id)
            self.assertEqual(unchanged.revision, 0)
            self.assertEqual(unchanged.lifecycle.value, "QUEUED")
            self.assertEqual(unchanged.result_markers, ())

    def test_each_decisive_identity_change_refuses_before_engine_and_preserves_scope_state(self) -> None:
        base = _environment()
        changes = {
            "kslide_source_revision": "b" * 40,
            "candidate_identity": _sha("candidate-b"),
            "candidate_version": "2.0",
            "kslide_version": "0.3.6",
            "runtime_artifact_identity": _sha("artifact-b"),
            "runtime_image_identity": f"sha256:{_sha('image-b')}",
            "runtime_build_identity": _sha("build-b"),
            "runtime_manifest_sha256": _sha("manifest-b"),
            "runtime_sbom_sha256": _sha("sbom-b"),
            "target_model_identity": "google/gemma-4-32b-it",
            "effective_model_identity": "google/gemma-4-32b-it",
            "model_config_identity": _sha("model-config-b"),
            "semantic_config_identity": _sha("semantic-config-b"),
            "ocr_asset_identity": _sha("ocr-assets-b"),
            "ocr_config_identity": _sha("ocr-config-b"),
            "termbase_identity": _sha("termbase-b"),
            "execution_contract_version": "2.0",
            "run_store_schema_version": "2.0",
            "evidence_ir_schema_version": "2.0",
            "translation_patch_schema_version": "2.0",
            "slide_ir_schema_version": "2.0",
        }
        scope = AuthorizedScopeContext("user-a", "workspace-a", "scope-a")
        for field, changed in changes.items():
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                run_id = f"run-{field.replace('_', '-').replace('source', 'subject')}"
                receipt = self._submit(root, base, scope=scope, run_id=run_id, total=1)
                before = {path: path.read_bytes() for path in root.rglob("*.json")}
                modified = replace(base, **{field: changed})
                if field == "effective_model_identity":
                    modified = replace(modified, target_model_identity=changed)
                engine = _CountingEngine()
                worker = PaaSWorker(self._reference_service(root), worker_id="stale-worker", runtime_identity=_runtime(modified), engine=engine, scope_context=scope)
                with self.assertRaises(KSlideError) as raised:
                    worker.run_once(receipt.identity)
                self.assertEqual(raised.exception.code, ErrorCode.EXECUTION_ENVIRONMENT_MISMATCH)
                self.assertEqual(raised.exception.details["mismatch_code"], "KSLIDE_RUN_ENVIRONMENT_MISMATCH")
                expected_fields = ["target_model_identity", "effective_model_identity"] if field == "effective_model_identity" else [field if field != "kslide_source_revision" else "kslide_revision"]
                self.assertEqual(raised.exception.details["mismatch_fields"], expected_fields)
                self.assertEqual(engine.calls, 0)
                self.assertEqual(before, {path: path.read_bytes() for path in root.rglob("*.json")})

    def test_status_and_mismatch_diagnostics_are_source_free(self) -> None:
        environment = _environment()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt = self._submit(root, environment)
            changed = replace(environment, runtime_image_identity=f"sha256:{_sha('different-image')}")
            try:
                PaaSWorker(self._reference_service(root), worker_id="wrong", runtime_identity=_runtime(changed), engine=ReferenceWorkerEngine()).run_once(receipt.identity)
            except KSlideError as exc:
                payload = json.dumps(exc.as_dict(), ensure_ascii=False)
            else:  # pragma: no cover
                self.fail("mismatched environment was accepted")
            self.assertNotIn("AccessKey", payload)
            self.assertNotIn(str(root), payload)
            persisted = "\n".join(path.read_text(encoding="utf-8") for path in root.rglob("*.json"))
            self.assertNotIn("AccessKey", persisted)
            self.assertNotIn(str(root), persisted)
            self.assertNotIn("source", persisted.lower())

    def test_workspace_creation_requires_complete_canonical_identity_before_run_directory_creation(self) -> None:
        candidate_variants = {
            "missing": None,
            "incomplete": {"schema_version": "1.0"},
            "unresolved": {
                "schema_version": "1.0",
                "subject_git_sha": "UNSET",
                "requested_model": "google/gemma-4-31b-it",
            },
        }
        for name, candidate in candidate_variants.items():
            with self.subTest(identity=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / "slide.png"
                source.write_bytes(b"\x89PNG\r\n\x1a\nfixture")
                if candidate is not None:
                    config = root / ".k-slide-config"
                    config.mkdir()
                    (config / "production-candidate.json").write_text(json.dumps(candidate), encoding="utf-8")
                with self.assertRaises(KSlideError) as raised:
                    prepare_run(root, explicit_paths=[str(source)])
                self.assertEqual(raised.exception.code, ErrorCode.EXECUTION_INVALID)
                self.assertFalse((root / ".k-slide-runs").exists())

    def test_explicit_reference_fixture_opt_in_remains_deterministic(self) -> None:
        environment = RunEnvironmentIdentity.legacy_reference(
            runtime_ref="runtime-reference",
            model_identity="model-reference",
            ocr_identity="ocr-reference",
            termbase_identity="termbase-reference",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "slide.png"
            source.write_bytes(b"\x89PNG\r\n\x1a\nfixture")
            run = prepare_run(root, explicit_paths=[str(source)], environment_identity=environment)
            self.assertEqual(WorkspaceRunStore(run).load(f"job-{run.name}").environment_identity, environment)

    def test_paas_submission_and_worker_startup_refuse_missing_canonical_identity(self) -> None:
        runtime = RuntimeIdentity("runtime-reference", "model-reference", "ocr-reference", "termbase-reference")
        with self.assertRaises(KSlideError) as raised:
            PaaSJobRequest("run-missing-environment", "scope", "store-missing-environment", runtime)
        self.assertEqual(raised.exception.code, ErrorCode.EXECUTION_INVALID)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(KSlideError) as raised:
                PaaSWorker(
                    self._reference_service(Path(directory)),
                    worker_id="worker-missing-environment",
                    runtime_identity=runtime,
                    engine=ReferenceWorkerEngine(),
                )
            self.assertEqual(raised.exception.code, ErrorCode.EXECUTION_INVALID)

    def _translation_run(self, root: Path, environment: RunEnvironmentIdentity) -> Path:
        source = root / "slide.png"
        source.write_bytes(b"\x89PNG\r\n\x1a\nfixture")
        run = prepare_run(root, explicit_paths=[str(source)], environment_identity=environment)
        queue = load_queue(run)
        unit = queue.work_units[0]
        evidence = EvidenceIR(
            "doc-001",
            unit.work_unit_id,
            {"input_id": unit.source_input_id, "width_px": 100, "height_px": 100},
            (EvidenceRegion(f"{unit.work_unit_id}-r001", (0, 0, 100, 100), (0, 0, 1, 1), selected_literal_candidate="검토", literal_confidence=1.0),),
            required_source_ids=(f"{unit.work_unit_id}-r001",),
        ).with_revision()
        save_evidence(run, evidence)
        unit.status = WorkUnitStatus.READY
        unit.evidence_revision = evidence.evidence_revision
        save_queue(run, queue)
        state = load_state(run)
        state.transition(RunPhase.NORMALIZED)
        state.transition(RunPhase.EXTRACTED)
        save_state(run, state)
        return run

    def test_workspace_mismatch_is_before_every_resumable_mutation_and_identity_a_reconnects(self) -> None:
        actions = {
            "next": lambda root, run, wrong: _next(root, run.name, None, wrong),
            "repair": lambda root, run, wrong: _next(root, run.name, None, wrong),
            "submit": lambda root, run, wrong: _submit(root, run.name, "{}", None, wrong),
            "normalize": lambda root, run, wrong: normalize_run(run, environment_identity=wrong),
            "extract": lambda root, run, wrong: extract_run(run, environment_identity=wrong),
            "verify": lambda root, run, wrong: verify_run(run, environment_identity=wrong),
            "finalize": lambda root, run, wrong: finalize_run(run, environment_identity=wrong),
            "sync": lambda root, run, wrong: sync_workspace_execution(run, environment_identity=wrong),
        }
        for name, action in actions.items():
            with self.subTest(action=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                expected = _environment("a")
                wrong = _environment("b")
                run = self._translation_run(root, expected)
                if name == "repair":
                    queue = load_queue(run)
                    queue.work_units[0].status = WorkUnitStatus.VERIFY_FAILED
                    save_queue(run, queue)
                    state = load_state(run)
                    state.transition(RunPhase.TRANSLATING)
                    state.transition(RunPhase.FAIL_REPAIRABLE)
                    save_state(run, state)
                before = {path: path.read_bytes() for path in root.rglob("*") if path.is_file()}
                with self.assertRaises(KSlideError) as raised:
                    action(root, run, wrong)
                self.assertEqual(raised.exception.code, ErrorCode.EXECUTION_ENVIRONMENT_MISMATCH)
                self.assertEqual(before, {path: path.read_bytes() for path in root.rglob("*") if path.is_file()})

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = _environment("a")
            run = self._translation_run(root, expected)
            result = _next(root, run.name, None, expected)
            self.assertEqual(result["status"], "READY")
            self.assertEqual(load_state(run).phase, RunPhase.TRANSLATING)

    def test_status_under_mismatch_is_read_only_and_source_free(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = _environment("a")
            wrong = _environment("b")
            run = self._translation_run(root, expected)
            before = {path: path.read_bytes() for path in root.rglob("*") if path.is_file()}
            status = _status(root, run.name, None, wrong)
            self.assertEqual(status["environment_compatibility"], "INCOMPATIBLE")
            self.assertEqual(status["environment_error"]["details"]["mismatch_code"], "KSLIDE_RUN_ENVIRONMENT_MISMATCH")
            self.assertEqual(before, {path: path.read_bytes() for path in root.rglob("*") if path.is_file()})


if __name__ == "__main__":
    unittest.main()
