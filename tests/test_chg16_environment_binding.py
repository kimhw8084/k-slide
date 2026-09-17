from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from k_slide.environment import RunEnvironmentIdentity
from k_slide.errors import ErrorCode, KSlideError
from k_slide.execution import ExecutionController, ExecutionProfile, WorkspaceRunStore, new_execution_job
from k_slide.paas import (
    AuthorizedScopeContext,
    PaaSController,
    PaaSJobRequest,
    PaaSWorker,
    ReferencePaaSJobService,
    ReferenceWorkerEngine,
    RuntimeIdentity,
)


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
    def _submit(self, root: Path, environment: RunEnvironmentIdentity, *, scope: AuthorizedScopeContext | None = None, run_id: str = "run-environment", total: int = 2):
        service = ReferencePaaSJobService(root)
        runtime = _runtime(environment)
        request = PaaSJobRequest(
            run_id=run_id,
            scope_ref=scope.scope_ref if scope else "scope",
            store_ref=f"store-{run_id}",
            runtime_identity=runtime,
            environment_identity=environment,
            total_work_units=total,
        )
        return PaaSController(service, scope_context=scope).submit(request)

    def test_creation_persists_one_complete_identity_and_recreation_is_field_equivalent(self) -> None:
        environment = _environment()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt = self._submit(root, environment)
            service = ReferencePaaSJobService(root)
            job = service.open_store(receipt.identity).load(receipt.job_id)
            self.assertEqual(job.environment_identity, environment)
            self.assertEqual(job.checkpoint.environment_identity_sha256, environment.identity_sha256)
            recreated = ReferencePaaSJobService(root).open_store(receipt.identity).load(receipt.job_id)
            self.assertEqual(recreated.environment_identity.as_dict(), environment.as_dict())
            self.assertEqual(recreated.environment_identity.identity_sha256, environment.identity_sha256)
            status = ReferencePaaSJobService(root).inspect(receipt.identity).as_dict()
            self.assertEqual(status["environment_identity"], environment.as_dict())
            self.assertEqual(status["environment_identity_sha256"], environment.identity_sha256)

    def test_recreated_worker_resumes_checkpoint_and_result_commit_once(self) -> None:
        environment = _environment()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt = self._submit(root, environment)
            first_engine = _CountingEngine()
            first = PaaSWorker(ReferencePaaSJobService(root), worker_id="worker-one", runtime_identity=_runtime(environment), engine=first_engine).run_once(receipt.identity)
            self.assertEqual(first.status, "ACCEPTED")
            self.assertEqual(first_engine.calls, 1)
            self.assertEqual(len(first.job.result_markers), 1)

            second_engine = _CountingEngine()
            resumed = PaaSWorker(ReferencePaaSJobService(root), worker_id="worker-two", runtime_identity=_runtime(environment), engine=second_engine).run_until_terminal(receipt.identity)
            self.assertEqual(resumed.status, "DONE")
            self.assertEqual(second_engine.calls, 1)
            committed = ReferencePaaSJobService(root).open_store(receipt.identity).load(receipt.job_id)
            self.assertEqual(len(committed.result_markers), 2)
            replay = PaaSWorker(ReferencePaaSJobService(root), worker_id="worker-three", runtime_identity=_runtime(environment), engine=_CountingEngine()).run_once(receipt.identity)
            self.assertEqual(replay.status, "DONE")
            self.assertEqual(len(ReferencePaaSJobService(root).open_store(receipt.identity).load(receipt.job_id).result_markers), 2)

    def test_rolling_upgrade_binds_new_runs_only_and_cannot_rewrite_old_binding(self) -> None:
        old_environment = _environment("a")
        new_environment = _environment("b")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old_receipt = self._submit(root, old_environment, run_id="run-old")
            new_receipt = self._submit(root, new_environment, run_id="run-new")
            service = ReferencePaaSJobService(root)
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
                worker = PaaSWorker(ReferencePaaSJobService(root), worker_id="stale-worker", runtime_identity=_runtime(modified), engine=engine, scope_context=scope)
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
                PaaSWorker(ReferencePaaSJobService(root), worker_id="wrong", runtime_identity=_runtime(changed), engine=ReferenceWorkerEngine()).run_once(receipt.identity)
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


if __name__ == "__main__":
    unittest.main()
