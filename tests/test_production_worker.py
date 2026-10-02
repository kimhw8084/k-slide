from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from k_slide.errors import ErrorCode, KSlideError
from k_slide.execution import OperationalLifecycle
from k_slide.paas import AuthorizedScopeContext, PaaSController, PaaSJobRequest, PaaSWorker, ReferencePaaSJobService, ReferenceWorkerEngine
from k_slide.worker import _load_engine, main
from tests.reference_fixtures import reference_runtime
from tests import test_phase11 as run_fixture


class ProductionWorkerTests(unittest.TestCase):
    def test_managed_finalization_rechecks_retained_patch_after_done(self):
        from k_slide.cli import _conflict_assess, _next, _submit
        from k_slide.verify import finalize_run, verify_run
        from tests.reference_fixtures import reference_environment

        fixture = run_fixture.Phase11Tests()
        environment = reference_environment()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = fixture._prepared(root)
            unit_id = _next(root, run.name, None, environment)["work_unit_id"]
            _submit(root, run.name, json.dumps(fixture._payload(run, unit_id)), None, environment)
            _conflict_assess(root, run.name, '{"schema_version":"1.0","candidate_groups":[]}', None, environment)
            self.assertTrue(verify_run(run, environment_identity=environment).passed)
            finalize_run(run, environment_identity=environment, require_patches=True)
            self.assertTrue((run / "RUN_COMPLETE.md").is_file())
            (run / "translations" / f"{unit_id}.json").unlink()
            with self.assertRaises(KSlideError) as error:
                finalize_run(run, environment_identity=environment, require_patches=True)
            self.assertEqual(error.exception.code, ErrorCode.COMPLETION_BLOCKED)
            self.assertFalse((run / "RUN_COMPLETE.md").exists())

    def test_scoped_cli_without_factory_cannot_advance_a_job(self):
        runtime = reference_runtime("worker-guard")
        scope = AuthorizedScopeContext("worker-user", "worker-workspace", "worker-scope")
        with tempfile.TemporaryDirectory() as directory:
            service = ReferencePaaSJobService(Path(directory))
            receipt = PaaSController(service, scope_context=scope).submit(PaaSJobRequest(
                "worker-run", scope.scope_ref, "worker-store", runtime, total_work_units=1,
            ))
            args = ["--service-root", directory, "--job-id", receipt.job_id,
                    "--worker-id", "worker", "--runtime-ref", runtime.runtime_ref,
                    "--model-identity", runtime.model_identity, "--ocr-identity", runtime.ocr_identity,
                    "--termbase-identity", runtime.termbase_identity,
                    "--environment-identity-json", json.dumps(runtime.environment().as_dict()),
                    "--user-ref", scope.user_ref, "--workspace-ref", scope.workspace_ref,
                    "--scope-ref", scope.scope_ref, "--until-terminal"]
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(args), 2)
            self.assertEqual(json.loads(output.getvalue())["status"], "ERROR")
            status = service.inspect(receipt.identity, scope_context=scope)
            self.assertEqual(status.lifecycle, OperationalLifecycle.QUEUED)
            self.assertEqual(status.checkpoint_revision, 0)
            self.assertEqual(list(Path(directory).rglob("RUN_COMPLETE.md")), [])

    def test_reference_engine_requires_explicit_reference_mode(self):
        for spec in (None, "k_slide.paas:ReferenceWorkerEngine"):
            with self.subTest(spec=spec), self.assertRaises(KSlideError):
                _load_engine(spec)
        self.assertIsInstance(_load_engine(None, reference_mode=True), ReferenceWorkerEngine)

    def test_managed_completion_and_replay_call_locked_finalizer(self):
        runtime = reference_runtime("managed-guard")
        scope = AuthorizedScopeContext("user", "workspace", "scope")
        with tempfile.TemporaryDirectory() as directory:
            reference = ReferencePaaSJobService(Path(directory))
            receipt = PaaSController(reference, scope_context=scope).submit(PaaSJobRequest(
                "guard-run", scope.scope_ref, "store", runtime, total_work_units=1,
            ))

            class ManagedService:
                # Exercise managed guard while retaining the tested store protocol.
                def claim(self, *args, **kwargs):
                    return reference.claim(*args, **kwargs)

                def open_store(self, *args, **kwargs):
                    return reference.open_store(*args, **kwargs)

            class Engine:
                def step(self, *args):
                    return ReferenceWorkerEngine().step(*args)

                def run_directory(self, job):
                    return Path(directory) / job.run_id

            worker = PaaSWorker(ManagedService(), worker_id="worker", runtime_identity=runtime,
                                engine=Engine(), scope_context=scope)
            with patch("k_slide.state.load_state") as state, patch("k_slide.queue.load_queue") as queue, patch("k_slide.verify.finalize_run") as finalize:
                state.return_value.run_id = queue.return_value.run_id = "guard-run"
                finalize.side_effect = KSlideError(ErrorCode.COMPLETION_BLOCKED, "Artifacts are incomplete")
                result = worker.run_once(receipt.identity)
                self.assertEqual(result.status, "SEMANTIC_REPAIR")
                self.assertNotEqual(result.job.lifecycle, OperationalLifecycle.COMPLETED)
                finalize.assert_called_once_with(Path(directory) / "guard-run", environment_identity=runtime.environment(), require_patches=True)
                finalize.side_effect = None
                self.assertEqual(worker.run_once(receipt.identity).status, "DONE")
                finalize.side_effect = KSlideError(ErrorCode.COMPLETION_BLOCKED, "Artifacts changed")
                with self.assertRaises(KSlideError):
                    worker.run_once(receipt.identity)


if __name__ == "__main__":
    unittest.main()
