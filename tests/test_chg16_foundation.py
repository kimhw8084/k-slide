from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from k_slide.authentication import authentication_readiness, require_access_key
from k_slide.cli import _next
from k_slide.errors import ErrorCode, KSlideError
from k_slide.queue import WorkQueue, WorkUnit, WorkUnitStatus, save_queue
from k_slide.redaction import redact_text, redact_value
from k_slide.state import OPERATIONAL_FAILURE_PHASES, RunPhase, RunState, save_state
from k_slide.support import build_support_bundle


class Chg16FoundationTests(unittest.TestCase):
    def _run_with_state(self, root: Path, state: RunState) -> Path:
        run_dir = root / ".k-slide-runs" / state.run_id
        run_dir.mkdir(parents=True, mode=0o700)
        save_state(run_dir, state)
        return run_dir

    def test_operational_failure_phases_are_not_reported_as_needs_review(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for phase in OPERATIONAL_FAILURE_PHASES:
                run_id = f"k-slide-{phase.value.lower()}"
                run_dir = self._run_with_state(
                    root,
                    RunState(
                        run_id=run_id,
                        mode="smart",
                        phase=phase,
                        next_action="Retry after fixing the reported failure.",
                        error_code=f"KSLIDE_{phase.value}",
                        error_message="Processing failed safely.",
                    ),
                )
                result = _next(root, run_dir.name, None)
                self.assertEqual(result["status"], "PROCESSING_FAILED")
                self.assertEqual(result["phase"], phase.value)
                self.assertEqual(result["error_code"], f"KSLIDE_{phase.value}")
                self.assertNotEqual(result["status"], "NEEDS_REVIEW")

    def test_needs_review_remains_reserved_for_semantic_review_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_id = "k-slide-semantic-review"
            run_dir = self._run_with_state(root, RunState(run_id=run_id, mode="smart", phase=RunPhase.NEEDS_REVIEW))
            save_queue(
                run_dir,
                WorkQueue(
                    run_id=run_id,
                    work_units=[WorkUnit("unit-1", "doc-1", "source-1", 0, status=WorkUnitStatus.NEEDS_REVIEW)],
                ),
            )
            result = _next(root, run_dir.name, None)
            self.assertEqual(result["status"], "NEEDS_REVIEW")

    def test_access_key_readiness_is_secret_free_and_fails_closed(self) -> None:
        secret = "company-access-secret-123"
        self.assertEqual(authentication_readiness({}).as_dict(), {"ready": False, "reason": "missing"})
        self.assertEqual(authentication_readiness({"AccessKey": "   "}).reason, "empty")
        self.assertEqual(authentication_readiness({"AccessKey": " valid "}).reason, "unusable")
        self.assertEqual(authentication_readiness({"AccessKey": "valid\nkey"}).reason, "unusable")
        self.assertEqual(authentication_readiness({"AccessKey": secret}).as_dict(), {"ready": True, "reason": "available"})
        self.assertEqual(require_access_key({"AccessKey": secret}), secret)
        with self.assertRaises(KSlideError) as raised:
            require_access_key({"AccessKey": ""})
        self.assertEqual(raised.exception.code, ErrorCode.AUTHENTICATION_FAILED)
        self.assertNotIn(secret, json.dumps(raised.exception.as_dict()))

    def test_access_key_redaction_covers_metadata_diagnostics_and_support(self) -> None:
        secret = "company-access-secret-456"
        for spelling in ("AccessKey", "access_key", "access-key", "access key", "ACCESSKEY"):
            self.assertEqual(redact_value({spelling: secret})[spelling], "[REDACTED_SECRET]")
            safe = redact_text(f"{spelling}={secret}")
            self.assertNotIn(secret, safe)
            self.assertIn("[REDACTED]", safe)
        self.assertNotIn(secret, redact_text(json.dumps({"AccessKey": secret})))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / ".k-slide-runs" / "k-slide-auth-diagnostic"
            run.mkdir(parents=True, mode=0o700)
            (run / "RUN_STATE.json").write_text(
                json.dumps(
                    {
                        "run_id": run.name,
                        "phase": "FAILED_RUNTIME",
                        "error_code": f"AccessKey={secret}",
                    }
                ),
                encoding="utf-8",
            )
            output = root / "support.zip"
            build_support_bundle(root, output)
            with zipfile.ZipFile(output) as archive:
                content = archive.read("support-metadata.json").decode("utf-8")
            self.assertNotIn(secret, content)
            self.assertIn("[REDACTED]", content)


if __name__ == "__main__":
    unittest.main()
