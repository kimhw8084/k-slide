from __future__ import annotations

import io
import json
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from k_slide.authentication import authentication_readiness, require_access_key
from k_slide.cli import _next, main
from k_slide.evidence_ir import EvidenceIR, EvidenceRegion, save_evidence
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
        secret = "fixture-token-123._~+/=="
        bearer = "Bearer fixture-token-456._~+/=="
        self.assertEqual(authentication_readiness({}).as_dict(), {"ready": False, "reason": "missing"})
        self.assertEqual(authentication_readiness({"AccessKey": "   "}).reason, "empty")
        self.assertEqual(authentication_readiness({"AccessKey": " valid "}).reason, "unusable")
        self.assertEqual(authentication_readiness({"AccessKey": "valid\nkey"}).reason, "unusable")
        for value in ("fixture,token", "fixture;token", 'fixture"token', "fixture'token"):
            self.assertEqual(authentication_readiness({"AccessKey": value}).reason, "unusable")
        self.assertEqual(authentication_readiness({"AccessKey": secret}).as_dict(), {"ready": True, "reason": "available"})
        self.assertEqual(authentication_readiness({"AccessKey": bearer}).as_dict(), {"ready": True, "reason": "available"})
        self.assertEqual(require_access_key({"AccessKey": secret}), secret)
        with self.assertRaises(KSlideError) as raised:
            require_access_key({"AccessKey": ""})
        self.assertEqual(raised.exception.code, ErrorCode.AUTHENTICATION_FAILED)
        self.assertNotIn(secret, json.dumps(raised.exception.as_dict()))

    def test_access_key_redaction_covers_metadata_diagnostics_and_support(self) -> None:
        secret = "fixture-token-789._~+/=="
        bearer = "Bearer fixture-token-987._~+/=="
        for spelling in ("AccessKey", "access_key", "access-key", "access key", "ACCESSKEY"):
            self.assertEqual(redact_value({spelling: secret})[spelling], "[REDACTED_SECRET]")
            for value in (secret, bearer):
                safe = redact_text(f'{spelling}="{value}", next_action=retry')
                self.assertNotIn(value, safe)
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

    def test_next_sanitizes_all_state_derived_failure_fields(self) -> None:
        token = "fixture-state-token-001._~+/=="
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_dir = self._run_with_state(
                root,
                RunState(
                    run_id="k-slide-state-diagnostic",
                    mode="smart",
                    phase=RunPhase.FAILED_RUNTIME,
                    next_action=f'Retry with AccessKey="{token}".',
                    error_code=f"AccessKey={token}",
                    error_message=f'Processing failed: AccessKey="{token}".',
                ),
            )
            result = _next(root, run_dir.name, None)
            serialized = json.dumps(result)
            self.assertEqual(result["status"], "PROCESSING_FAILED")
            self.assertNotIn(token, serialized)
            self.assertEqual(result["error_code"], "AccessKey=[REDACTED]")
            self.assertIn("[REDACTED]", result["error_message"])
            self.assertIn("[REDACTED]", result["next_action"])

    def test_cli_json_and_text_error_boundaries_sanitize_nested_diagnostics(self) -> None:
        token = "fixture-cli-token-001._~+/=="

        def invoke(*arguments: str) -> tuple[int, str]:
            output = io.StringIO()
            with redirect_stdout(output):
                code = main(["next", "--root", ".", *arguments])
            return code, output.getvalue()

        error = KSlideError(
            ErrorCode.INTERNAL,
            f'Command failed: AccessKey="{token}".',
            {"nested": {"error_message": f"AccessKey={token}", "AccessKey": token, "next_action": "Retry safely."}},
        )
        with patch("k_slide.cli._find_run", side_effect=error):
            code, output = invoke("--json")
        self.assertNotEqual(code, 0)
        payload = json.loads(output)
        self.assertEqual(payload["error"]["code"], ErrorCode.INTERNAL.value)
        self.assertNotIn(token, output)
        self.assertIn("[REDACTED_SECRET]", output)
        self.assertIn("[REDACTED]", output)

        with patch("k_slide.cli._find_run", side_effect=error):
            code, output = invoke()
        self.assertNotEqual(code, 0)
        self.assertNotIn(token, output)
        self.assertIn("error_code:", output)
        self.assertIn("error_message:", output)
        self.assertIn("error_details:", output)

        generic = RuntimeError(f'Unexpected failure: AccessKey="{token}".')
        with patch("k_slide.cli._find_run", side_effect=generic):
            code, output = invoke("--json")
        self.assertNotEqual(code, 0)
        self.assertEqual(json.loads(output)["error"]["code"], "KSLIDE_INTERNAL")
        self.assertNotIn(token, output)

        with patch("k_slide.cli._find_run", side_effect=generic):
            code, output = invoke()
        self.assertNotEqual(code, 0)
        self.assertNotIn(token, output)
        self.assertIn("error_code: KSLIDE_INTERNAL", output)

    def test_evidence_payload_is_not_changed_by_operational_sanitization(self) -> None:
        source_text = "Business note: AccessKey=fixture-business-token"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_dir = self._run_with_state(
                root,
                RunState(run_id="k-slide-source-content", mode="smart", phase=RunPhase.TRANSLATING, current_work_unit="unit-1"),
            )
            save_evidence(
                run_dir,
                EvidenceIR(
                    "doc-1",
                    "unit-1",
                    {"document_id": "doc-1", "title": source_text},
                    regions=(EvidenceRegion("unit-1-r1", selected_literal_candidate=source_text),),
                    required_source_ids=("unit-1-r1",),
                ).with_revision(),
            )
            output = io.StringIO()
            with redirect_stdout(output):
                code = main(["evidence", "--root", str(root), "--run", run_dir.name, "--json"])
            self.assertEqual(code, 0)
            self.assertIn(source_text, output.getvalue())

    def test_opencode_does_not_forward_raw_stderr(self) -> None:
        tool_source = (Path(__file__).resolve().parents[1] / ".opencode" / "tools" / "kslide.ts").read_text(encoding="utf-8")
        self.assertIn("Never forward stderr across the OpenCode boundary.", tool_source)
        self.assertNotIn("stderr.trim() ||", tool_source)


if __name__ == "__main__":
    unittest.main()
