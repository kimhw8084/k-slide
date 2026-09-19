from __future__ import annotations

import io
import json
import os
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
from k_slide.redaction import redact_json, redact_text, redact_value, sanitize_operational
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
        self.assertEqual(authentication_readiness({}).as_dict(), {"ready": False, "reason": "missing"})
        self.assertEqual(authentication_readiness({"AccessKey": None}).reason, "unusable")
        self.assertEqual(authentication_readiness({"AccessKey": 1234}).reason, "unusable")
        with self.assertRaises(KSlideError) as raised:
            require_access_key({"AccessKey": ""})
        self.assertEqual(raised.exception.code, ErrorCode.AUTHENTICATION_FAILED)
        self.assertEqual(authentication_readiness({"AccessKey": ""}).reason, "empty")

        supported_values = (
            "ordinary-token",
            " token with spaces ",
            "   ",
            "comma,value",
            "semicolon;value",
            'double"quote',
            "apostrophe'value",
            "equals=colon:slash/like\\",
            "mixed!@#$%^&*()[]{}<>|,;:'\"",
            "unicode-한글-🧪",
            "Bearer-looking value",
            "line\nbreak",
        )
        for value in supported_values:
            self.assertEqual(authentication_readiness({"AccessKey": value}).reason, "available")
        self.assertEqual(require_access_key({"AccessKey": supported_values[0]}), supported_values[0])

    def test_access_key_redaction_masks_exact_opaque_values_before_heuristics(self) -> None:
        canary = 'synthetic opaque canary ::,;="\' / 한글'
        with patch.dict(os.environ, {"AccessKey": canary}, clear=False):
            direct = f"diagnostic text: {canary}"
            self.assertNotIn(canary, redact_text(direct, secret_values=(canary,)))
            payload = {
                "AccessKey": canary,
                "nested": {"diagnostic": canary, "items": [f"before {canary} after", {"opaque": canary}]},
                "list": [canary],
            }
            safe = sanitize_operational(payload, secret_values=(canary,))
            serialized = json.dumps(safe, ensure_ascii=False)
            self.assertNotIn(canary, serialized)
            self.assertEqual(safe["AccessKey"], "[REDACTED_SECRET]")
            self.assertNotIn(canary, redact_json(payload, secret_values=(canary,)))

            error = KSlideError(ErrorCode.INTERNAL, f"Diagnostic value: {canary}", {"nested": [canary, {"value": canary}]})
            self.assertNotIn(canary, json.dumps(error.as_dict(), ensure_ascii=False))

        for spelling in ("AccessKey", "access_key", "access-key", "access key", "ACCESSKEY"):
            self.assertEqual(redact_value({spelling: "fixture-structured-value"})[spelling], "[REDACTED_SECRET]")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / ".k-slide-runs" / "k-slide-auth-diagnostic"
            run.mkdir(parents=True, mode=0o700)
            with patch.dict(os.environ, {"AccessKey": canary}, clear=False):
                (run / "RUN_STATE.json").write_text(
                    json.dumps(
                        {
                            "run_id": run.name,
                            "phase": "FAILED_RUNTIME",
                            "error_code": f"AccessKey={canary}",
                        }
                    ),
                    encoding="utf-8",
                )
                output = root / "support.zip"
                build_support_bundle(root, output)
                with zipfile.ZipFile(output) as archive:
                    content = archive.read("support-metadata.json").decode("utf-8")
            self.assertNotIn(canary, content)
            self.assertIn("[REDACTED]", content)

    def test_next_sanitizes_all_state_derived_failure_fields(self) -> None:
        token = 'synthetic state canary,;=" / 한글'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.dict(os.environ, {"AccessKey": token}, clear=False):
                run_dir = self._run_with_state(
                    root,
                    RunState(
                        run_id="k-slide-state-diagnostic",
                        mode="smart",
                        phase=RunPhase.FAILED_RUNTIME,
                        next_action=f"Retry with AccessKey=\"{token}\".",
                        error_code=f"AccessKey={token}",
                        error_message=f"Processing failed: AccessKey=\"{token}\".",
                    ),
                )
                persisted = (run_dir / "RUN_STATE.json").read_text(encoding="utf-8")
                result = _next(root, run_dir.name, None)
            self.assertNotIn(token, persisted)
            serialized = json.dumps(result)
            self.assertEqual(result["status"], "PROCESSING_FAILED")
            self.assertNotIn(token, serialized)
            self.assertEqual(result["error_code"], "AccessKey=[REDACTED]")
            self.assertIn("[REDACTED]", result["error_message"])
            self.assertIn("[REDACTED]", result["next_action"])

    def test_cli_json_and_text_error_boundaries_sanitize_nested_diagnostics(self) -> None:
        token = 'synthetic CLI canary,;=" / 한글'

        def invoke(*arguments: str) -> tuple[int, str]:
            output = io.StringIO()
            with redirect_stdout(output):
                code = main(["next", "--root", ".", *arguments])
            return code, output.getvalue()

        with patch.dict(os.environ, {"AccessKey": token}, clear=False):
            error = KSlideError(
                ErrorCode.INTERNAL,
                f"Command failed: AccessKey=\"{token}\".",
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

            generic = RuntimeError(f"Unexpected failure: AccessKey=\"{token}\".")
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
