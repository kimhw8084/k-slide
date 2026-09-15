from __future__ import annotations

import hashlib
import io
import json
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path

from k_slide.cli import _next, build_parser, main
from k_slide.errors import ErrorCode, KSlideError
from k_slide.host_adapter import (
    HOST_ADAPTER_SCHEMA_VERSION,
    HOST_ADAPTER_VERSION,
    HostInputReference,
    HostInvocation,
    OperationalState,
    SemanticOutcome,
    add_host_contract,
    phase_contract,
    validate_host_inputs,
)
from k_slide.ingest import prepare_run
from k_slide.installer import install, verify_install
from k_slide.redaction import sanitize_operational
from k_slide.security import sha256_file
from k_slide.state import RunPhase, RunState, load_state, save_state
from k_slide.support import build_support_bundle


PNG = b"\x89PNG\r\n\x1a\nsynthetic-host-fixture"


class HostIntegrationTests(unittest.TestCase):
    def _reference(self, path: Path, name: str, kind: str = "workspace_file") -> HostInputReference:
        return HostInputReference(kind, name, path.as_uri())

    def test_versioned_contract_separates_lifecycle_from_semantic_outcome(self) -> None:
        self.assertEqual(phase_contract(RunPhase.CREATED), (OperationalState.QUEUED.value, SemanticOutcome.PENDING.value))
        self.assertEqual(phase_contract(RunPhase.TRANSLATING), (OperationalState.RUNNING.value, SemanticOutcome.PENDING.value))
        self.assertEqual(phase_contract(RunPhase.REPAIRING), (OperationalState.RETRYING.value, SemanticOutcome.PENDING.value))
        self.assertEqual(phase_contract(RunPhase.COMPLETE), (OperationalState.COMPLETED.value, SemanticOutcome.DONE.value))
        self.assertEqual(phase_contract(RunPhase.NEEDS_REVIEW), (OperationalState.COMPLETED.value, SemanticOutcome.NEEDS_REVIEW.value))
        self.assertEqual(phase_contract(RunPhase.FAILED_RUNTIME), (OperationalState.PROCESSING_FAILED.value, None))

        result = add_host_contract({"status": "PROCESSING_FAILED", "run_id": "run-1"}, phase=RunPhase.FAILED_RUNTIME, input_count=1)
        self.assertEqual(result["adapter_schema_version"], HOST_ADAPTER_SCHEMA_VERSION)
        self.assertEqual(result["adapter_version"], HOST_ADAPTER_VERSION)
        self.assertEqual(result["operational_state"], "PROCESSING_FAILED")
        self.assertIsNone(result["semantic_outcome"])
        self.assertEqual(set(result["progress"]), {"phase", "completed_work_units", "total_work_units", "input_count", "current_work_unit", "next_action"})

    def test_host_invocation_is_versioned_and_rejects_unknown_versions(self) -> None:
        payload = {"schema_version": HOST_ADAPTER_SCHEMA_VERSION, "adapter_version": HOST_ADAPTER_VERSION, "input_refs": []}
        invocation = HostInvocation.from_json(json.dumps(payload))
        self.assertIsNotNone(invocation)
        self.assertEqual(invocation.input_refs, ())
        with self.assertRaises(KSlideError) as raised:
            HostInvocation.from_json(json.dumps({**payload, "adapter_version": "9.9"}))
        self.assertEqual(raised.exception.code, ErrorCode.SCHEMA_INVALID)

    def test_normal_employee_tool_has_no_mode_choice_and_legacy_commands_are_absent(self) -> None:
        parser = build_parser()
        help_output = io.StringIO()
        with self.assertRaises(SystemExit), redirect_stdout(help_output):
            parser.parse_args(["prepare", "--help"])
        self.assertNotIn("smart", help_output.getvalue())
        self.assertNotIn("strict", help_output.getvalue())
        self.assertNotIn("safe", help_output.getvalue())

        root = Path(__file__).resolve().parents[1]
        tool_source = (root / ".opencode" / "tools" / "kslide.ts").read_text(encoding="utf-8")
        prepare_source = tool_source.split("export const prepare", 1)[1].split("export const next", 1)[0]
        self.assertNotIn("mode", prepare_source)
        self.assertIn("host_input_refs", prepare_source)
        self.assertFalse((root / ".opencode" / "commands" / "k-slide-strict.md").exists())
        self.assertFalse((root / ".opencode" / "commands" / "k-slide-safe.md").exists())

    def test_workspace_packet_preserves_order_identity_hashes_and_snapshot_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first.png"
            second = root / "second.png"
            first.write_bytes(PNG + b"-one")
            second.write_bytes(PNG + b"-two")
            refs = (self._reference(first, "first.png"), self._reference(second, "second.png"))
            run = prepare_run(root, host_input_refs=refs, approved_root=root, session_id="host-session")
            self.assertEqual(load_state(run).phase, RunPhase.INPUT_VALIDATED)
            manifest = json.loads((run / "RUN_MANIFEST.json").read_text(encoding="utf-8"))
            inputs = manifest["inputs"]
            self.assertEqual([item["snapshot_id"] for item in inputs], ["source-001", "source-002"])
            self.assertEqual([item["source_name"] for item in inputs], ["first.png", "second.png"])
            self.assertEqual([item["sha256"] for item in inputs], [hashlib.sha256(first.read_bytes()).hexdigest(), hashlib.sha256(second.read_bytes()).hexdigest()])
            self.assertEqual((run / "inputs" / "source-001.png").read_bytes(), first.read_bytes())
            self.assertEqual((run / "inputs" / "source-002.png").read_bytes(), second.read_bytes())
            self.assertNotIn("source_path", json.dumps(manifest))
            self.assertNotIn(str(root), json.dumps(manifest))
            first.write_bytes(PNG + b"-changed-after-snapshot")
            self.assertEqual(sha256_file(run / "inputs" / "source-001.png"), inputs[0]["sha256"])

            inventory = json.loads((run / "00_input_inventory.json").read_text(encoding="utf-8"))
            self.assertEqual(inventory["attachments"], {"supported": True, "reason": "validated local host references"})

    def test_attachment_local_file_uri_is_accepted_but_network_uri_is_not_fetched(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside_directory:
            root = Path(directory)
            attachment = Path(outside_directory) / "upload.bin"
            attachment.write_bytes(PNG)
            accepted = prepare_run(
                root,
                host_input_refs=(self._reference(attachment, "uploaded.png", "attachment"),),
                approved_root=root,
            )
            self.assertEqual(load_state(accepted).phase, RunPhase.INPUT_VALIDATED)
            rejected = prepare_run(
                root,
                host_input_refs=(HostInputReference("attachment", "remote.png", "https://example.invalid/remote.png"),),
                approved_root=root,
            )
            state = load_state(rejected)
            self.assertEqual(state.phase, RunPhase.FAILED_INPUT)
            self.assertEqual(state.error_code, ErrorCode.INPUT_UNSUPPORTED.value)
            self.assertNotIn("example.invalid", (rejected / "RUN_FAILED.md").read_text(encoding="utf-8"))

    def test_workspace_escape_symlink_type_and_unsafe_archive_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside_directory:
            root = Path(directory)
            outside = Path(outside_directory) / "outside.png"
            outside.write_bytes(PNG)
            with self.assertRaises(KSlideError) as raised:
                validate_host_inputs((self._reference(outside, "outside.png"),), approved_root=root)
            self.assertEqual(raised.exception.code, ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT)

            linked = root / "linked.png"
            linked.symlink_to(outside)
            with self.assertRaises(KSlideError) as raised:
                validate_host_inputs((self._reference(linked, "linked.png"),), approved_root=root)
            self.assertEqual(raised.exception.code, ErrorCode.INPUT_NOT_FOUND)

            wrong_type = root / "wrong.jpg"
            wrong_type.write_bytes(PNG)
            with self.assertRaises(KSlideError) as raised:
                validate_host_inputs((self._reference(wrong_type, "wrong.jpg"),), approved_root=root)
            self.assertEqual(raised.exception.code, ErrorCode.INPUT_TYPE_MISMATCH)

            unsafe = root / "unsafe.pptx"
            with zipfile.ZipFile(unsafe, "w") as archive:
                archive.writestr("[Content_Types].xml", "<Types/>")
                archive.writestr("ppt/presentation.xml", "<presentation/>")
                archive.writestr("../escape.txt", "unsafe")
            with self.assertRaises(KSlideError) as raised:
                validate_host_inputs((self._reference(unsafe, "unsafe.pptx"),), approved_root=root)
            self.assertEqual(raised.exception.code, ErrorCode.INPUT_ARCHIVE_UNSAFE)

    def test_failure_and_semantic_review_remain_distinct_in_next_and_cli_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            failed_run = root / ".k-slide-runs" / "k-slide-failed"
            failed_run.mkdir(parents=True)
            save_state(failed_run, RunState("k-slide-failed", "standard", RunPhase.FAILED_SCHEMA, error_code="KSLIDE_SCHEMA_INVALID", error_message="Schema failed."))
            failed = _next(root, failed_run.name, None)
            self.assertEqual(failed["status"], "PROCESSING_FAILED")
            self.assertEqual(failed["operational_state"], "PROCESSING_FAILED")
            self.assertIsNone(failed["semantic_outcome"])

            review_run = root / ".k-slide-runs" / "k-slide-review"
            review_run.mkdir(parents=True)
            save_state(review_run, RunState("k-slide-review", "standard", RunPhase.NEEDS_REVIEW))
            (review_run / "WORK_QUEUE.json").write_text(json.dumps({"run_id": review_run.name, "work_units": [], "queue_revision": ""}), encoding="utf-8")
            review = _next(root, review_run.name, None)
            self.assertEqual(review["status"], "NEEDS_REVIEW")
            self.assertEqual(review["operational_state"], "COMPLETED")
            self.assertEqual(review["semantic_outcome"], "NEEDS_REVIEW")

            output = io.StringIO()
            with redirect_stdout(output):
                code = main(["next", "--root", str(root), "--run", failed_run.name, "--json"])
            self.assertNotEqual(code, 0)
            payload = json.loads(output.getvalue())
            self.assertEqual(payload["operational_state"], "PROCESSING_FAILED")
            self.assertIsNone(payload["semantic_outcome"])

    def test_status_and_support_metadata_do_not_leak_attachment_path_or_source_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside_directory:
            root = Path(directory)
            attachment = Path(outside_directory) / "private.png"
            attachment.write_bytes(PNG + b"SECRET-SOURCE-CONTENT")
            run = prepare_run(root, host_input_refs=(self._reference(attachment, "private.png", "attachment"),), approved_root=root)
            status_output = io.StringIO()
            with redirect_stdout(status_output):
                self.assertEqual(main(["status", "--root", str(root), "--run", run.name, "--json"]), 0)
            status = status_output.getvalue()
            self.assertNotIn(str(attachment), status)
            self.assertNotIn("SECRET-SOURCE-CONTENT", status)
            output = root / "support.zip"
            build_support_bundle(root, output)
            with zipfile.ZipFile(output) as archive:
                support = archive.read("support-metadata.json").decode("utf-8")
            self.assertNotIn(str(attachment), support)
            self.assertNotIn("SECRET-SOURCE-CONTENT", support)

    def test_host_validation_failure_does_not_persist_local_source_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside_directory:
            root = Path(directory)
            attachment = Path(outside_directory) / "not-an-image.png"
            attachment.write_bytes(b"not-a-png")
            run = prepare_run(
                root,
                host_input_refs=(self._reference(attachment, "not-an-image.png", "attachment"),),
                approved_root=root,
            )
            self.assertEqual(load_state(run).phase, RunPhase.FAILED_INPUT)
            for name in ("RUN_STATE.json", "00_input_inventory.json", "RUN_FAILED.md"):
                self.assertNotIn(str(attachment), (run / name).read_text(encoding="utf-8"))
            output = root / "support.zip"
            build_support_bundle(root, output)
            with zipfile.ZipFile(output) as archive:
                support = archive.read("support-metadata.json").decode("utf-8")
            self.assertNotIn(str(attachment), support)

    def test_opencode_native_bridge_uses_supported_parts_and_is_installed(self) -> None:
        root = Path(__file__).resolve().parents[1]
        plugin = (root / ".opencode" / "plugin" / "k-slide-host.ts").read_text(encoding="utf-8")
        self.assertIn('"chat.message"', plugin)
        self.assertIn('"tool.execute.before"', plugin)
        self.assertIn("source.path", plugin)
        self.assertIn("part.url", plugin)
        self.assertNotIn("fetch(", plugin)
        self.assertNotIn("readFile", plugin)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "host"
            install(root, target)
            self.assertTrue((target / ".opencode" / "plugin" / "k-slide-host.ts").is_file())
            self.assertTrue(all(passed for _, passed in verify_install(target)))


if __name__ == "__main__":
    unittest.main()
