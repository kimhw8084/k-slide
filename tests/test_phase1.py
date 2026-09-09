from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from k_slide.errors import ErrorCode, KSlideError
from k_slide.ingest import prepare_run
from k_slide.installer import install, verify_install
from k_slide.doctor import diagnose
from k_slide.evidence_ir import EvidenceIR, EvidenceRegion, save_evidence
from k_slide.queue import WorkUnitStatus, load_queue, save_queue
from k_slide.runtime import discover_runtime
from k_slide.session import resolve_run
from k_slide.state import RunPhase, load_state, save_state
from k_slide.verify import finalize_run, verify_run
from k_slide.cli import _next, _submit


PNG_HEADER = b"\x89PNG\r\n\x1a\nminimal-test-fixture"


class Phase1Tests(unittest.TestCase):
    def test_input_extension_and_magic_must_agree(self) -> None:
        from k_slide.security import validate_input

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "slide.png"
            path.write_bytes(b"not-a-png")
            with self.assertRaises(KSlideError) as raised:
                validate_input(path)
            self.assertEqual(raised.exception.code, ErrorCode.INPUT_TYPE_MISMATCH)

    def test_pptx_external_relationship_is_rejected(self) -> None:
        from k_slide.security import validate_input

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "remote.pptx"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("[Content_Types].xml", "<Types/>")
                archive.writestr("ppt/presentation.xml", "<presentation/>")
                archive.writestr("ppt/_rels/presentation.xml.rels", '<Relationship TargetMode="External" Target="https://example.com"/>')
            with self.assertRaises(KSlideError) as raised:
                validate_input(path)
            self.assertEqual(raised.exception.code, ErrorCode.INPUT_ARCHIVE_UNSAFE)

    def test_prepare_creates_immutable_hashed_snapshot_and_session_binding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "slide.png"
            source.write_bytes(PNG_HEADER)
            run_dir = prepare_run(root, explicit_paths=[str(source)], session_id="session-1")
            state = load_state(run_dir)
            self.assertEqual(state.phase, RunPhase.INPUT_VALIDATED)
            snapshot = run_dir / "inputs" / "source-001.png"
            self.assertEqual(snapshot.read_bytes(), PNG_HEADER)
            manifest = json.loads((run_dir / "inputs" / "checksums.json").read_text())
            self.assertEqual(manifest["input_count"], 1)
            self.assertEqual(manifest["inputs"][0]["sha256"], __import__("hashlib").sha256(PNG_HEADER).hexdigest())
            self.assertEqual(resolve_run(root / ".k-slide-runs", session_id="session-1"), run_dir)
            source.write_bytes(PNG_HEADER + b"changed-after-snapshot")
            self.assertEqual(snapshot.read_bytes(), PNG_HEADER)

    def test_no_input_is_a_failed_run_not_a_fake_valid_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_dir = prepare_run(root)
            state = load_state(run_dir)
            self.assertEqual(state.phase, RunPhase.FAILED_INPUT)
            self.assertTrue((run_dir / "RUN_FAILED.md").is_file())
            self.assertFalse((run_dir / "RUN_COMPLETE.md").exists())

    def test_state_machine_rejects_skipping_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "slide.png"
            source.write_bytes(PNG_HEADER)
            run_dir = prepare_run(root, explicit_paths=[str(source)])
            state = load_state(run_dir)
            with self.assertRaises(KSlideError) as raised:
                state.transition(RunPhase.TRANSLATED)
            self.assertEqual(raised.exception.code, ErrorCode.INVALID_TRANSITION)

    def test_installer_does_not_overwrite_host_agents_and_is_idempotent(self) -> None:
        source_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "host"
            target.mkdir()
            host_agents = target / "AGENTS.md"
            host_agents.write_text("host-owned instructions\n")
            manifest = install(source_root, target)
            self.assertTrue(manifest.is_file())
            self.assertEqual(host_agents.read_text(), "host-owned instructions\n")
            self.assertTrue((target / ".opencode" / "tools" / "kslide.ts").is_file())
            self.assertTrue((target / ".k-slide-engine" / "src" / "k_slide" / "cli.py").is_file())
            self.assertTrue(all(passed for _, passed in verify_install(target)))
            install(source_root, target)
            self.assertEqual(host_agents.read_text(), "host-owned instructions\n")

    def test_installer_refuses_unowned_collision(self) -> None:
        source_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "host"
            collision = target / ".opencode" / "commands" / "k-slide.md"
            collision.parent.mkdir(parents=True)
            collision.write_text("host-owned command\n")
            with self.assertRaises(KSlideError) as raised:
                install(source_root, target)
            self.assertEqual(raised.exception.code, ErrorCode.INSTALL_COLLISION)
            self.assertEqual(collision.read_text(), "host-owned command\n")

    def test_completion_is_owned_by_verifier_and_finalizer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "slide.png"
            source.write_bytes(PNG_HEADER)
            run_dir = prepare_run(root, explicit_paths=[str(source)])
            blocked = verify_run(run_dir)
            self.assertFalse(blocked.passed)
            self.assertFalse((run_dir / "RUN_COMPLETE.md").exists())

            queue = load_queue(run_dir)
            work_unit_id = queue.work_units[0].work_unit_id
            region_id = f"{work_unit_id}-r001"
            evidence = EvidenceIR(
                "doc-001",
                work_unit_id,
                {"input_id": "source-001", "width_px": 100, "height_px": 100},
                (EvidenceRegion(region_id, (0, 0, 100, 100), (0, 0, 1, 1), selected_literal_candidate="원문", literal_confidence=1.0),),
                required_source_ids=(region_id,),
            ).with_revision()
            save_evidence(run_dir, evidence)
            queue.work_units[0].status = WorkUnitStatus.READY
            queue.work_units[0].evidence_revision = evidence.evidence_revision
            save_queue(run_dir, queue)
            state = load_state(run_dir)
            state.transition(RunPhase.NORMALIZED)
            state.transition(RunPhase.EXTRACTED)
            save_state(run_dir, state)
            payload = {
                "schema_version": "1.0",
                "work_unit_id": work_unit_id,
                "evidence_revision": evidence.evidence_revision,
                "regions": [{"region_id": region_id, "english": "A faithful reconstruction."}],
                "tables": [],
            }
            self.assertEqual(_next(root, run_dir.name, None)["status"], "READY")
            accepted = _submit(root, run_dir.name, json.dumps(payload), None)
            self.assertEqual(accepted["status"], "ACCEPTED")
            (run_dir / "05_executive_brief.md").write_text("# Executive brief\n")
            (run_dir / "05_final_report.md").write_text("# Source-faithful reconstruction\n")
            (run_dir / "07_unresolved_items.md").write_text("No unresolved items.\n")
            result = verify_run(run_dir)
            self.assertTrue(result.passed)
            self.assertEqual(load_state(run_dir).phase, RunPhase.VERIFIED)
            finalize_run(run_dir)
            self.assertTrue((run_dir / "RUN_COMPLETE.md").is_file())
            self.assertEqual(load_state(run_dir).phase, RunPhase.COMPLETE)

    def test_explicit_directory_discovers_supported_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = root / "slides"
            inputs.mkdir()
            (inputs / "02.png").write_bytes(PNG_HEADER)
            (inputs / "01.jpg").write_bytes(b"\xff\xd8\xffminimal")
            (inputs / "ignore.txt").write_text("not a slide")
            run_dir = prepare_run(root, explicit_paths=[str(inputs)])
            state = load_state(run_dir)
            self.assertEqual(state.phase, RunPhase.INPUT_VALIDATED)
            self.assertEqual(state.input_count, 2)

    def test_symlink_input_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "real.png"
            source.write_bytes(PNG_HEADER)
            alias = root / "alias.png"
            alias.symlink_to(source)
            run_dir = prepare_run(root, explicit_paths=[str(alias)])
            self.assertEqual(load_state(run_dir).phase, RunPhase.FAILED_INPUT)
            self.assertIn("symbolic link", (run_dir / "RUN_FAILED.md").read_text())

    def test_next_fails_closed_before_normalization_exists(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "slide.png"
            source.write_bytes(PNG_HEADER)
            run_dir = prepare_run(root, explicit_paths=[str(source)], session_id="session-1")
            result = _next(root, run_dir.name, "session-1")
            self.assertEqual(result["status"], "NOT_READY")
            self.assertEqual(load_state(run_dir).phase, RunPhase.INPUT_VALIDATED)

    def test_global_install_uses_open_code_config_root(self) -> None:
        source_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "opencode"
            manifest = install(source_root, target, scope="global")
            self.assertTrue(manifest.is_file())
            self.assertTrue((target / "tools" / "kslide.ts").is_file())
            self.assertTrue((target / "commands" / "k-slide.md").is_file())
            self.assertFalse((target / ".opencode" / "tools" / "kslide.ts").exists())
            self.assertTrue(all(passed for _, passed in verify_install(target, scope="global")))

    def test_doctor_recognizes_installed_project_engine(self) -> None:
        source_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "host"
            install(source_root, target)
            report = diagnose(target)
            source_check = next(item for item in report["checks"] if item["label"] == "K-Slide source tree")
            self.assertEqual(source_check["status"], "PASS")

    def test_runtime_discovery_records_model_identity_without_certifying_unknown_model(self) -> None:
        metadata = discover_runtime()
        self.assertTrue(metadata.kslide_version)
        self.assertIn(metadata.model_compatibility, {"production_candidate", "different_model_warning", "non_instruction_tuned_warning", "unknown_model_warning"})


if __name__ == "__main__":
    unittest.main()
