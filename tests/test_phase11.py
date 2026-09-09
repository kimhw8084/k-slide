from __future__ import annotations

import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from k_slide.cli import _next, _submit
from k_slide.errors import ErrorCode, KSlideError
from k_slide.evidence_ir import EvidenceIR, EvidenceRegion, save_evidence
from k_slide.ingest import prepare_run
from k_slide.queue import WorkUnitStatus, load_queue, save_queue
from k_slide.state import RunPhase, load_state, save_state
from k_slide.translation import parse_translation_patch
from k_slide.verify import finalize_run, verify_run


PNG_HEADER = b"\x89PNG\r\n\x1a\nphase-1.1-fixture"


class Phase11Tests(unittest.TestCase):
    def _prepared(self, root: Path, count: int = 1) -> Path:
        for index in range(1, count + 1):
            (root / f"slide-{index:03d}.png").write_bytes(PNG_HEADER + bytes([index]))
        run = prepare_run(root, explicit_paths=[str(root / f"slide-{index:03d}.png") for index in range(1, count + 1)])
        queue = load_queue(run)
        for index, unit in enumerate(queue.work_units, start=1):
            evidence = EvidenceIR(
                f"doc-{index:03d}",
                unit.work_unit_id,
                {"input_id": unit.source_input_id, "width_px": 100, "height_px": 100},
                (
                    EvidenceRegion(f"{unit.work_unit_id}-r001", (0, 0, 100, 100), (0, 0, 1, 1), selected_literal_candidate="검토 필요", literal_confidence=1.0),
                ),
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

    def _payload(self, run: Path, work_unit_id: str, *, evidence_revision: str | None = None, repair_revision: str | None = None) -> dict[str, object]:
        evidence = json.loads((run / "evidence" / f"{work_unit_id}.json").read_text())
        return {
            "schema_version": "1.0",
            "work_unit_id": work_unit_id,
            "evidence_revision": evidence_revision or evidence["evidence_revision"],
            "regions": [{"region_id": f"{work_unit_id}-r001", "english": "Requires review before deployment.", "commitment_status": "under_review", "speech_act": "plan", "term_ids": [], "numeric_fact_ids": [], "unresolved": False}],
            "tables": [],
            "visual_interpretations": [],
            "executive_semantics": {"evidence_ids": [f"{work_unit_id}-r001"]},
            **({"repair_revision": repair_revision} if repair_revision else {}),
        }

    def test_model_patch_cannot_author_source_fields(self) -> None:
        with self.assertRaises(KSlideError) as raised:
            parse_translation_patch({"schema_version": "1.0", "work_unit_id": "slide-001", "evidence_revision": "a" * 64, "regions": [{"region_id": "r001", "english": "x", "bbox": [0, 0, 1, 1]}], "tables": [], "visual_interpretations": [], "executive_semantics": {}})
        self.assertEqual(raised.exception.code, ErrorCode.SCHEMA_INVALID)

    def test_stale_and_incomplete_patches_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = self._prepared(root)
            result = _next(root, run.name, None)
            self.assertEqual(result["status"], "READY")
            stale = self._payload(run, "slide-001", evidence_revision="b" * 64)
            with self.assertRaises(KSlideError) as raised:
                _submit(root, run.name, json.dumps(stale), None)
            self.assertEqual(raised.exception.code, ErrorCode.STALE_EVIDENCE)

    def test_three_work_units_progress_and_resume_sequentially(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = self._prepared(root, count=3)
            for index in range(1, 4):
                next_value = _next(root, run.name, None)
                self.assertEqual(next_value["status"], "READY")
                work_unit_id = str(next_value["work_unit_id"])
                _submit(root, run.name, json.dumps(self._payload(run, work_unit_id)), None)
                if index == 2:
                    self.assertEqual(load_state(run).phase, RunPhase.TRANSLATING)
            self.assertEqual(_next(root, run.name, None)["status"], "ALL_TRANSLATED")
            self.assertEqual([unit.status for unit in load_queue(run).work_units], [WorkUnitStatus.TRANSLATED] * 3)

    def test_concurrent_submit_has_one_winner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = self._prepared(root)
            next_value = _next(root, run.name, None)
            payload = json.dumps(self._payload(run, str(next_value["work_unit_id"])))

            def submit() -> str:
                try:
                    return str(_submit(root, run.name, payload, None)["status"])
                except KSlideError as exc:
                    return exc.code.value

            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(lambda _: submit(), range(2)))
            self.assertEqual(results.count("ACCEPTED"), 1)
            self.assertEqual(sum(value == ErrorCode.WORK_UNIT_ALREADY_COMPLETE.value for value in results), 1)

    def test_finalize_rechecks_changed_canonical_ir(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = self._prepared(root)
            next_value = _next(root, run.name, None)
            _submit(root, run.name, json.dumps(self._payload(run, str(next_value["work_unit_id"]))), None)
            for name, content in {"05_executive_brief.md": "# brief\n", "05_final_report.md": "# report\n", "07_unresolved_items.md": "No unresolved items.\n"}.items():
                (run / name).write_text(content)
            self.assertTrue(verify_run(run).passed)
            finalize_run(run)
            self.assertTrue((run / "RUN_COMPLETE.md").exists())
            ir_path = run / "ir" / "slide-001.json"
            ir_path.write_text(ir_path.read_text().replace("Requires review", "Fabricated change"))
            with self.assertRaises(KSlideError) as raised:
                finalize_run(run)
            self.assertEqual(raised.exception.code, ErrorCode.COMPLETION_BLOCKED)
            self.assertFalse((run / "RUN_COMPLETE.md").exists())

    def test_needs_review_is_resumable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = self._prepared(root)
            state = load_state(run)
            state.transition(RunPhase.TRANSLATING)
            state.transition(RunPhase.NEEDS_REVIEW)
            save_state(run, state)
            self.assertFalse(load_state(run).terminal)
            state = load_state(run)
            state.transition(RunPhase.REPAIRING)
            self.assertEqual(state.phase, RunPhase.REPAIRING)


if __name__ == "__main__":
    unittest.main()
