from __future__ import annotations

import tempfile
import unittest
import json
from pathlib import Path

from k_slide.errors import ErrorCode, KSlideError
from k_slide.evidence_ir import EvidenceIR, EvidenceRegion, save_evidence
from k_slide.ir import SlideIR
from k_slide.queue import WorkQueue, WorkUnit, WorkUnitStatus, save_queue
from k_slide.rendering.reports import _semantic_text, render_run
from k_slide.semantics import ProvenanceState
from k_slide.storage import StorageArtifact, storage_path
from k_slide.translation import merge_evidence_patch, parse_translation_patch
from k_slide.terminology import Termbase
from k_slide.verify import VerificationResult, _validate_canonical_provenance, _validate_slide
from k_slide.io import atomic_write_json


class KSA22ProvenanceTests(unittest.TestCase):
    def _evidence(self) -> EvidenceIR:
        return EvidenceIR(
            "doc",
            "unit",
            {},
            regions=(
                EvidenceRegion("unit-r1", selected_literal_candidate="A"),
                EvidenceRegion("unit-r2", selected_literal_candidate="B"),
                EvidenceRegion("unit-r3", selected_literal_candidate="C"),
            ),
            required_source_ids=("unit-r1", "unit-r2", "unit-r3"),
        ).with_revision()

    def _patch(self, evidence: EvidenceIR) -> dict[str, object]:
        return {
            "schema_version": "1.0",
            "work_unit_id": evidence.work_unit_id,
            "evidence_revision": evidence.evidence_revision,
            "regions": [
                {"region_id": "unit-r1", "english": "A", "term_ids": [], "unresolved": False, "provenance": "source_fact", "evidence_ids": ["unit-r1"]},
                {"region_id": "unit-r2", "english": "B", "term_ids": [], "unresolved": False, "provenance": "supported_interpretation", "evidence_ids": ["unit-r2"]},
                {"region_id": "unit-r3", "english": "C", "term_ids": [], "unresolved": True, "unresolved_reason": "Unreadable", "provenance": "unresolved", "evidence_ids": ["unit-r3"]},
            ],
            "tables": [],
            "visual_interpretations": [],
            "executive_claims": [
                {"claim_id": "claim-1", "kind": "takeaway", "text": "Decision context", "evidence_ids": ["unit-r2"], "uncertainty": "low", "provenance": "supported_interpretation"},
                {"claim_id": "claim-2", "kind": "risk", "text": "Unknown", "evidence_ids": ["unit-r3"], "uncertainty": "high", "provenance": "unresolved", "unresolved_reason": "The source is unreadable."},
            ],
        }

    def test_closed_vocabulary_and_round_trip(self) -> None:
        evidence = self._evidence()
        patch = parse_translation_patch(self._patch(evidence))
        patch.validate_against(evidence)
        round_trip = parse_translation_patch(patch.as_dict())
        self.assertEqual(round_trip.as_dict(), patch.as_dict())
        self.assertEqual(tuple(item.value for item in ProvenanceState), ("source_fact", "supported_interpretation", "unresolved"))
        invalid = self._patch(evidence)
        invalid["regions"] = [dict(invalid["regions"][0], provenance="guess")]  # type: ignore[index]
        with self.assertRaises(KSlideError) as raised:
            parse_translation_patch(invalid)
        self.assertEqual(raised.exception.code, ErrorCode.SCHEMA_INVALID)

    def test_schema_and_typed_tool_contract_expose_only_closed_provenance(self) -> None:
        evidence = self._evidence()
        root = Path(__file__).resolve().parents[1]
        patch_schema = json.loads((root / "schemas" / "translation-patch.schema.json").read_text(encoding="utf-8"))
        slide_schema = json.loads((root / "schemas" / "slide-ir.schema.json").read_text(encoding="utf-8"))
        expected = ["source_fact", "supported_interpretation", "unresolved"]
        self.assertEqual(patch_schema["$defs"]["provenance"]["enum"], expected)
        self.assertEqual(slide_schema["$defs"]["provenance"]["enum"], expected)
        tool = (root / ".opencode" / "tools" / "kslide.ts").read_text(encoding="utf-8")
        for state in expected:
            self.assertIn(state, tool)
        source_owned = self._patch(evidence)
        source_owned["regions"] = [dict(source_owned["regions"][0], provenance_evidence_ids=["unit-r1"])]  # type: ignore[index]
        with self.assertRaises(KSlideError) as raised:
            parse_translation_patch(source_owned)
        self.assertEqual(raised.exception.code, ErrorCode.SCHEMA_INVALID)

    def test_each_state_survives_engine_merge_and_unresolved_is_explicit(self) -> None:
        evidence = self._evidence()
        slide = merge_evidence_patch(evidence, parse_translation_patch(self._patch(evidence)))
        self.assertEqual([region.provenance for region in slide.regions], ["source_fact", "supported_interpretation", "unresolved"])
        self.assertEqual(slide.executive_semantics["executive_claims"][0]["provenance"], "supported_interpretation")
        self.assertEqual(slide.executive_semantics["executive_claims"][1]["provenance"], "unresolved")
        self.assertTrue(all(item["provenance"] == "unresolved" for item in slide.unresolved))

    def test_missing_foreign_stale_and_inconsistent_evidence_are_rejected(self) -> None:
        evidence = self._evidence()
        missing = self._patch(evidence)
        missing["regions"] = [dict(missing["regions"][0], evidence_ids=[])]  # type: ignore[index]
        with self.assertRaises(KSlideError) as raised:
            parse_translation_patch(missing).validate_against(evidence)
        self.assertEqual(raised.exception.code, ErrorCode.CLAIM_UNSUPPORTED)

        foreign = self._patch(evidence)
        foreign["regions"] = [dict(foreign["regions"][0], evidence_ids=["foreign-r1"])]  # type: ignore[index]
        with self.assertRaises(KSlideError) as raised:
            parse_translation_patch(foreign).validate_against(evidence)
        self.assertEqual(raised.exception.code, ErrorCode.UNKNOWN_SOURCE_ELEMENT)

        stale = self._patch(evidence)
        stale["evidence_revision"] = "b" * 64
        with self.assertRaises(KSlideError) as raised:
            parse_translation_patch(stale).validate_against(evidence)
        self.assertEqual(raised.exception.code, ErrorCode.STALE_EVIDENCE)

        inconsistent = self._patch(evidence)
        inconsistent["regions"] = [dict(inconsistent["regions"][0], provenance="unresolved", unresolved=False, unresolved_reason="reason")]  # type: ignore[index]
        with self.assertRaises(KSlideError) as raised:
            parse_translation_patch(inconsistent).validate_against(evidence)
        self.assertEqual(raised.exception.code, ErrorCode.SCHEMA_INVALID)

    def test_canonical_verifier_rejects_invalid_provenance_and_foreign_ids(self) -> None:
        evidence = self._evidence()
        result = VerificationResult(status="PASS", run_id="run")
        invalid = SlideIR.from_dict({
            "schema_version": "1.0",
            "slide_id": "unit",
            "evidence_revision": evidence.evidence_revision,
            "regions": [{"region_id": "unit-r1", "translation": "A", "provenance": "not-a-state", "provenance_evidence_ids": ["unit-r1"]}],
            "unresolved": [],
        })
        _validate_canonical_provenance(result, invalid, evidence, "unit")
        self.assertIn("KSLIDE_PROVENANCE_INVALID", {issue.code for issue in result.issues})

        result = VerificationResult(status="PASS", run_id="run")
        foreign = SlideIR.from_dict({
            "schema_version": "1.0",
            "slide_id": "unit",
            "evidence_revision": evidence.evidence_revision,
            "regions": [{"region_id": "unit-r1", "translation": "A", "provenance": "supported_interpretation", "provenance_evidence_ids": ["foreign"]}],
            "unresolved": [],
        })
        _validate_canonical_provenance(result, foreign, evidence, "unit")
        self.assertIn("KSLIDE_PROVENANCE_FOREIGN_EVIDENCE", {issue.code for issue in result.issues})

        result = VerificationResult(status="PASS", run_id="run")
        missing = SlideIR.from_dict({
            "schema_version": "1.0",
            "slide_id": "unit",
            "evidence_revision": evidence.evidence_revision,
            "regions": [{"region_id": "unit-r1", "translation": "A", "provenance": "source_fact", "provenance_evidence_ids": []}],
            "unresolved": [],
        })
        _validate_canonical_provenance(result, missing, evidence, "unit")
        self.assertIn("KSLIDE_PROVENANCE_EVIDENCE_REQUIRED", {issue.code for issue in result.issues})

    def test_legacy_slide_ir_maps_ambiguity_conservatively(self) -> None:
        legacy = SlideIR.from_dict({
            "schema_version": "1.0",
            "slide_id": "unit",
            "regions": [{"region_id": "unit-r1", "translation": "Legacy text"}],
            "unresolved": [],
            "executive_semantics": {"executive_claims": [{"claim_id": "claim-1", "kind": "takeaway", "text": "Legacy claim", "evidence_ids": ["unit-r1"], "uncertainty": "low"}]},
        })
        self.assertEqual(legacy.regions[0].provenance, "supported_interpretation")
        self.assertNotEqual(legacy.regions[0].provenance, "source_fact")
        self.assertEqual(legacy.executive_semantics["executive_claims"][0]["provenance"], "supported_interpretation")

    def test_canonical_verifier_rejects_stale_evidence_revision(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory) / "run"
            run.mkdir()
            evidence = self._evidence()
            save_evidence(run, evidence)
            slide = merge_evidence_patch(evidence, parse_translation_patch(self._patch(evidence)))
            value = slide.as_dict()
            value["evidence_revision"] = "b" * 64
            atomic_write_json(storage_path(run, StorageArtifact.CANONICAL_IR, "ir/unit.json", create_parent=True), value)
            result = VerificationResult(status="PASS", run_id="run")
            _validate_slide(run, "unit", result, termbase=Termbase("1.0", ()))
            self.assertIn("KSLIDE_STALE_EVIDENCE", {issue.code for issue in result.issues})

    def test_report_surfaces_label_all_states_and_never_prints_unresolved_text_as_fact(self) -> None:
        self.assertEqual(_semantic_text("literal", "source_fact"), "[SOURCE FACT] literal")
        self.assertEqual(_semantic_text("derived", "supported_interpretation"), "[SUPPORTED INTERPRETATION] derived")
        self.assertEqual(_semantic_text("do not render", "unresolved", "Needs review"), "[UNRESOLVED: Needs review]")

        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory) / "run"
            run.mkdir()
            atomic_write_json(storage_path(run, StorageArtifact.RUN_MANIFEST, "RUN_MANIFEST.json", create_parent=True), {"inputs": []})
            evidence = self._evidence()
            save_evidence(run, evidence)
            queue = WorkQueue(run_id="run", work_units=[WorkUnit("unit", "doc", "source-001", 0, status=WorkUnitStatus.TRANSLATED)])
            save_queue(run, queue)
            slide = merge_evidence_patch(evidence, parse_translation_patch(self._patch(evidence)))
            atomic_write_json(storage_path(run, StorageArtifact.CANONICAL_IR, "ir/unit.json", create_parent=True), slide.as_dict())
            render_run(run)
            report = storage_path(run, StorageArtifact.REPORT, "05_final_report.md").read_text(encoding="utf-8")
            brief = storage_path(run, StorageArtifact.REPORT, "05_executive_brief.md").read_text(encoding="utf-8")
            unresolved = storage_path(run, StorageArtifact.REPORT, "07_unresolved_items.md").read_text(encoding="utf-8")
            self.assertIn("SOURCE FACT", report)
            self.assertIn("SUPPORTED INTERPRETATION", report)
            self.assertIn("UNRESOLVED", unresolved)
            self.assertIn("SUPPORTED INTERPRETATION", brief)
            self.assertNotIn("- C", report)


if __name__ == "__main__":
    unittest.main()
