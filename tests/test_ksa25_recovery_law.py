from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from k_slide.cli import _conflict_assess, _evidence, _next, _submit
from k_slide.conflicts import assess_conflicts
from k_slide.environment import RunEnvironmentIdentity
from k_slide.errors import ErrorCode, KSlideError
from k_slide.evidence_ir import EvidenceIR, EvidenceRegion, EvidenceTable, EvidenceTableCell, save_evidence
from k_slide.extraction import extract_run
from k_slide.fusion import fuse_literal_evidence
from k_slide.ingest import prepare_run
from k_slide.model import build_work_packet
from k_slide.normalization import normalize_run
from k_slide.ocr.base import OCRRegion, OCRResult
from k_slide.queue import WorkUnitStatus, load_queue, save_queue
from k_slide.semantics import ProvenanceState
from k_slide.storage import StorageArtifact, storage_path
from k_slide.translation import merge_evidence_patch, parse_translation_patch
from k_slide.verify import finalize_run, verify_run
from tests.reference_fixtures import reference_environment


_PROJECT_ROOT = Path(__file__).resolve().parents[1]


class _FixtureOCR:
    name = "fixture-ocr"
    version = "1"

    def __init__(self, *, page_regions: tuple[OCRRegion, ...], crop_regions: tuple[OCRRegion, ...] = (), crop_error: Exception | None = None) -> None:
        self.page_regions = page_regions
        self.crop_regions = crop_regions
        self.crop_error = crop_error
        self.calls = 0

    def extract(self, image: Path, *, language_hints: tuple[str, ...] = ("ko", "en")) -> OCRResult:
        self.calls += 1
        if "regions" in image.parts:
            if self.crop_error:
                raise self.crop_error
            return OCRResult(self.name, self.version, regions=self.crop_regions)
        return OCRResult(self.name, self.version, regions=self.page_regions)


class KSA25RecoveryLawTests(unittest.TestCase):
    def _source_run(self, provider: _FixtureOCR) -> tuple[tempfile.TemporaryDirectory[str], Path, Path, RunEnvironmentIdentity]:
        holder = tempfile.TemporaryDirectory()
        root = Path(holder.name)
        shutil.copytree(_PROJECT_ROOT / "termbase", root / "termbase")
        source = root / "source.png"
        from PIL import Image

        Image.new("RGB", (120, 120), "white").save(source)
        environment = reference_environment("ksa25")
        run = prepare_run(root, explicit_paths=[str(source)], environment_identity=environment)
        normalize_run(run, environment_identity=environment)
        extract_run(run, ocr_provider=provider, environment_identity=environment)
        return holder, root, run, environment

    def _patch(self, evidence: EvidenceIR, *, english: str, unresolved: bool, provenance: str, reason: str | None = None) -> dict[str, object]:
        region = next(item for item in evidence.regions if item.required_for_translation)
        item: dict[str, object] = {
            "region_id": region.region_id,
            "english": english,
            "term_ids": [],
            "unresolved": unresolved,
            "provenance": provenance,
            "evidence_ids": [region.region_id],
        }
        if reason is not None:
            item["unresolved_reason"] = reason
        return {
            "schema_version": "1.0",
            "work_unit_id": evidence.work_unit_id,
            "evidence_revision": evidence.evidence_revision,
            "regions": [item],
            "tables": [],
            "visual_interpretations": [],
            "executive_claims": [],
        }

    def _simple_evidence(self, *, state: str, selected: str | None, candidates: tuple[dict[str, object], ...] = ()) -> EvidenceIR:
        region = EvidenceRegion(
            "unit-r1",
            selected_literal_candidate=selected,
            native_text_candidates=({"text": "원문 A", "confidence": 1.0},) if state == "DISAGREEMENT" else (),
            ocr_candidates=candidates or (({"text": "부분", "confidence": 0.35},) if state == "LOW_CONFIDENCE" else (({"text": "원문 B", "confidence": 0.91},) if state == "DISAGREEMENT" else ())),
            evidence_state=state,
        )
        return EvidenceIR("doc-1", "unit", {}, regions=(region,), required_source_ids=(region.region_id,)).with_revision()

    def _semantic_evidence(self, *, document_id: str = "doc-1", work_unit_id: str = "unit", grounded_table: bool = False) -> EvidenceIR:
        risk_id = f"{work_unit_id}-risk"
        trusted_id = f"{work_unit_id}-trusted"
        table_id = f"{work_unit_id}-table"
        trusted_cell_id = f"{work_unit_id}-cell-trusted"
        risk_cell_id = f"{work_unit_id}-cell-risk"
        fact_id = f"{work_unit_id}-fact"
        risk = EvidenceRegion(risk_id, selected_literal_candidate=None, evidence_state="NO_LITERAL_EVIDENCE")
        trusted = EvidenceRegion(trusted_id, selected_literal_candidate="Launch date 2026-04-01")
        trusted_cell = EvidenceTableCell(
            trusted_cell_id, 0, 0, source_text="2026-04-01", cell_state="nonblank", numeric_fact_ids=(fact_id,),
        )
        cells = [trusted_cell]
        if not grounded_table:
            cells.append(EvidenceTableCell(
                risk_cell_id, 1, 0, source_text=None, cell_state="nonblank", evidence_region_ids=(risk_id,),
            ))
        table = EvidenceTable(table_id, row_count=len(cells), column_count=1, cells=tuple(cells))
        numeric = ({
            "fact_id": fact_id,
            "source_region_id": None,
            "source_object_id": trusted_cell_id,
            "source_cell_id": trusted_cell_id,
            "source_string": "2026-04-01",
            "raw_value": 2026,
            "canonical_value": 2026,
            "scale_factor": 1,
            "source_unit": None,
            "semantic_quantity": "date",
            "currency": None,
            "direction": None,
        },)
        visuals = (
            {"element_id": f"{work_unit_id}-context", "kind": "context_image", "path": "context.png", "sha256": "a" * 64, "bbox_px": [0, 0, 120, 120], "required": True},
            {
                "element_id": f"{work_unit_id}-chart", "kind": "chart", "bbox_px": [0, 0, 80, 40], "required": True,
                "chart": {"chart_type": "line", "categories": ["Q1", "Q2"], "series": [{"series_index": 0, "name": "Revenue", "points": [{"point_index": 0, "value": 1, "is_blank": False}, {"point_index": 1, "value": 2, "is_blank": False}]}]},
            },
            {"element_id": f"{work_unit_id}-node-a", "kind": "shape", "bbox_px": [0, 0, 10, 10], "required": True},
            {"element_id": f"{work_unit_id}-node-b", "kind": "shape", "bbox_px": [30, 0, 40, 10], "required": True},
            {
                "element_id": f"{work_unit_id}-edge", "kind": "connector", "bbox_px": [10, 5, 30, 5], "required": True,
                "connector": {"from_element_id": f"{work_unit_id}-node-a", "to_element_id": f"{work_unit_id}-node-b", "direction_evidence": "start_to_end"},
            },
        )
        required = [risk_id, trusted_id, table_id, trusted_cell_id, fact_id, *(str(item["element_id"]) for item in visuals)]
        if not grounded_table:
            required.append(risk_cell_id)
        return EvidenceIR(
            document_id, work_unit_id, {}, regions=(risk, trusted), tables=(table,), numeric_facts=numeric,
            visual_elements=visuals, required_source_ids=tuple(required),
        ).with_revision()

    def _semantic_patch(self, evidence: EvidenceIR) -> dict[str, object]:
        regions = []
        for region in evidence.regions:
            if region.evidence_state in {"NO_LITERAL_EVIDENCE", "LOW_CONFIDENCE", "DISAGREEMENT"}:
                regions.append({"region_id": region.region_id, "english": "", "term_ids": [], "unresolved": True, "provenance": "unresolved", "evidence_ids": [region.region_id]})
            else:
                regions.append({"region_id": region.region_id, "english": region.selected_literal_candidate or "", "term_ids": [], "unresolved": False, "provenance": "source_fact", "evidence_ids": [region.region_id]})
        tables = []
        for table in evidence.tables:
            cells = []
            for cell in table.cells:
                unresolved = cell.source_text is None and bool(cell.evidence_region_ids)
                cells.append({
                    "cell_id": cell.cell_id,
                    "english": "" if unresolved else (cell.source_text or ""),
                    "unresolved": unresolved,
                    "provenance": "unresolved" if unresolved else "source_fact",
                    "evidence_ids": [cell.cell_id],
                })
            tables.append({"table_id": table.table_id, "cells": cells})
        return {
            "schema_version": "1.0", "work_unit_id": evidence.work_unit_id, "evidence_revision": evidence.evidence_revision,
            "regions": regions, "tables": tables, "visual_interpretations": [], "executive_claims": [],
        }

    def test_risky_literal_states_cannot_be_promoted_or_completed_by_patch_text(self) -> None:
        cases = (
            ("NO_LITERAL_EVIDENCE", None),
            ("LOW_CONFIDENCE", "부분"),
            ("DISAGREEMENT", "원문 A"),
        )
        for state, selected in cases:
            with self.subTest(state=state):
                evidence = self._simple_evidence(state=state, selected=selected)
                forged = parse_translation_patch(self._patch(evidence, english="The unreadable item is approved.", unresolved=False, provenance="source_fact"))
                with self.assertRaises(KSlideError) as raised:
                    forged.validate_against(evidence)
                self.assertEqual(raised.exception.code, ErrorCode.CLAIM_UNSUPPORTED)

                invented_literal = self._patch(evidence, english="The unreadable item is approved.", unresolved=False, provenance="source_fact")
                invented_literal["regions"][0]["source_literal"] = "invented Korean"  # type: ignore[index]
                with self.assertRaises(KSlideError) as raised:
                    parse_translation_patch(invented_literal)
                self.assertEqual(raised.exception.code, ErrorCode.SCHEMA_INVALID)

                with_claim = self._patch(evidence, english="", unresolved=True, provenance="unresolved")
                with_claim["executive_claims"] = [{"claim_id": "claim-1", "kind": "decision_status", "text": "Approval is final.", "evidence_ids": ["unit-r1"], "uncertainty": "low", "provenance": "supported_interpretation"}]
                with self.assertRaises(KSlideError) as raised:
                    parse_translation_patch(with_claim).validate_against(evidence)
                self.assertEqual(raised.exception.code, ErrorCode.CLAIM_UNSUPPORTED)

                completed = parse_translation_patch(self._patch(evidence, english="", unresolved=True, provenance="unresolved"))
                completed.validate_against(evidence)
                canonical = merge_evidence_patch(evidence, completed)
                self.assertEqual(canonical.regions[0].translation, "")
                self.assertEqual(canonical.regions[0].provenance, ProvenanceState.UNRESOLVED.value)
                self.assertEqual(canonical.unresolved[0]["recovery_status"], "NEEDS_REVIEW")
                self.assertTrue(canonical.unresolved[0]["impact"])
                self.assertTrue(canonical.unresolved[0]["recommended_action"])
                self.assertEqual(canonical.unresolved[0]["location"]["bbox_px"], [0, 0, 0, 0])

    def test_unreadable_table_cell_cannot_be_recovered_from_model_text(self) -> None:
        region = EvidenceRegion("unit-r1", selected_literal_candidate=None, evidence_state="NO_LITERAL_EVIDENCE")
        cell = EvidenceTableCell("unit-t-r0-c0", 0, 0, source_text=None, cell_state="nonblank", evidence_region_ids=(region.region_id,))
        evidence = EvidenceIR(
            "doc-1", "unit", {}, regions=(region,),
            tables=(EvidenceTable("unit-t", row_count=1, column_count=1, cells=(cell,)),),
            required_source_ids=(region.region_id, "unit-t", cell.cell_id),
        ).with_revision()
        payload = {
            "schema_version": "1.0", "work_unit_id": "unit", "evidence_revision": evidence.evidence_revision,
            "regions": [{"region_id": region.region_id, "english": "", "term_ids": [], "unresolved": True, "provenance": "unresolved", "evidence_ids": [region.region_id]}],
            "tables": [{"table_id": "unit-t", "cells": [{"cell_id": cell.cell_id, "english": "Approved", "unresolved": False, "provenance": "source_fact", "evidence_ids": [cell.cell_id]}]}],
            "visual_interpretations": [], "executive_claims": [],
        }
        with self.assertRaises(KSlideError):
            parse_translation_patch(payload).validate_against(evidence)
        payload["tables"][0]["cells"][0].update({"english": "", "unresolved": True, "provenance": "unresolved"})  # type: ignore[index]
        patch = parse_translation_patch(payload)
        patch.validate_against(evidence)
        canonical = merge_evidence_patch(evidence, patch)
        self.assertEqual(canonical.tables[0].cells[0].translation, "")
        self.assertEqual(canonical.tables[0].cells[0].provenance, ProvenanceState.UNRESOLVED.value)

    def test_bounded_recovery_requires_hashed_engine_crop_candidate_and_rejects_partial_text(self) -> None:
        recovered_candidate = {
            "text": "원문 A",
            "confidence": 0.94,
            "provider": "fixture-ocr",
            "provider_version": "1",
            "recovery_pass": 1,
            "crop_sha256": "a" * 64,
            "trust_eligible": True,
        }
        selected, confidence, state = fuse_literal_evidence(
            [{"text": "원문 A", "confidence": 1.0}],
            [{"text": "원문 B", "confidence": 0.30}, recovered_candidate],
        )
        self.assertEqual((selected, state), ("원문 A", "HIGH_AGREEMENT"))
        self.assertEqual(confidence, 1.0)

        weak_confirmation = {**recovered_candidate, "confidence": 0.79}
        weak_selected, weak_confidence, weak_state = fuse_literal_evidence(
            [{"text": "원문 A", "confidence": 1.0}],
            [{"text": "원문 B", "confidence": 0.30}, weak_confirmation],
        )
        self.assertEqual((weak_selected, weak_state), ("원문 A", "HIGH_AGREEMENT"))
        weak_recovery = EvidenceIR(
            "doc-1", "unit", {},
            regions=(EvidenceRegion(
                "unit-r1", selected_literal_candidate=weak_selected,
                native_text_candidates=({"text": "원문 A", "confidence": 1.0},),
                ocr_candidates=({"text": "원문 B", "confidence": 0.30}, weak_confirmation),
                literal_confidence=weak_confidence, evidence_state=weak_state,
                recovery_status="RECOVERED", recovery_attempts=1,
            ),),
            required_source_ids=("unit-r1",),
        )
        with self.assertRaises(KSlideError):
            weak_recovery.with_revision()

        recovered = EvidenceIR(
            "doc-1", "unit", {},
            regions=(EvidenceRegion(
                "unit-r1", selected_literal_candidate=selected,
                native_text_candidates=({"text": "원문 A", "confidence": 1.0},),
                ocr_candidates=({"text": "원문 B", "confidence": 0.30}, recovered_candidate),
                literal_confidence=confidence, evidence_state=state,
                recovery_status="RECOVERED", recovery_attempts=1,
            ),),
            required_source_ids=("unit-r1",),
        ).with_revision()
        parse_translation_patch(self._patch(recovered, english="Source text A", unresolved=False, provenance="source_fact")).validate_against(recovered)

        partial = {**recovered_candidate, "text": "부분", "touches_crop_boundary": True, "trust_eligible": False}
        selected, confidence, state = fuse_literal_evidence([], [partial])
        self.assertIsNone(selected)
        self.assertIsNone(confidence)
        self.assertEqual(state, "NO_LITERAL_EVIDENCE")
        failed = EvidenceIR(
            "doc-1", "unit", {},
            regions=(EvidenceRegion(
                "unit-r1", selected_literal_candidate=None,
                ocr_candidates=(partial,), evidence_state="NO_LITERAL_EVIDENCE",
                recovery_status="NEEDS_REVIEW", recovery_attempts=1,
                recovery_reason="A bounded crop re-extraction did not produce a trustworthy complete literal.",
            ),),
            required_source_ids=("unit-r1",),
        ).with_revision()
        self.assertEqual(failed.regions[0].recovery_status, "NEEDS_REVIEW")

    def test_semantic_evidence_aliases_fail_closed_at_patch_and_canonical_boundaries(self) -> None:
        evidence = self._semantic_evidence()
        base = self._semantic_patch(evidence)
        context_id = f"{evidence.work_unit_id}-context"
        table_id = f"{evidence.work_unit_id}-table"

        aliases = (
            {
                **base,
                "executive_claims": [{"claim_id": "raw-context-claim", "kind": "decision_status", "text": "Approval is final.", "evidence_ids": [context_id], "uncertainty": "low", "provenance": "supported_interpretation"}],
            },
            {
                **base,
                "visual_interpretations": [{"relation_id": "raw-context-visual", "interpretation": "The unreadable item is approved.", "evidence_ids": [context_id], "source_element_ids": [context_id], "provenance": "supported_interpretation"}],
            },
            {
                **base,
                "executive_claims": [{"claim_id": "unresolved-table-claim", "kind": "takeaway", "text": "The table confirms approval.", "evidence_ids": [table_id], "uncertainty": "low", "provenance": "supported_interpretation"}],
            },
        )
        for payload in aliases:
            with self.subTest(surface="visual" if payload.get("visual_interpretations") else "claim"):
                with self.assertRaises(KSlideError) as raised:
                    parse_translation_patch(payload).validate_against(evidence)
                self.assertEqual(raised.exception.code, ErrorCode.CLAIM_UNSUPPORTED)

        from k_slide.ir import SlideIR
        from k_slide.verify import VerificationResult, _validate_canonical_provenance

        canonical = merge_evidence_patch(evidence, parse_translation_patch(base)).as_dict()
        canonical["executive_semantics"]["executive_claims"] = aliases[0]["executive_claims"]
        parsed = SlideIR.from_dict(canonical, evidence=evidence)
        result = VerificationResult(status="PASS", run_id="run")
        _validate_canonical_provenance(result, parsed, evidence, evidence.work_unit_id, canonical)
        self.assertIn("KSLIDE_LITERAL_RECOVERY_REQUIRED", {issue.code for issue in result.issues})

    def test_exact_grounded_evidence_containers_and_typed_visuals_remain_usable(self) -> None:
        evidence = self._semantic_evidence()
        base = self._semantic_patch(evidence)
        base["executive_claims"] = [
            {"claim_id": "trusted-region", "kind": "takeaway", "text": "The launch date is 2026-04-01.", "evidence_ids": [f"{evidence.work_unit_id}-trusted"], "uncertainty": "low", "provenance": "supported_interpretation"},
            {"claim_id": "trusted-cell", "kind": "takeaway", "text": "The trusted cell records 2026-04-01.", "evidence_ids": [f"{evidence.work_unit_id}-cell-trusted"], "uncertainty": "low", "provenance": "supported_interpretation"},
            {"claim_id": "trusted-number", "kind": "takeaway", "text": "The source records 2026-04-01.", "evidence_ids": [f"{evidence.work_unit_id}-fact"], "uncertainty": "low", "provenance": "supported_interpretation"},
        ]
        parse_translation_patch(base).validate_against(evidence)

        grounded = self._semantic_evidence(grounded_table=True)
        grounded_patch = self._semantic_patch(grounded)
        grounded_patch["executive_claims"] = [{
            "claim_id": "grounded-table", "kind": "takeaway", "text": "The table records 2026-04-01.",
            "evidence_ids": [f"{grounded.work_unit_id}-table"], "uncertainty": "low", "provenance": "supported_interpretation",
        }]
        parse_translation_patch(grounded_patch).validate_against(grounded)

        chart_id = f"{evidence.work_unit_id}-chart"
        edge_id = f"{evidence.work_unit_id}-edge"
        visual_patch = self._semantic_patch(evidence)
        visual_patch["visual_interpretations"] = [
            {
                "relation_id": "typed-chart", "interpretation": "Revenue rises.", "evidence_ids": [chart_id],
                "source_element_ids": [chart_id], "provenance": "source_fact",
                "chart_claim": {"chart_element_id": chart_id, "kind": "trend", "series_index": 0, "series_name": "Revenue", "direction": "increasing"},
            },
            {
                "relation_id": "typed-connector", "interpretation": "A flows to B.", "evidence_ids": [edge_id],
                "source_element_ids": [f"{evidence.work_unit_id}-node-a", f"{evidence.work_unit_id}-node-b", edge_id],
                "relation_type": "next", "direction": "left_to_right", "provenance": "source_fact",
            },
        ]
        patch = parse_translation_patch(visual_patch)
        patch.validate_against(evidence)
        from k_slide.verify import VerificationResult, _check_visual_evidence

        slide = merge_evidence_patch(evidence, patch)
        result = VerificationResult(status="PASS", run_id="run")
        _check_visual_evidence(result, slide, evidence)
        self.assertEqual(result.issues, [])

    def test_native_typed_nontext_visual_can_ground_visual_interpretation(self) -> None:
        region = EvidenceRegion(
            "unit-group", region_type="IMAGE", selected_literal_candidate=None,
            evidence_state="NO_LITERAL_EVIDENCE", required_for_translation=False,
            translation_disposition="NOT_APPLICABLE_NATIVE_VISUAL", disposition_policy="native-nontext-visual-v1",
            disposition_evidence_ids=("unit-group",), recovery_status="NOT_REQUIRED",
        )
        native = ({"source_id": "unit-group", "shape_type": "group"}, {"source_id": "unit-group-child", "shape_type": "auto_shape", "text": "A"})
        visual = (
            {"element_id": "unit-group", "source_id": "unit-group", "kind": "shape", "shape_type": "group", "bbox_px": [0, 0, 10, 10], "required": True},
            {"element_id": "unit-group-child", "source_id": "unit-group-child", "kind": "shape", "shape_type": "auto_shape", "bbox_px": [0, 0, 10, 10], "source_text": "A", "required": True},
        )
        evidence = EvidenceIR("doc-1", "unit", {}, regions=(region,), visual_elements=visual, native_evidence=native, required_source_ids=("unit-group", "unit-group-child")).with_revision()
        payload = {"schema_version": "1.0", "work_unit_id": "unit", "evidence_revision": evidence.evidence_revision, "regions": [], "tables": [], "visual_interpretations": [{"relation_id": "native-group", "interpretation": "A grouped non-text object is present.", "evidence_ids": ["unit-group"], "source_element_ids": ["unit-group"], "provenance": "supported_interpretation"}], "executive_claims": []}
        parse_translation_patch(payload).validate_against(evidence)

    def test_targeted_crop_ocr_recovers_high_confidence_or_keeps_partial_and_failure_unresolved(self) -> None:
        scenarios = (
            ("recovered", _FixtureOCR(page_regions=(OCRRegion("검토", (20, 20, 80, 80), 0.35),), crop_regions=(OCRRegion("검토", (10, 10, 60, 30), 0.96),)), "RECOVERED", "OCR_ONLY"),
            ("partial", _FixtureOCR(page_regions=(OCRRegion("검토", (20, 20, 80, 80), 0.35),), crop_regions=(OCRRegion("검토", (0, 10, 72, 30), 0.98),)), "NEEDS_REVIEW", "LOW_CONFIDENCE"),
            ("cropped-partial", _FixtureOCR(page_regions=(OCRRegion("검토", (20, 20, 80, 80), 0.35),), crop_regions=(OCRRegion("검", (10, 10, 60, 30), 0.99),)), "NEEDS_REVIEW", "LOW_CONFIDENCE"),
            ("crop-error", _FixtureOCR(page_regions=(), crop_error=ValueError("fixture")), "NEEDS_REVIEW", "NO_LITERAL_EVIDENCE"),
        )
        for name, provider, expected_recovery, expected_state in scenarios:
            with self.subTest(name=name):
                holder, _root, run, _environment = self._source_run(provider)
                try:
                    evidence = EvidenceIR.from_dict(json.loads(storage_path(run, StorageArtifact.EVIDENCE_IR, f"evidence/{load_queue(run).work_units[0].work_unit_id}.json").read_text(encoding="utf-8")))
                    region = evidence.regions[0]
                    self.assertEqual(region.recovery_status, expected_recovery)
                    self.assertEqual(region.evidence_state, expected_state)
                    self.assertEqual(region.recovery_attempts, 1)
                    self.assertEqual(region.translation_disposition, "REQUIRED")
                    self.assertTrue(region.required_for_translation)
                    if expected_recovery == "RECOVERED":
                        self.assertEqual(region.selected_literal_candidate, "검토")
                        self.assertEqual(region.ocr_candidates[-1]["recovery_pass"], 1)
                        self.assertEqual(len(region.ocr_candidates[-1]["crop_sha256"]), 64)
                    elif name == "partial":
                        self.assertFalse(region.ocr_candidates[-1]["trust_eligible"])
                    elif name == "cropped-partial":
                        self.assertEqual(region.selected_literal_candidate, "검토")
                        self.assertTrue(region.ocr_candidates[-1]["trust_eligible"])
                    else:
                        self.assertIn("failed safely", region.recovery_reason)
                finally:
                    holder.cleanup()

    def test_native_visual_not_applicable_policy_is_bound_and_cannot_hide_required_coverage(self) -> None:
        region = EvidenceRegion(
            "unit-group", region_type="IMAGE", selected_literal_candidate=None,
            evidence_state="NO_LITERAL_EVIDENCE", required_for_translation=False,
            translation_disposition="NOT_APPLICABLE_NATIVE_VISUAL", disposition_policy="native-nontext-visual-v1",
            disposition_evidence_ids=("unit-group",), recovery_status="NOT_REQUIRED",
        )
        native = (
            {"source_id": "unit-group", "shape_type": "group"},
            {"source_id": "unit-group-child", "shape_type": "auto_shape", "text": "A"},
        )
        visual = (
            {"element_id": "unit-group", "source_id": "unit-group", "kind": "shape", "shape_type": "group", "required": True},
            {"element_id": "unit-group-child", "source_id": "unit-group-child", "kind": "shape", "shape_type": "auto_shape", "source_text": "A", "required": True},
        )
        evidence = EvidenceIR("doc-1", "unit", {}, regions=(region,), visual_elements=visual, native_evidence=native, required_source_ids=("unit-group", "unit-group-child")).with_revision()
        packet = build_work_packet(evidence)
        self.assertNotIn("unit-group", packet["required_output_ids"])
        self.assertEqual(packet["source_regions"][0]["translation_disposition"], "NOT_APPLICABLE_NATIVE_VISUAL")

        minimal = {"schema_version": "1.0", "work_unit_id": "unit", "evidence_revision": evidence.evidence_revision, "regions": [], "tables": [], "visual_interpretations": [], "executive_claims": []}
        canonical = merge_evidence_patch(evidence, parse_translation_patch(minimal))
        self.assertEqual(canonical.regions, [])
        self.assertEqual({entry.source_id: entry.status for entry in canonical.coverage}["unit-group"], "intentionally_preserved")

        attempted_escape = {**minimal, "regions": [{"region_id": "unit-group", "english": "Decorative", "term_ids": [], "unresolved": False}]}
        with self.assertRaises(KSlideError):
            parse_translation_patch(attempted_escape).validate_against(evidence)

        hidden = EvidenceIR("doc-1", "unit", {}, regions=(region,), visual_elements=visual, native_evidence=native, required_source_ids=("unit-group-child",))
        with self.assertRaises(KSlideError):
            hidden.with_revision()
        generic_image = EvidenceRegion(
            "unit-image", evidence_state="NO_LITERAL_EVIDENCE", selected_literal_candidate=None,
            required_for_translation=False, translation_disposition="NOT_APPLICABLE_NATIVE_VISUAL",
            disposition_policy="native-nontext-visual-v1", disposition_evidence_ids=("unit-image",), recovery_status="NOT_REQUIRED",
        )
        with self.assertRaises(KSlideError):
            EvidenceIR("doc-1", "unit", {}, regions=(generic_image,), required_source_ids=("unit-image",)).with_revision()

    def test_conflict_synthesis_waits_for_each_document_and_keeps_competing_claims(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(_PROJECT_ROOT / "termbase", root / "termbase")
            from PIL import Image

            for name in ("a.png", "b.png"):
                Image.new("RGB", (20, 20), "white").save(root / name)
            run = prepare_run(root, explicit_paths=[str(root / "a.png"), str(root / "b.png")], environment_identity=reference_environment("ksa25-conflict"))
            queue = load_queue(run)
            evidences: list[EvidenceIR] = []
            assertions = []
            for unit, claim_text in zip(queue.work_units, ("Launch date: 2026-04-01.", "Launch date: 2026-05-01.")):
                source_text = "Launch date 2026-04-01" if claim_text.endswith("04-01.") else "Launch date 2026-05-01"
                region = EvidenceRegion(f"{unit.work_unit_id}-r1", selected_literal_candidate=source_text)
                evidence = EvidenceIR(unit.document_id, unit.work_unit_id, {"page_or_slide_index": unit.source_index}, regions=(region,), required_source_ids=(region.region_id,)).with_revision()
                save_evidence(run, evidence)
                unit.evidence_revision = evidence.evidence_revision
                unit.status = WorkUnitStatus.TRANSLATED
                patch = parse_translation_patch({
                    "schema_version": "1.0",
                    "work_unit_id": unit.work_unit_id,
                    "evidence_revision": evidence.evidence_revision,
                    "regions": [{"region_id": region.region_id, "english": source_text, "term_ids": [], "unresolved": False, "provenance": "source_fact", "evidence_ids": [region.region_id]}],
                    "tables": [],
                    "visual_interpretations": [],
                    "executive_claims": [{"claim_id": f"{unit.work_unit_id}-date", "kind": "timing", "text": claim_text, "evidence_ids": [region.region_id], "uncertainty": "low", "provenance": "supported_interpretation"}],
                })
                from k_slide.translation import merge_evidence_patch

                canonical = merge_evidence_patch(evidence, patch)
                atomic = storage_path(run, StorageArtifact.CANONICAL_IR, f"ir/{unit.work_unit_id}.json", create_parent=True)
                atomic.write_text(json.dumps(canonical.as_dict(), ensure_ascii=False), encoding="utf-8")
                assertions.append({"work_unit_id": unit.work_unit_id, "semantic_kind": "executive_claim", "semantic_id": f"{unit.work_unit_id}-date"})
                evidences.append(evidence)
            save_queue(run, queue)

            second_canonical = storage_path(run, StorageArtifact.CANONICAL_IR, f"ir/{queue.work_units[1].work_unit_id}.json")
            second_payload = second_canonical.read_bytes()
            second_canonical.unlink()
            with self.assertRaises(KSlideError):
                assess_conflicts(run, candidate_groups=[{"assertions": assertions}])
            second_canonical.write_bytes(second_payload)

            registry = assess_conflicts(run, candidate_groups=[{"assertions": assertions}])
            self.assertEqual(len(registry.conflicts), 1)
            conflict = registry.conflicts[0]
            self.assertEqual(conflict.resolution_state, "unresolved")
            self.assertEqual({item.document_id for item in conflict.participants}, {item.document_id for item in evidences})
            self.assertEqual({item.evidence_ref["evidence_revision"] for item in conflict.participants}, {item.evidence_revision for item in evidences})

    def test_conflict_rebuild_rejects_canonical_claims_backed_only_by_raw_context(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(_PROJECT_ROOT / "termbase", root / "termbase")
            from PIL import Image

            for name in ("a.png", "b.png"):
                Image.new("RGB", (20, 20), "white").save(root / name)
            environment = reference_environment("ksa25-context-conflict")
            run = prepare_run(root, explicit_paths=[str(root / "a.png"), str(root / "b.png")], environment_identity=environment)
            queue = load_queue(run)
            assertions = []
            for unit in queue.work_units:
                evidence = self._semantic_evidence(document_id=unit.document_id, work_unit_id=unit.work_unit_id)
                save_evidence(run, evidence)
                unit.evidence_revision = evidence.evidence_revision
                unit.status = WorkUnitStatus.TRANSLATED
                canonical = merge_evidence_patch(evidence, parse_translation_patch(self._semantic_patch(evidence))).as_dict()
                claim_id = f"{unit.work_unit_id}-raw-context"
                canonical["executive_semantics"]["executive_claims"] = [{
                    "claim_id": claim_id,
                    "kind": "decision_status",
                    "text": "Approval is final.",
                    "evidence_ids": [f"{unit.work_unit_id}-context"],
                    "uncertainty": "low",
                    "provenance": "supported_interpretation",
                }]
                storage_path(run, StorageArtifact.CANONICAL_IR, f"ir/{unit.work_unit_id}.json", create_parent=True).write_text(json.dumps(canonical), encoding="utf-8")
                assertions.append({"work_unit_id": unit.work_unit_id, "semantic_kind": "executive_claim", "semantic_id": claim_id})
            save_queue(run, queue)
            with self.assertRaises(KSlideError) as raised:
                assess_conflicts(run, candidate_groups=[{"assertions": assertions}])
            self.assertEqual(raised.exception.code, ErrorCode.CONFLICT_REFERENCE_INVALID)

    def test_foreign_context_and_foreign_patch_cannot_repair_another_document(self) -> None:
        evidence_a = EvidenceIR("doc-a", "unit-a", {}, regions=(EvidenceRegion("unit-a-r1", selected_literal_candidate="원문 A"),), required_source_ids=("unit-a-r1",)).with_revision()
        evidence_b = EvidenceIR("doc-b", "unit-b", {}, regions=(EvidenceRegion("unit-b-r1", selected_literal_candidate="원문 B"),), required_source_ids=("unit-b-r1",)).with_revision()
        with self.assertRaises(KSlideError) as raised:
            build_work_packet(evidence_a, deck_context={"document_id": "doc-b", "raw_source": "원문 B", "translation": "repaired"})
        self.assertEqual(raised.exception.code, ErrorCode.CLAIM_UNSUPPORTED)
        foreign = parse_translation_patch(self._patch(evidence_a, english="Source text B", unresolved=False, provenance="supported_interpretation"))
        from dataclasses import replace

        foreign = replace(foreign, regions=(replace(foreign.regions[0], evidence_ids=("unit-b-r1",)),))
        with self.assertRaises(KSlideError):
            foreign.validate_against(evidence_a)
        self.assertNotEqual(evidence_a.evidence_revision, evidence_b.evidence_revision)

    def test_employee_recovery_lifecycle_persists_review_and_blocks_completion(self) -> None:
        provider = _FixtureOCR(page_regions=(), crop_error=ValueError("fixture OCR crop failure"))
        holder, root, run, environment = self._source_run(provider)
        try:
            next_value = _next(root, run.name, None, environment)
            self.assertEqual(next_value["status"], "READY")
            packet = _evidence(root, run.name, None, environment)
            self.assertEqual(packet["status"], "EVIDENCE_READY")
            self.assertEqual(packet["source_regions"][0]["recovery_status"], "NEEDS_REVIEW")
            self.assertTrue(packet["model_media_plan"]["required_crops"])

            evidence = EvidenceIR.from_dict(json.loads(storage_path(run, StorageArtifact.EVIDENCE_IR, f"evidence/{next_value['work_unit_id']}.json").read_text(encoding="utf-8")))
            forged = self._patch(evidence, english="The unreadable source confirms approval.", unresolved=False, provenance="source_fact")
            with self.assertRaises(KSlideError):
                _submit(root, run.name, json.dumps(forged), None, environment)
            context_id = next(item["element_id"] for item in evidence.visual_elements if item.get("kind") == "context_image")
            indirect = self._patch(evidence, english="", unresolved=True, provenance="unresolved")
            indirect["executive_claims"] = [{"claim_id": "raw-context-decision", "kind": "decision_status", "text": "Approval is final.", "evidence_ids": [context_id], "uncertainty": "low", "provenance": "supported_interpretation"}]
            with self.assertRaises(KSlideError):
                _submit(root, run.name, json.dumps(indirect), None, environment)
            unresolved = self._patch(evidence, english="", unresolved=True, provenance="unresolved")
            accepted = _submit(root, run.name, json.dumps(unresolved), None, environment)
            self.assertEqual(accepted["status"], "NEEDS_REVIEW")
            self.assertEqual(_next(root, run.name, None, environment)["status"], "NEEDS_REVIEW")
            brief = storage_path(run, StorageArtifact.REPORT, "05_executive_brief.md").read_text(encoding="utf-8")
            self.assertNotIn("Approval is final.", brief)
            self.assertIn("No evidence-backed executive claims are available yet.", brief)

            assessment = _conflict_assess(root, run.name, '{"schema_version":"1.0","candidate_groups":[]}', None, environment)
            self.assertEqual(assessment["status"], "ASSESSED_ZERO_CONFLICTS")
            verify = verify_run(run, environment_identity=environment)
            self.assertFalse(verify.passed)
            self.assertIn("KSLIDE_REVIEW_REQUIRED", {item.code for item in verify.issues})
            self.assertFalse(storage_path(run, StorageArtifact.COMPLETION_MARKER, "RUN_COMPLETE.md").exists())
            with self.assertRaises(KSlideError) as raised:
                finalize_run(run, environment_identity=environment)
            self.assertEqual(raised.exception.code, ErrorCode.COMPLETION_BLOCKED)
            self.assertFalse(storage_path(run, StorageArtifact.COMPLETION_MARKER, "RUN_COMPLETE.md").exists())
        finally:
            holder.cleanup()


if __name__ == "__main__":
    unittest.main()
