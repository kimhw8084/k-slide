from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from k_slide.evidence_ir import EvidenceIR, EvidenceRegion, EvidenceTable, EvidenceTableCell, save_evidence
from k_slide.errors import ErrorCode, KSlideError
from k_slide.ir import SlideIR
from k_slide.modality import classify_source_language, source_english_spans
from k_slide.queue import WorkQueue, WorkUnit, WorkUnitStatus, save_queue
from k_slide.rendering.reports import render_run
from k_slide.storage import StorageArtifact, storage_path
from k_slide.translation import merge_evidence_patch, parse_translation_patch
from k_slide.terminology import Termbase
from k_slide.verify import VerificationResult, _check_visual_evidence, _validate_canonical_provenance, _validate_slide
from k_slide.io import atomic_write_json


def _patch(evidence: EvidenceIR, *, region_text: str, status: str | None = None, speech: str | None = None, relation: dict[str, object] | None = None) -> dict[str, object]:
    region: dict[str, object] = {"region_id": evidence.regions[0].region_id, "english": region_text, "term_ids": [], "unresolved": False}
    if status is not None:
        region["commitment_status"] = status
        region["evidence_ids"] = [evidence.regions[0].region_id]
    if speech is not None:
        region["speech_act"] = speech
    return {
        "schema_version": "1.0",
        "work_unit_id": evidence.work_unit_id,
        "evidence_revision": evidence.evidence_revision,
        "regions": [region],
        "tables": [],
        "visual_interpretations": [relation] if relation else [],
        "executive_claims": [],
    }


class KSA24ModalityConformanceTests(unittest.TestCase):
    def test_script_identity_and_mixed_source_english_are_engine_owned(self) -> None:
        self.assertEqual(classify_source_language("검토"), "ko")
        self.assertEqual(classify_source_language("Review"), "en")
        self.assertEqual(classify_source_language("AI Platform 검토"), "mixed")
        self.assertEqual(classify_source_language("2025 / %"), "unknown")
        self.assertEqual(source_english_spans("AI Platform 검토"), ("AI Platform",))

        evidence = EvidenceIR(
            "doc",
            "unit",
            {},
            regions=(EvidenceRegion("unit-r", selected_literal_candidate="AI Platform 검토", language="mixed", source_english_spans=("AI Platform",)),),
            required_source_ids=("unit-r",),
        ).with_revision()
        good = parse_translation_patch(_patch(evidence, region_text="AI Platform under review"))
        self.assertEqual(merge_evidence_patch(evidence, good).regions[0].translation, "AI Platform under review")
        bad = _patch(evidence, region_text="Platform under review")
        with self.assertRaises(KSlideError) as raised:
            parse_translation_patch(bad).validate_against(evidence)
        self.assertEqual(raised.exception.code, ErrorCode.CLAIM_UNSUPPORTED)

    def test_table_structure_and_notes_survive_merge_render_and_tamper_verification(self) -> None:
        cells = (
            EvidenceTableCell("unit-t-r0-c0", 0, 0, source_text="항목", source_language="ko", is_header=True, cell_state="nonblank"),
            EvidenceTableCell("unit-t-r0-c1", 0, 1, source_text="Revenue", source_language="en", is_header=True, cell_state="nonblank"),
            EvidenceTableCell("unit-t-r1-c0", 1, 0, source_text="", cell_state="blank", is_blank=True),
            EvidenceTableCell("unit-t-r1-c1", 1, 1, source_text="AI 2025 검토", source_language="mixed", source_english_spans=("AI 2025",), cell_state="nonblank"),
        )
        table = EvidenceTable("unit-t", row_count=2, column_count=2, header_rows=(0,), unit="USD millions", source_notes=("Source: Finance",), cells=cells)
        evidence = EvidenceIR("doc", "unit", {}, regions=(EvidenceRegion("unit-r", selected_literal_candidate="표"),), tables=(table,), required_source_ids=("unit-r", "unit-t", *(cell.cell_id for cell in cells))).with_revision()
        patch = {
            **_patch(evidence, region_text="Table"),
            "tables": [{"table_id": "unit-t", "cells": [
                {"cell_id": "unit-t-r0-c0", "english": "Item", "unresolved": False},
                {"cell_id": "unit-t-r0-c1", "english": "Revenue", "unresolved": False},
                {"cell_id": "unit-t-r1-c0", "english": "", "unresolved": False},
                {"cell_id": "unit-t-r1-c1", "english": "AI 2025 under review", "unresolved": False},
            ]}],
        }
        slide = merge_evidence_patch(evidence, parse_translation_patch(patch))
        self.assertEqual((slide.tables[0].row_count, slide.tables[0].column_count), (2, 2))
        self.assertEqual(slide.tables[0].source_notes, ["Source: Finance"])
        self.assertEqual(slide.tables[0].cells[2].translation, "")
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory) / "run"
            run.mkdir()
            atomic_write_json(storage_path(run, StorageArtifact.RUN_MANIFEST, "RUN_MANIFEST.json", create_parent=True), {"inputs": []})
            save_evidence(run, evidence)
            save_queue(run, WorkQueue("run", [WorkUnit("unit", "doc", "source-001", 0, status=WorkUnitStatus.TRANSLATED)]))
            atomic_write_json(storage_path(run, StorageArtifact.CANONICAL_IR, "ir/unit.json", create_parent=True), slide.as_dict())
            render_run(run)
            report = storage_path(run, StorageArtifact.REPORT, "05_final_report.md").read_text(encoding="utf-8")
            self.assertIn("2 × 2", report)
            self.assertIn("Source: Finance", report)
            tampered = slide.as_dict()
            tampered["tables"][0]["cells"][1]["column"] = 0  # type: ignore[index]
            atomic_write_json(storage_path(run, StorageArtifact.CANONICAL_IR, "ir/unit.json"), tampered)
            result = VerificationResult(status="PASS", run_id="run")
            _validate_slide(run, "unit", result, termbase=Termbase("1.0", ()))
            self.assertIn("KSLIDE_TABLE_CELL_ID_MISMATCH", {issue.code for issue in result.issues})

    def test_protected_fixture_covers_multilevel_headers_merges_blanks_units_and_notes(self) -> None:
        fixture = json.loads((Path(__file__).parent / "fixtures" / "ksa24_table_fixture.json").read_text(encoding="utf-8"))
        self.assertEqual((fixture["row_count"], fixture["column_count"]), (3, 3))
        self.assertEqual(fixture["header_rows"], [0, 1])
        self.assertEqual(fixture["header_columns"], [0])
        self.assertEqual(fixture["unit"], "USD millions")
        cells = {cell["cell_id"]: cell for cell in fixture["cells"]}
        self.assertEqual(cells["fixture-table-r0-c0"]["cell_state"], "merge_origin")
        self.assertEqual(cells["fixture-table-r0-c1"]["cell_state"], "merge_continuation")
        self.assertTrue(cells["fixture-table-r2-c2"]["is_blank"])
        self.assertEqual(fixture["source_notes"], ["Source: Finance", "* Margin excludes one-time items"])

    def test_modality_strengthening_is_rejected_and_clear_states_are_preserved(self) -> None:
        cases = (("검토 중", "under_review"), ("가능", "possible"), ("전망", "forecast"), ("제안", "proposed"), ("잠정", "tentative"), ("완료", "completed"), ("진행 중", "in_progress"))
        for source_text, status in cases:
            with self.subTest(source_text=source_text):
                evidence = EvidenceIR("doc", "unit", {}, regions=(EvidenceRegion("unit-r", selected_literal_candidate=source_text, language="ko"),), required_source_ids=("unit-r",)).with_revision()
                patch = parse_translation_patch(_patch(evidence, region_text="status", status=status, speech="status"))
                self.assertEqual(patch.regions[0].commitment_status, status)
        evidence = EvidenceIR("doc", "unit", {}, regions=(EvidenceRegion("unit-r", selected_literal_candidate="검토 중", language="ko"),), required_source_ids=("unit-r",)).with_revision()
        with self.assertRaises(KSlideError) as raised:
            parse_translation_patch(_patch(evidence, region_text="Decided", status="decided", speech="decision")).validate_against(evidence)
        self.assertEqual(raised.exception.code, ErrorCode.MODALITY_MISMATCH)

    def test_chart_trend_and_process_direction_are_bound_to_engine_evidence(self) -> None:
        chart = {"element_id": "unit-chart", "kind": "chart", "bbox_px": [0, 0, 100, 100], "required": True, "chart": {"chart_type": "line", "title": "Revenue", "categories": ["Q1", "Q2", "Q3"], "series": [{"series_index": 0, "name": "Revenue", "points": [{"point_index": 0, "value": 1.0, "is_blank": False}, {"point_index": 1, "value": 2.0, "is_blank": False}, {"point_index": 2, "value": 3.0, "is_blank": False}]}]}}
        evidence = EvidenceIR("doc", "unit", {}, regions=(EvidenceRegion("unit-r", selected_literal_candidate="Chart"),), visual_elements=(chart,), required_source_ids=("unit-r", "unit-chart")).with_revision()
        reversed_patch = _patch(evidence, region_text="Chart", relation={"relation_id": "trend", "interpretation": "The trend is declining", "evidence_ids": ["unit-chart"], "source_element_ids": ["unit-chart"], "provenance": "supported_interpretation"})
        with self.assertRaises(KSlideError) as raised:
            parse_translation_patch(reversed_patch).validate_against(evidence)
        self.assertEqual(raised.exception.code, ErrorCode.CHART_INTERPRETATION_MISMATCH)

        process = (
            {"element_id": "unit-a", "kind": "shape", "bbox_px": [0, 0, 10, 10], "required": True},
            {"element_id": "unit-b", "kind": "shape", "bbox_px": [20, 0, 30, 10], "required": True},
            {"element_id": "unit-edge", "kind": "connector", "bbox_px": [10, 5, 20, 5], "required": True, "connector": {"from_element_id": "unit-a", "to_element_id": "unit-b"}},
        )
        process_evidence = EvidenceIR("doc", "unit", {}, regions=(EvidenceRegion("unit-r", selected_literal_candidate="Process"),), visual_elements=process, required_source_ids=("unit-r", "unit-a", "unit-b", "unit-edge")).with_revision()
        reversed_edge = _patch(process_evidence, region_text="Process", relation={"relation_id": "edge", "interpretation": "reverse", "evidence_ids": ["unit-edge"], "source_element_ids": ["unit-b", "unit-a", "unit-edge"], "relation_type": "next", "direction": "right_to_left", "provenance": "source_fact"})
        with self.assertRaises(KSlideError):
            parse_translation_patch(reversed_edge).validate_against(process_evidence)

        valid_edge = _patch(process_evidence, region_text="Process", relation={"relation_id": "edge", "interpretation": "next", "evidence_ids": ["unit-edge"], "source_element_ids": ["unit-a", "unit-b", "unit-edge"], "relation_type": "next", "direction": "left_to_right", "provenance": "source_fact"})
        valid_slide = merge_evidence_patch(process_evidence, parse_translation_patch(valid_edge))
        result = VerificationResult(status="PASS", run_id="run")
        _validate_canonical_provenance(result, valid_slide, process_evidence, "unit")
        _check_visual_evidence(result, valid_slide, process_evidence)
        self.assertEqual(result.issues, [])


if __name__ == "__main__":
    unittest.main()
