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

    def test_table_cell_modality_is_closed_persisted_and_checked_for_weakening(self) -> None:
        cues = (
            ("검토 중", "under_review", "Under review", "status"),
            ("예정", "scheduled", "Scheduled", "plan"),
            ("계획", "planned", "Planned", "plan"),
            ("목표", "target", "Target", "plan"),
            ("확정", "decided", "Decided", "decision"),
            ("완료", "completed", "Completed", "status"),
            ("진행 중", "in_progress", "In progress", "status"),
            ("제안", "proposed", "Proposed", "recommendation"),
            ("전망", "forecast", "Forecast", "forecast"),
            ("가능", "possible", "Possible", "risk"),
            ("잠정", "tentative", "Tentative", "status"),
        )
        cells = tuple(
            EvidenceTableCell(f"unit-t-r{index}-c0", index, 0, source_text=source, source_language="ko", cell_state="nonblank")
            for index, (source, _status, _english, _speech) in enumerate(cues)
        )
        table = EvidenceTable("unit-t", row_count=len(cells), column_count=1, cells=cells)
        evidence = EvidenceIR(
            "doc",
            "unit",
            {"source_language_policy": "unicode-script-v1"},
            regions=(EvidenceRegion("unit-r", selected_literal_candidate="Title", language="en"),),
            tables=(table,),
            required_source_ids=("unit-r", "unit-t", *(cell.cell_id for cell in cells)),
        ).with_revision()
        patch = {
            **_patch(evidence, region_text="Title"),
            "tables": [{
                "table_id": "unit-t",
                "cells": [
                    {"cell_id": cell.cell_id, "english": english, "commitment_status": status, "speech_act": speech, "unresolved": False}
                    for cell, (_source, status, english, speech) in zip(cells, cues)
                ],
            }],
        }
        merged = merge_evidence_patch(evidence, parse_translation_patch(patch))
        self.assertEqual([cell.commitment_status for cell in merged.tables[0].cells], [item[1] for item in cues])
        self.assertEqual([cell.speech_act for cell in merged.tables[0].cells], [item[3] for item in cues])

        missing = json.loads(json.dumps(patch))
        missing["tables"][0]["cells"][0].pop("commitment_status")
        with self.assertRaises(KSlideError) as raised:
            parse_translation_patch(missing).validate_against(evidence)
        self.assertEqual(raised.exception.code, ErrorCode.MODALITY_MISMATCH)

        mismatch = json.loads(json.dumps(patch))
        mismatch["tables"][0]["cells"][0].update({"commitment_status": "decided", "speech_act": "decision"})
        with self.assertRaises(KSlideError) as raised:
            parse_translation_patch(mismatch).validate_against(evidence)
        self.assertEqual(raised.exception.code, ErrorCode.MODALITY_MISMATCH)

        weakened = json.loads(json.dumps(patch))
        weakened["tables"][0]["cells"][0]["english"] = "Launch status"
        with self.assertRaises(KSlideError) as raised:
            parse_translation_patch(weakened).validate_against(evidence)
        self.assertEqual(raised.exception.code, ErrorCode.MODALITY_MISMATCH)

        strengthened = json.loads(json.dumps(patch))
        strengthened["tables"][0]["cells"][0]["english"] = "Launch approved"
        with self.assertRaises(KSlideError) as raised:
            parse_translation_patch(strengthened).validate_against(evidence)
        self.assertEqual(raised.exception.code, ErrorCode.MODALITY_MISMATCH)

    def test_executive_claim_modality_is_bound_to_cited_source_and_conflicts_stay_explicit(self) -> None:
        def evidence_for(source_text: str) -> EvidenceIR:
            return EvidenceIR(
                "doc",
                "unit",
                {"source_language_policy": "unicode-script-v1"},
                regions=(EvidenceRegion("unit-r", selected_literal_candidate=source_text, language="ko"),),
                required_source_ids=("unit-r",),
            ).with_revision()

        evidence = evidence_for("검토 중")
        base = _patch(evidence, region_text="Under review", status="under_review", speech="status")

        def claim(text: str, **changes: object) -> dict[str, object]:
            value: dict[str, object] = {
                "claim_id": "decision",
                "kind": "decision_status",
                "text": text,
                "evidence_ids": ["unit-r"],
                "uncertainty": "low",
                "provenance": "supported_interpretation",
            }
            value.update(changes)
            return value

        compatible = {**base, "executive_claims": [claim("Launch remains under review")]}
        parse_translation_patch(compatible).validate_against(evidence)
        parse_translation_patch({**base, "executive_claims": [claim("Launch remains under review and is not approved")]}).validate_against(evidence)
        for text in ("Launch approved", "Launch decided", "Launch committed"):
            with self.subTest(text=text):
                invalid = {**base, "executive_claims": [claim(text)]}
                with self.assertRaises(KSlideError) as raised:
                    parse_translation_patch(invalid).validate_against(evidence)
                self.assertEqual(raised.exception.code, ErrorCode.MODALITY_MISMATCH)

        planned_evidence = evidence_for("출시 계획")
        planned_base = _patch(planned_evidence, region_text="Launch planned", status="planned", speech="plan")
        for text in ("Launch is scheduled", "Launch status"):
            with self.subTest(text=text):
                invalid = {**planned_base, "executive_claims": [claim(text)]}
                with self.assertRaises(KSlideError) as raised:
                    parse_translation_patch(invalid).validate_against(planned_evidence)
                self.assertEqual(raised.exception.code, ErrorCode.MODALITY_MISMATCH)
        with self.assertRaises(KSlideError) as raised:
            parse_translation_patch({**planned_base, "executive_claims": [claim("Launch in Q3", kind="timing")]}).validate_against(planned_evidence)
        self.assertEqual(raised.exception.code, ErrorCode.MODALITY_MISMATCH)
        parse_translation_patch({**planned_base, "executive_claims": [claim("Launch remains planned")]}).validate_against(planned_evidence)

        conflicted_evidence = evidence_for("검토 중 및 계획")
        conflicted_base = _patch(conflicted_evidence, region_text="Under review and planned")
        fully_bound = {**conflicted_base, "executive_claims": [claim("Launch is under review and planned", uncertainty="high")]}
        parse_translation_patch(fully_bound).validate_against(conflicted_evidence)
        for invalid_claim in (
            claim("Launch is under review", uncertainty="high", provenance="supported_interpretation"),
            claim("Launch is under review and planned", uncertainty="high", provenance=None),
        ):
            invalid = {**conflicted_base, "executive_claims": [invalid_claim]}
            with self.assertRaises(KSlideError) as raised:
                parse_translation_patch(invalid).validate_against(conflicted_evidence)
            self.assertEqual(raised.exception.code, ErrorCode.MODALITY_MISMATCH)

    def test_chart_trend_and_process_direction_are_bound_to_engine_evidence(self) -> None:
        chart = {"element_id": "unit-chart", "kind": "chart", "bbox_px": [0, 0, 100, 100], "required": True, "chart": {"chart_type": "line", "title": "Revenue", "categories": ["Q1", "Q2", "Q3"], "series": [{"series_index": 0, "name": "Revenue", "points": [{"point_index": 0, "value": 1.0, "is_blank": False}, {"point_index": 1, "value": 2.0, "is_blank": False}, {"point_index": 2, "value": 3.0, "is_blank": False}]}]}}
        evidence = EvidenceIR("doc", "unit", {}, regions=(EvidenceRegion("unit-r", selected_literal_candidate="Chart"),), visual_elements=(chart,), required_source_ids=("unit-r", "unit-chart")).with_revision()
        reversed_patch = _patch(evidence, region_text="Chart", relation={"relation_id": "trend", "interpretation": "The trend is declining", "evidence_ids": ["unit-chart"], "source_element_ids": ["unit-chart"], "provenance": "supported_interpretation"})
        # Free chart prose remains a bounded interpretation. Deterministic
        # trend/value facts require the closed chart_claim contract exercised
        # by the F24 repair tests.
        parse_translation_patch(reversed_patch).validate_against(evidence)

        process = (
            {"element_id": "unit-a", "kind": "shape", "bbox_px": [0, 0, 10, 10], "required": True},
            {"element_id": "unit-b", "kind": "shape", "bbox_px": [20, 0, 30, 10], "required": True},
            {"element_id": "unit-edge", "kind": "connector", "bbox_px": [10, 5, 20, 5], "required": True, "connector": {"from_element_id": "unit-a", "to_element_id": "unit-b", "start_arrow_type": "none", "end_arrow_type": "triangle", "direction_evidence": "start_to_end"}},
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
