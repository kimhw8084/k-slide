from __future__ import annotations

import json
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace

from k_slide.cli import _conflict_assess, _next, _submit
from k_slide.errors import ErrorCode, KSlideError
from k_slide.evidence_ir import EvidenceIR, EvidenceRegion
from k_slide.extraction import _tables
from k_slide.ingest import prepare_run
from k_slide.normalization import _connector_endpoints, _pptx_native
from k_slide.translation import parse_translation_patch
from k_slide.verify import finalize_run, verify_run
from tests.reference_fixtures import reference_environment


FIXTURES = Path(__file__).parent / "fixtures"


def _evidence(visual_elements: tuple[dict, ...] = (), *, source_text: str = "Visual", language: str | None = None) -> EvidenceIR:
    return EvidenceIR(
        "doc",
        "unit",
        {},
        regions=(EvidenceRegion("unit-r", selected_literal_candidate=source_text, language=language),),
        visual_elements=visual_elements,
        required_source_ids=("unit-r", *(item["element_id"] for item in visual_elements)),
    ).with_revision()


def _patch(evidence: EvidenceIR, *, relation: dict | None = None, english: str = "Visual", region: dict | None = None) -> dict:
    return {
        "schema_version": "1.0",
        "work_unit_id": evidence.work_unit_id,
        "evidence_revision": evidence.evidence_revision,
        "regions": [region or {"region_id": "unit-r", "english": english, "term_ids": [], "unresolved": False}],
        "tables": [],
        "visual_interpretations": [relation] if relation else [],
        "executive_claims": [],
    }


class KSA24F24RepairTests(unittest.TestCase):
    def test_connector_direction_requires_arrow_proof_and_handles_grouped_shapes(self) -> None:
        fixture = json.loads((FIXTURES / "ksa24_connector_fixture.json").read_text(encoding="utf-8"))
        evidence = _evidence(tuple(fixture["elements"] + fixture["connectors"]))

        def relation(edge: str, endpoints: tuple[str, str], direction: str, provenance: str = "source_fact") -> dict:
            return {"relation_id": edge, "interpretation": "flow", "evidence_ids": [edge], "source_element_ids": [*endpoints, edge], "relation_type": "next", "direction": direction, "provenance": provenance}

        with self.assertRaises(KSlideError) as raised:
            parse_translation_patch(_patch(evidence, relation=relation("fixture-no-arrow", ("fixture-group-a", "fixture-group-b"), "left_to_right"))).validate_against(evidence)
        self.assertEqual(raised.exception.code, ErrorCode.SCHEMA_INVALID)
        parse_translation_patch(_patch(evidence, relation=relation("fixture-end-arrow", ("fixture-a", "fixture-b"), "left_to_right"))).validate_against(evidence)
        parse_translation_patch(_patch(evidence, relation=relation("fixture-start-arrow", ("fixture-b", "fixture-a"), "right_to_left"))).validate_against(evidence)
        for bad in (
            relation("fixture-start-arrow", ("fixture-a", "fixture-b"), "left_to_right"),
            relation("fixture-bidirectional", ("fixture-a", "fixture-b"), "left_to_right"),
            relation("fixture-ambiguous", ("fixture-a", "fixture-b"), "left_to_right"),
        ):
            with self.subTest(relation=bad["relation_id"]):
                with self.assertRaises(KSlideError):
                    parse_translation_patch(_patch(evidence, relation=bad)).validate_against(evidence)
        parse_translation_patch(_patch(evidence, relation=relation("fixture-bidirectional", ("fixture-a", "fixture-b"), "bidirectional"))).validate_against(evidence)
        parse_translation_patch(_patch(evidence, relation=relation("fixture-no-arrow", ("fixture-group-a", "fixture-group-b"), "left_to_right", "supported_interpretation"))).validate_against(evidence)

    def test_normalizer_reads_ooxml_head_and_tail_arrowheads(self) -> None:
        xml = ET.fromstring(
            '<p:cxnSp xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">'
            '<p:nvCxnSpPr><p:cNvCxnSpPr><a:stCxn id="1"/><a:endCxn id="2"/></p:cNvCxnSpPr></p:nvCxnSpPr>'
            '<p:spPr><a:ln><a:headEnd type="triangle"/><a:tailEnd type="none"/></a:ln></p:spPr></p:cxnSp>'
        )
        result = _connector_endpoints(SimpleNamespace(_element=xml), {1: "a", 2: "b"})
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["direction_evidence"], "end_to_start")
        self.assertEqual(result["start_arrow_type"], "triangle")
        self.assertEqual(result["end_arrow_type"], "none")

    def test_chart_claims_are_closed_per_series_point_and_category(self) -> None:
        chart = json.loads((FIXTURES / "ksa24_chart_claim_fixture.json").read_text(encoding="utf-8"))
        evidence = _evidence((chart,))

        def claim(**changes: object) -> dict:
            value = {"chart_element_id": "fixture-chart", "kind": "trend", "series_index": 0, "series_name": "North", "direction": "increasing"}
            value.update(changes)
            return value

        def chart_relation(chart_claim: dict | None, *, provenance: str = "source_fact", text: str = "North is increasing") -> dict:
            value = {"relation_id": "trend", "interpretation": text, "evidence_ids": ["fixture-chart"], "source_element_ids": ["fixture-chart"], "provenance": provenance}
            if chart_claim is not None:
                value["chart_claim"] = chart_claim
            return value

        parse_translation_patch(_patch(evidence, relation=chart_relation(claim()))).validate_against(evidence)
        parse_translation_patch(_patch(evidence, relation=chart_relation(claim(series_index=1, series_name="South", direction="decreasing")))).validate_against(evidence)
        parse_translation_patch(_patch(evidence, relation=chart_relation(claim(series_index=2, series_name="Flat", direction="flat")))).validate_against(evidence)
        for bad in (claim(series_index=1), claim(series_name="South"), claim(direction="decreasing")):
            with self.assertRaises(KSlideError):
                parse_translation_patch(_patch(evidence, relation=chart_relation(bad))).validate_against(evidence)

        point = {"chart_element_id": "fixture-chart", "kind": "point_value", "series_index": 0, "series_name": "North", "point_index": 0, "category": "Q1", "value": -1234.5}
        parse_translation_patch(_patch(evidence, relation=chart_relation(point, text="North is -1,234.5%"))).validate_against(evidence)
        for bad in (
            {**point, "value": -1234.4},
            {**point, "category": "Q2"},
            {**point, "value": -1234.5, "direction": "increasing"},
        ):
            with self.assertRaises(KSlideError):
                parse_translation_patch(_patch(evidence, relation=chart_relation(bad))).validate_against(evidence)

        blank = {"chart_element_id": "fixture-chart", "kind": "point_value", "series_index": 3, "series_name": "Nullable", "point_index": 1, "category": "Q2", "is_blank": True}
        parse_translation_patch(_patch(evidence, relation=chart_relation(blank))).validate_against(evidence)
        with self.assertRaises(KSlideError):
            parse_translation_patch(_patch(evidence, relation=chart_relation({**blank, "value": 0}))).validate_against(evidence)
        with self.assertRaises(KSlideError):
            parse_translation_patch(_patch(evidence, relation=chart_relation(claim(series_index=3, series_name="Nullable", direction="increasing")))).validate_against(evidence)

        ranking = {"chart_element_id": "fixture-chart", "kind": "ranking", "series_index": 0, "series_name": "North", "point_index": 0, "category": "Q1", "ranking": "lowest", "rank": 1}
        parse_translation_patch(_patch(evidence, relation=chart_relation(ranking))).validate_against(evidence)
        comparison = {"chart_element_id": "fixture-chart", "kind": "comparison", "series_index": 0, "series_name": "North", "point_index": 0, "category": "Q1", "other_series_index": 1, "other_series_name": "South", "operator": "less_than"}
        parse_translation_patch(_patch(evidence, relation=chart_relation(comparison))).validate_against(evidence)
        with self.assertRaises(KSlideError):
            parse_translation_patch(_patch(evidence, relation=chart_relation({**comparison, "operator": "greater_than"}))).validate_against(evidence)

        # Free prose remains supported interpretation, but source_fact chart
        # prose without the exact closed claim is not admitted.
        parse_translation_patch(_patch(evidence, relation=chart_relation(None, provenance="supported_interpretation", text="North falls while South rises"))).validate_against(evidence)
        with self.assertRaises(KSlideError):
            parse_translation_patch(_patch(evidence, relation=chart_relation(None))).validate_against(evidence)

    def test_modality_metadata_and_english_strength_guard_are_non_bypassable(self) -> None:
        cases = (("결정", "decided", "decision", "The decision is decided."), ("약속", "committed", "status", "The work is committed."), ("계획", "planned", "status", "The work is planned."), ("예정", "scheduled", "status", "The work is scheduled."), ("목표", "target", "status", "The target is the target."), ("제안", "proposed", "status", "The proposal is proposed."), ("검토 중", "under_review", "status", "The work is under review."), ("가능", "possible", "status", "The work is possible."), ("전망", "forecast", "status", "The forecast is projected."), ("잠정", "tentative", "status", "The result is tentative."), ("완료", "completed", "status", "The work is completed."), ("진행 중", "in_progress", "status", "The work is in progress."))
        for source_text, status, speech, english in cases:
            with self.subTest(source_text=source_text):
                evidence = _evidence((), source_text=source_text, language="ko")
                region = {"region_id": "unit-r", "english": english, "term_ids": [], "unresolved": False, "commitment_status": status, "speech_act": speech, "evidence_ids": ["unit-r"]}
                parse_translation_patch(_patch(evidence, region=region)).validate_against(evidence)
                omitted = dict(region)
                omitted.pop("commitment_status")
                with self.assertRaises(KSlideError):
                    parse_translation_patch(_patch(evidence, region=omitted)).validate_against(evidence)

        for source_text, wrong_status in (("계획", "committed"), ("예정", "decided"), ("목표", "decided"), ("검토 중", "decided"), ("가능", "committed"), ("전망", "decided"), ("제안", "decided"), ("잠정", "planned")):
            evidence = _evidence((), source_text=source_text, language="ko")
            region = {"region_id": "unit-r", "english": "The work is approved.", "term_ids": [], "unresolved": False, "commitment_status": wrong_status, "speech_act": "decision", "evidence_ids": ["unit-r"]}
            with self.subTest(source_text=source_text):
                with self.assertRaises(KSlideError):
                    parse_translation_patch(_patch(evidence, region=region)).validate_against(evidence)

        evidence = _evidence((), source_text="결정", language="ko")
        missing_speech = {"region_id": "unit-r", "english": "The decision is approved.", "term_ids": [], "unresolved": False, "commitment_status": "decided", "evidence_ids": ["unit-r"]}
        with self.assertRaises(KSlideError):
            parse_translation_patch(_patch(evidence, region=missing_speech)).validate_against(evidence)
        evidence = _evidence((), source_text="검토 중", language="ko")
        strengthened = {"region_id": "unit-r", "english": "The work is approved.", "term_ids": [], "unresolved": False, "commitment_status": "under_review", "speech_act": "status", "evidence_ids": ["unit-r"]}
        with self.assertRaises(KSlideError):
            parse_translation_patch(_patch(evidence, region=strengthened)).validate_against(evidence)
        # Ambiguous wording is outside the deterministic guard.
        ambiguous = _evidence((), source_text="검토", language="ko")
        parse_translation_patch(_patch(ambiguous, region={"region_id": "unit-r", "english": "Review", "term_ids": [], "unresolved": False})).validate_against(ambiguous)

    def test_table_units_are_header_or_note_scoped_and_blanks_are_structural(self) -> None:
        cells = [
            {"cell_id": "t-r0-c0", "row": 0, "column": 0, "text": "KRW 억", "is_header": True},
            {"cell_id": "t-r0-c1", "row": 0, "column": 1, "text": "   ", "is_header": True},
            {"cell_id": "t-r1-c0", "row": 1, "column": 0, "text": "5", "is_header": False},
            {"cell_id": "t-r1-c1", "row": 1, "column": 1, "text": "\t", "is_header": False},
            {"cell_id": "t-r2-c0", "row": 2, "column": 0, "text": None, "is_spanned": True, "is_merge_origin": False},
            {"cell_id": "t-r2-c1", "row": 2, "column": 1, "text": "", "is_header": False},
        ]
        tables, facts = _tables(SimpleNamespace(work_unit_id="unit"), [{"source_id": "shape", "table": {"row_count": 3, "column_count": 2, "header_rows": [0], "cells": cells}}])
        self.assertEqual(tables[0].unit, "KRW 억")
        self.assertEqual(tables[0].cells[1].source_text, "")
        self.assertEqual(tables[0].cells[1].cell_state, "blank")
        self.assertEqual(tables[0].cells[4].source_text, None)
        self.assertEqual(tables[0].cells[4].cell_state, "merge_continuation")
        numeric = next(fact for fact in facts if fact.get("source_cell_id") == "t-r1-c0")
        self.assertEqual(numeric["source_unit"], "KRW 억")
        self.assertEqual(numeric["canonical_value"], 5 * 10**8)
        self.assertEqual(numeric["currency"], "KRW")

        ambiguous = [
            {"cell_id": "a-r0-c0", "row": 0, "column": 0, "text": "USD millions", "is_header": True},
            {"cell_id": "a-r0-c1", "row": 0, "column": 1, "text": "KRW 억", "is_header": True},
            {"cell_id": "a-r1-c0", "row": 1, "column": 0, "text": "5", "is_header": False},
            {"cell_id": "a-r1-c1", "row": 1, "column": 1, "text": "6", "is_header": False},
        ]
        tables, facts = _tables(SimpleNamespace(work_unit_id="unit"), [{"source_id": "shape", "table": {"row_count": 2, "column_count": 2, "header_rows": [0], "cells": ambiguous}}])
        self.assertIsNone(tables[0].unit)
        self.assertIsNone(next(fact for fact in facts if fact.get("source_cell_id") == "a-r1-c0").get("source_unit"))

    def test_real_pptx_native_table_path_emits_unit_and_blank(self) -> None:
        try:
            from PIL import Image
            from pptx import Presentation
            from pptx.util import Inches
        except ImportError:
            self.skipTest("PPTX normalization dependencies are unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            presentation = Presentation()
            slide = presentation.slides.add_slide(presentation.slide_layouts[6])
            shape = slide.shapes.add_table(3, 2, Inches(1), Inches(1), Inches(5), Inches(2))
            table = shape.table
            table._tbl.tblPr.set("firstRow", "1")
            table.cell(0, 0).text = "USD millions"
            table.cell(0, 1).text = "Metric"
            table.cell(1, 0).text = "1.5"
            table.cell(1, 1).text = "   "
            table.cell(2, 0).text = "Revenue"
            table.cell(2, 1).text = "2"
            source = root / "fixture.pptx"
            presentation.save(source)
            render = root / "run" / "normalized" / "slide.png"
            render.parent.mkdir(parents=True)
            Image.new("RGB", (1280, 720), "white").save(render)
            units = _pptx_native(source, root / "run", "source-001", "doc-001", [render])
            native_table = next(item["table"] for item in units[0].native_evidence if "table" in item)
            self.assertEqual(native_table["unit"], "USD millions")
            whitespace = next(cell for cell in native_table["cells"] if cell["row"] == 1 and cell["column"] == 1)
            self.assertTrue(whitespace["is_blank"])
            tables, _facts = _tables(units[0], units[0].native_evidence)
            self.assertEqual(tables[0].cells[3].cell_state, "blank")

    def test_typed_runtime_submit_conflict_assess_verify_finalize(self) -> None:
        try:
            from PIL import Image
        except ImportError:
            self.skipTest("Pillow is unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "slide.png"
            Image.new("RGB", (40, 40), "white").save(source)
            environment = reference_environment("ksa24-f24")
            run = prepare_run(root, explicit_paths=[str(source)], perform_processing=True, environment_identity=environment)
            next_value = _next(root, run.name, None, environment)
            self.assertEqual(next_value["status"], "READY")
            evidence = json.loads((run / "evidence" / f"{next_value['work_unit_id']}.json").read_text(encoding="utf-8"))
            payload = {"schema_version": "1.0", "work_unit_id": next_value["work_unit_id"], "evidence_revision": evidence["evidence_revision"], "regions": [{"region_id": evidence["regions"][0]["region_id"], "english": "", "term_ids": [], "unresolved": False}], "tables": [], "visual_interpretations": [], "executive_claims": []}
            self.assertEqual(_submit(root, run.name, json.dumps(payload), None, environment)["status"], "ACCEPTED")
            self.assertEqual(_conflict_assess(root, run.name, '{"schema_version":"1.0","candidate_groups":[]}', None, environment)["status"], "ASSESSED_ZERO_CONFLICTS")
            verified = verify_run(run, environment_identity=environment)
            self.assertTrue(verified.passed, verified.as_dict())
            completed = finalize_run(run, environment_identity=environment)
            self.assertTrue(completed.passed)
            self.assertTrue((run / "RUN_COMPLETE.md").is_file())


if __name__ == "__main__":
    unittest.main()
