from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from evals.deck_scenarios import deck_scenarios
from evals.gold_binding import bind_gold_roles
from evals.opencode_events import media_compliance, normalize_events, work_unit_media_traces
from evals.opencode_diagnostics import run_diagnostic_ladder
from k_slide.errors import ErrorCode, KSlideError
from k_slide import TRANSLATION_PATCH_SCHEMA_VERSION
from k_slide.evidence_ir import EvidenceIR, EvidenceRegion, EvidenceTable, EvidenceTableCell
from k_slide.ocr.policy import OCRProviderPolicy, create_ocr_provider
from k_slide.translation import parse_translation_patch


ROOT = Path(__file__).resolve().parents[1]


def _evidence() -> EvidenceIR:
    return EvidenceIR(
        "doc-001",
        "doc-001-slide-0001",
        {"width_px": 1000, "height_px": 600},
        regions=(EvidenceRegion("doc-001-slide-0001-r001", selected_literal_candidate="검토"),),
        tables=(EvidenceTable("doc-001-slide-0001-table-001", row_count=1, column_count=1, cells=(EvidenceTableCell("doc-001-slide-0001-table-001-r01-c01", 0, 0, source_text="매출"),)),),
        visual_elements=(
            {"element_id": "doc-001-slide-0001-visual-001", "kind": "shape"},
            {"element_id": "doc-001-slide-0001-visual-context", "kind": "context_image"},
        ),
        required_source_ids=("doc-001-slide-0001-r001", "doc-001-slide-0001-table-001", "doc-001-slide-0001-table-001-r01-c01", "doc-001-slide-0001-visual-context"),
    ).with_revision()


def _media_attempt_events(unit: str, suffix: str = "") -> list[dict[str, object]]:
    context = f".k-slide-runs/run/{unit}/context{suffix}.png"
    crop = f".k-slide-runs/run/{unit}/crop{suffix}.png"
    plan = {"work_unit_id": unit, "evidence_revision": "a" * 64, "model_media_plan": {"context_image": {"path": context, "required": True}, "required_crops": [{"region_id": "r1", "path": crop}]}}
    return [
        {"type": "tool_result", "tool": "kslide_evidence", "output": json.dumps(plan)},
        {"type": "tool_use", "part": {"type": "tool", "tool": "read", "state": {"input": {"filePath": f"/workspace/{context}"}}}},
        {"type": "tool_use", "part": {"type": "tool", "tool": "read", "state": {"input": {"filePath": f"/workspace/{crop}"}}}},
        {"type": "tool_use", "part": {"type": "tool", "tool": "kslide_submit", "state": {"input": {"work_unit_id": unit, "repair_revision": suffix or None}}}},
    ]


class Phase34Tests(unittest.TestCase):
    def test_translation_contract_json_python_typescript_parity(self):
        fixture = json.loads((ROOT / "tests" / "fixtures" / "translation_patch_full.json").read_text(encoding="utf-8"))
        evidence = _evidence()
        fixture["evidence_revision"] = evidence.evidence_revision
        patch = parse_translation_patch(fixture)
        patch.validate_against(evidence)
        schema = json.loads((ROOT / "schemas" / "translation-patch.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(schema["properties"]["schema_version"]["const"], patch.schema_version)
        self.assertEqual(schema["properties"]["schema_version"]["const"], TRANSLATION_PATCH_SCHEMA_VERSION)
        try:
            import jsonschema
        except ImportError:
            jsonschema = None
        if jsonschema is not None:
            jsonschema.validate(fixture, schema)
        typescript = (ROOT / ".opencode" / "tools" / "kslide.ts").read_text(encoding="utf-8")
        for field in ("hangul_retention", "source_element_ids", "relation_type", "direction"):
            self.assertIn(field, typescript)

    def test_unknown_source_element_id_rejected(self):
        evidence = _evidence()
        value = {"schema_version": "1.0", "work_unit_id": evidence.work_unit_id, "evidence_revision": evidence.evidence_revision, "regions": [{"region_id": "doc-001-slide-0001-r001", "english": "Review", "term_ids": [], "unresolved": False}], "tables": [{"table_id": "doc-001-slide-0001-table-001", "cells": [{"cell_id": "doc-001-slide-0001-table-001-r01-c01", "english": "Revenue", "unresolved": False}]}], "visual_interpretations": [{"relation_id": "r", "interpretation": "x", "evidence_ids": ["doc-001-slide-0001-r001"], "source_element_ids": ["model-invented-step-1"], "relation_type": "next", "direction": "left_to_right"}], "executive_claims": []}
        with self.assertRaises(KSlideError) as raised:
            parse_translation_patch(value).validate_against(evidence)
        self.assertEqual(raised.exception.code, ErrorCode.UNKNOWN_SOURCE_ELEMENT)

    def test_ocr_policy_none_is_explicit(self):
        selection = create_ocr_provider(OCRProviderPolicy.NONE)
        self.assertEqual(selection.requested, "none")
        self.assertEqual(selection.effective, "none")

    def test_ocr_policy_paddle_requires_capability(self):
        try:
            selection = create_ocr_provider(OCRProviderPolicy.PADDLE)
        except KSlideError as exc:
            self.assertEqual(exc.code, ErrorCode.OCR_PROVIDER_UNAVAILABLE)
        else:
            self.assertEqual(selection.effective, "paddle")

    def test_normal_extraction_uses_configured_ocr_policy(self):
        try:
            from PIL import Image
            from k_slide.ingest import prepare_run
            from k_slide.normalization import normalize_run
            from k_slide.extraction import extract_run
        except ImportError:
            self.skipTest("Pillow is optional")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "slide.png"
            Image.new("RGB", (320, 180), "white").save(source)
            config = root / ".k-slide-config"
            config.mkdir()
            (config / "ocr.local.json").write_text('{"ocr_provider":"none"}\n', encoding="utf-8")
            run = prepare_run(root, explicit_paths=[str(source)])
            normalize_run(run)
            extract_run(run)
            metrics = json.loads((run / "metrics.json").read_text(encoding="utf-8"))
            self.assertEqual(metrics["ocr_policy_requested"], "none")
            self.assertEqual(metrics["ocr_provider_effective"], "none")
            metadata = json.loads((run / "OCR_METADATA.json").read_text(encoding="utf-8"))
            self.assertEqual(metadata["ocr_policy_requested"], "none")
            self.assertEqual(metadata["ocr_provider_effective"], "none")

    def test_media_attempt_history_does_not_overwrite_initial_trace(self):
        events = normalize_events(_media_attempt_events("u1") + _media_attempt_events("u1", "-repair"))
        trace = work_unit_media_traces(events)["u1"]
        self.assertEqual(len(trace["attempts"]), 2)
        self.assertEqual(trace["repair_count"], 1)
        self.assertTrue(trace["attempts"][0]["media_sequence_valid"])
        self.assertTrue(media_compliance(events)["media_sequence_valid"])

    def test_media_attempts_are_bound_to_their_own_unit(self):
        events = normalize_events(_media_attempt_events("u1") + _media_attempt_events("u2"))
        traces = work_unit_media_traces(events)
        self.assertEqual(set(traces), {"u1", "u2"})
        self.assertTrue(all(trace["media_sequence_valid"] for trace in traces.values()))

    def test_process_gold_binding_is_fail_closed(self):
        scenario = next(item for item in __import__("evals.scenarios", fromlist=["scenario_specs"]).scenario_specs() if item.category == "state_resume")
        evidence = EvidenceIR("doc", "u", {}, regions=(EvidenceRegion("u-r1", selected_literal_candidate="진행 중"), EvidenceRegion("u-r2", selected_literal_candidate="검토"), EvidenceRegion("u-r3", selected_literal_candidate="추진"))).with_revision()
        binding = bind_gold_roles(scenario, evidence)
        self.assertTrue(binding.ok)
        self.assertEqual(binding.bindings["step-1"], "u-r1")
        ambiguous = EvidenceIR("doc", "u", {}, regions=(EvidenceRegion("u-r1", selected_literal_candidate="검토"), EvidenceRegion("u-r2", selected_literal_candidate="검토"))).with_revision()
        self.assertFalse(bind_gold_roles(scenario, ambiguous).ok)

    def test_deck_sizes_are_available_for_protocol_input(self):
        decks = deck_scenarios()
        self.assertEqual(next(deck for deck in decks if deck.slide_count == 3).slide_count, 3)
        self.assertEqual(next(deck for deck in decks if deck.slide_count == 5).slide_count, 5)

    def test_diagnostic_ladder_result_schema_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            result = run_diagnostic_ladder(model="missing/model", output=Path(directory), opencode="/missing/opencode", cold_timeout=1, warm_timeout=1)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("levels", result)


if __name__ == "__main__":
    unittest.main()
