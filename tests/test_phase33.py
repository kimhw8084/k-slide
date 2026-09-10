from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from evals.certification import EvaluationState, ModelPolicy, certification_fingerprint, certification_status, certification_stale, corpus_fingerprint, held_out_fingerprint
from evals.deck_scenarios import deck_scenarios
from evals.experiments import compare_aggregate
from evals.model_eval import collect_run_artifacts
from evals.model_results import aggregate_model_results
from evals.model_scorers import score_deck_consistency, score_translation_patch
from evals.opencode_events import media_compliance, normalize_events, work_unit_media_traces
from evals.scenarios import EXPECTED_CORPUS_FINGERPRINT_V1, EXPECTED_HELD_OUT_FINGERPRINT_V1, scenario_specs
from k_slide.evidence_ir import EvidenceIR, EvidenceRegion, EvidenceTable, EvidenceTableCell, save_evidence
from k_slide.ir import SlideIR


def _events_for_unit(unit: str, *, missing_crop: bool = False):
    context = f".k-slide-runs/run/{unit}/context.png"
    crop = f".k-slide-runs/run/{unit}/r1.png"
    plan = {"work_unit_id": unit, "evidence_revision": "a" * 64, "model_media_plan": {"context_image": {"path": context, "required": True}, "required_crops": [{"region_id": "r1", "path": crop}]}}
    events = [
        {"type": "tool_result", "tool": "kslide_next", "output": json.dumps({"status": "READY", "work_unit_id": unit})},
        {"type": "tool_result", "tool": "kslide_evidence", "output": json.dumps(plan)},
        {"type": "tool_use", "part": {"type": "tool", "tool": "read", "state": {"input": {"filePath": f"/workspace/{context}"}}}},
    ]
    if not missing_crop:
        events.append({"type": "tool_use", "part": {"type": "tool", "tool": "read", "state": {"input": {"filePath": f"/workspace/{crop}"}}}})
    events.append({"type": "tool_use", "part": {"type": "tool", "tool": "kslide_submit", "state": {"input": {"work_unit_id": unit}}}})
    return events


def _evidence(work_unit: str = "u1", source: str = "검토") -> EvidenceIR:
    return EvidenceIR("doc-001", work_unit, {"width_px": 1000, "height_px": 600}, (EvidenceRegion(f"{work_unit}-r1", selected_literal_candidate=source),), required_source_ids=(f"{work_unit}-r1",)).with_revision()


class Phase33CertificationTests(unittest.TestCase):
    def test_champion_uses_real_category_keys_and_protected_metrics(self):
        baseline = {"split": "validation", "target_model_approved": True, "quality_metrics_authoritative": True, "critical_failure_count": 0, "critical_failure_types": [], "mean_scores": {"coverage": 1.0}, "by_category": {"financial_table": {"numeric_fidelity": 1.0, "table_cell_fidelity": 1.0, "coverage": 1.0}}}
        candidate = {**baseline, "mean_scores": {"coverage": 1.1}, "by_category": {"financial_table": {"numeric_fidelity": 1.0, "table_cell_fidelity": 0.98, "coverage": 1.0}}}
        result = compare_aggregate(baseline, candidate)
        self.assertIn("financial_table", result["protected_regressions"])
        self.assertIn("table_cell_fidelity", result["protected_regressions"]["financial_table"])
        self.assertFalse(result["accepted"])

    def test_modality_category_regression_is_protected(self):
        baseline = {"split": "validation", "target_model_approved": True, "quality_metrics_authoritative": True, "mean_scores": {"coverage": 1}, "by_category": {"modality_decision_state": {"modality": 1.0, "coverage": 1.0}}}
        candidate = {**baseline, "mean_scores": {"coverage": 1.1}, "by_category": {"modality_decision_state": {"modality": 0.9, "coverage": 1.0}}}
        self.assertFalse(compare_aggregate(baseline, candidate)["accepted"])

    def test_measurement_state_is_not_pass(self):
        self.assertEqual(certification_status(authoritative=True, critical_failures=1), EvaluationState.CERTIFICATION_FAIL)
        self.assertEqual(certification_status(authoritative=True, critical_failures=0), EvaluationState.MEASURED)

    def test_model_policy_requires_approved_effective_identity(self):
        policy = ModelPolicy.from_mapping({"approved_model_ids": ["google/gemma-4-31b-it"], "approved_aliases": ["corp/gemma-prod"]})
        self.assertFalse(policy.approved(requested="corp/gemma-prod", effective="corp/gemma-prod"))
        mapped = ModelPolicy.from_mapping({"approved_model_ids": ["google/gemma-4-31b-it"], "approved_aliases": ["corp/gemma-prod"], "approved_alias_targets": {"corp/gemma-prod": ["google/gemma-4-31b-it"]}})
        self.assertTrue(mapped.approved(requested="corp/gemma-prod", effective="google/gemma-4-31b-it"))
        self.assertFalse(policy.approved(requested="corp/gemma-prod", effective="ollama/qwen3:14b"))
        self.assertFalse(policy.approved(requested="unknown/gemma", effective="unknown/gemma"))

    def test_certification_fingerprint_becomes_stale_on_config_change(self):
        config = {"model": "google/gemma-4-31b-it", "prompt": "v1"}
        self.assertFalse(certification_stale(certification_fingerprint(config), config))
        self.assertTrue(certification_stale(certification_fingerprint(config), {**config, "prompt": "v2"}))

    def test_media_compliance_is_bound_per_work_unit(self):
        events = normalize_events(_events_for_unit("u1") + _events_for_unit("u2"))
        traces = work_unit_media_traces(events)
        self.assertEqual(set(traces), {"u1", "u2"})
        self.assertTrue(all(value["media_sequence_valid"] for value in traces.values()))
        self.assertTrue(media_compliance(events)["media_sequence_valid"])

    def test_missing_crop_fails_only_its_work_unit(self):
        events = normalize_events(_events_for_unit("u1") + _events_for_unit("u2", missing_crop=True))
        traces = work_unit_media_traces(events)
        self.assertTrue(traces["u1"]["media_sequence_valid"])
        self.assertFalse(traces["u2"]["media_sequence_valid"])

    def test_forbidden_tool_is_scoped_to_its_work_unit(self):
        first = _events_for_unit("u1")
        second = _events_for_unit("u2")
        second.insert(-1, {"type": "tool_use", "part": {"type": "tool", "tool": "bash", "state": {"input": {"cmd": "id"}}}})
        traces = work_unit_media_traces(normalize_events(first + second))
        self.assertEqual(traces["u1"]["forbidden_tool_attempts"], [])
        self.assertEqual(traces["u2"]["forbidden_tool_attempts"], ["bash"])

    def test_model_collector_loads_all_translation_patches(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            (run / "translations").mkdir()
            (run / "ir").mkdir()
            for index in (1, 2):
                evidence = _evidence(f"u{index}")
                save_evidence(run, evidence)
                patch = {"schema_version": "1.0", "work_unit_id": f"u{index}", "evidence_revision": evidence.evidence_revision, "regions": [{"region_id": f"u{index}-r1", "english": "Review", "unresolved": False}], "tables": [], "visual_interpretations": [], "executive_claims": []}
                (run / "translations" / f"u{index}.json").write_text(json.dumps(patch), encoding="utf-8")
                (run / "ir" / f"u{index}.json").write_text(json.dumps(SlideIR(slide_id=f"u{index}").as_dict()), encoding="utf-8")
            self.assertEqual({item["work_unit_id"] for item in collect_run_artifacts(run)}, {"u1", "u2"})

    def test_clean_unresolved_is_unexpected_but_degraded_unresolved_is_allowed(self):
        evidence = _evidence()
        patch = {"regions": [{"region_id": "u1-r1", "english": "[unreadable]", "unresolved": True, "unresolved_reason": "blurred"}]}
        clean = type("Scenario", (), {"gold": {}})()
        degraded = type("Scenario", (), {"gold": {"allowed_unresolved": True, "expected_unresolved_max": 1}})()
        self.assertIn("UNEXPECTED_UNRESOLVED", score_translation_patch(clean, evidence, patch)["critical_failures"])
        self.assertNotIn("UNEXPECTED_UNRESOLVED", score_translation_patch(degraded, evidence, patch)["critical_failures"])

    def test_modality_does_not_fallback_to_unrelated_region(self):
        evidence = EvidenceIR("doc", "u", {}, (EvidenceRegion("r1", selected_literal_candidate="다른 문구"), EvidenceRegion("r2", selected_literal_candidate="2H 적용 예정")), required_source_ids=("r1", "r2")).with_revision()
        scenario = type("Scenario", (), {"gold": {"modality": {"source_text": "2H 적용 검토", "commitment": "under_review", "speech_act": "plan"}}})()
        patch = {"regions": [{"region_id": "r1", "english": "Other", "commitment_status": "unknown"}, {"region_id": "r2", "english": "Scheduled", "commitment_status": "scheduled"}]}
        score = score_translation_patch(scenario, evidence, patch)
        self.assertIn("SCORER_SOURCE_BINDING_FAILURE", score["critical_failures"])

    def test_repeated_critical_frequency_is_computed(self):
        rows = [{"scenario_id": "s1", "format": "png", "category": "financial_table", "semantic_scored": True, "semantic": {"coverage": 1, "critical_failures": (["CRITICAL"] if index == 0 else [])}, "status": "PASS", "quality_metrics_authoritative": True, "engine_gate": "PASS"} for index in range(5)]
        summary = aggregate_model_results(rows, model="google/gemma-4-31b-it", split="validation")
        self.assertEqual(summary["stability_groups"]["s1/png"]["critical_frequency"], 0.2)

    def test_authoritative_critical_measurement_is_certification_failure(self):
        rows = [{"scenario_id": "s1", "format": "png", "category": "modality_decision_state", "semantic_scored": True, "semantic": {"coverage": 1, "critical_failures": ["CRITICAL_MODALITY_MISMATCH"]}, "status": "PASS", "quality_metrics_authoritative": True, "engine_gate": "PASS", "opencode": {"mode": "quality"}}]
        summary = aggregate_model_results(rows, model="google/gemma-4-31b-it", split="validation")
        self.assertEqual(summary["evaluation_state"], EvaluationState.CERTIFICATION_FAIL.value)

    def test_corpus_and_heldout_fingerprints_are_stable_and_gold_sensitive(self):
        scenarios = scenario_specs()
        self.assertEqual(corpus_fingerprint(scenarios), EXPECTED_CORPUS_FINGERPRINT_V1)
        self.assertEqual(held_out_fingerprint(scenarios), EXPECTED_HELD_OUT_FINGERPRINT_V1)
        changed = list(scenarios)
        changed[0] = type(scenarios[0])(**{**scenarios[0].as_dict(), "gold": {"changed": True}})
        self.assertNotEqual(corpus_fingerprint(changed), EXPECTED_CORPUS_FINGERPRINT_V1)

    def test_table_wrong_header_semantics_fails(self):
        table = EvidenceTable("t1", row_count=1, column_count=1, cells=(EvidenceTableCell("c1", 0, 0, source_text="매출"),))
        evidence = EvidenceIR("doc", "u", {}, (), (table,), required_source_ids=("t1", "c1")).with_revision()
        scenario = type("Scenario", (), {"gold": {"table": {"header_roles": [{"row": 0, "column": 0, "source": "매출", "acceptable": ["revenue"]}]}}})()
        score = score_translation_patch(scenario, evidence, {"regions": [], "tables": [{"table_id": "t1", "cells": [{"cell_id": "c1", "english": "Operating profit", "unresolved": False}]}]})
        self.assertIn("TABLE_HEADER_SEMANTIC_FAILURE", score["critical_failures"])

    def test_chart_trend_reversal_fails(self):
        evidence = _evidence()
        scenario = type("Scenario", (), {"gold": {"chart": {"trend": "increasing"}}})()
        patch = {"regions": [{"region_id": "u1-r1", "english": "Chart", "unresolved": False}], "visual_interpretations": [{"relation_id": "trend", "interpretation": "The trend is declining", "evidence_ids": ["u1-r1"]}]}
        self.assertIn("CRITICAL_TREND_REVERSAL", score_translation_patch(scenario, evidence, patch)["critical_failures"])

    def test_process_wrong_edge_direction_fails(self):
        evidence = _evidence()
        scenario = type("Scenario", (), {"gold": {"process": {"relations": [{"from": "step-1", "to": "step-2", "type": "next"}]}}})()
        patch = {"regions": [{"region_id": "u1-r1", "english": "Process", "unresolved": False}], "visual_interpretations": [{"relation_id": "r", "source_element_ids": ["step-2", "step-1"], "relation_type": "next", "interpretation": "reverse", "evidence_ids": ["u1-r1"]}]}
        self.assertIn("PROCESS_RELATION_MISMATCH", score_translation_patch(scenario, evidence, patch)["critical_failures"])

    def test_multislide_term_consistency(self):
        result = score_deck_consistency([{"regions": [{"english": "AI Platform"}]}, {"regions": [{"english": "AI platform"}]}, {"regions": [{"english": "AI system"}]}], {"locked_term": "AI Platform"})
        self.assertEqual(result["inconsistent_alternate_count"], 2)

    def test_deck_scenarios_are_real_resume_inputs(self):
        self.assertEqual([item.slide_count for item in deck_scenarios()], [3, 5, 10, 20, 50])


if __name__ == "__main__":
    unittest.main()
