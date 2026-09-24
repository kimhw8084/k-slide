from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from evals.model_results import aggregate_model_results, derive_result_hard_gate_findings
from evals.governed_corpus import case_matrix_fingerprint, case_matrix_item_fingerprint
from evals.model_scorers import score_translation_patch
from k_slide.certification import EvidenceValidationError, load_evidence, validate_evidence_payload
from k_slide.evidence_adapters import AdapterError, build_machine_evidence
from k_slide.evidence_ir import EvidenceIR, EvidenceRegion, EvidenceTable, EvidenceTableCell
from k_slide.quality_policy import (
    HARD_GATE_REGISTRY,
    QUALITY_FLOORS,
    QUALITY_POLICY_IDENTITY,
    canonical_policy_bytes,
    classify_hard_gate,
    policy_document,
    policy_identity_record,
    quality_policy_identity,
)
from evals.noncritical_semantics import public_gold_contract_sha256
from tests.test_certification_closure import _model_result_row, _model_sources, _write


def _inject_semantic_gate(row: dict, gate: str) -> None:
    unit = row["units"][0]["semantic"]
    evidence = unit["hard_gate_evidence"]
    gates: list[str]
    if gate == "CRITICAL_NUMERIC_MISMATCH":
        evidence["numeric_mismatch_fact_ids"] = ["fact-1"]
        gates = [gate]
    elif gate == "SILENT_REGION_OMISSION":
        evidence["missing_required_region_ids"] = ["region-1"]
        gates = [gate]
    elif gate == "TABLE_CARDINALITY_MISMATCH":
        evidence["table_cardinality_mismatch"] = True
        evidence["table_failure_codes"] = [gate]
        gates = ["TABLE_CELL_SEMANTIC_FAILURE", gate]
    elif gate == "CRITICAL_MODALITY_MISMATCH":
        evidence["modality_score"] = 0.0
        gates = [gate]
    elif gate == "CRITICAL_TREND_REVERSAL":
        evidence["chart_failure_codes"] = [gate]
        gates = [gate]
    elif gate == "UNSUPPORTED_EXECUTIVE_CLAIM":
        evidence["unsupported_claim_count"] = 1
        evidence["executive_claim_failure_codes"] = [gate]
        gates = [gate]
    elif gate == "SCORER_SOURCE_BINDING_FAILURE":
        evidence["modality_source_binding_failure"] = True
        gates = [gate]
    elif gate == "UNEXPECTED_HANGUL":
        evidence["hangul_violation_count"] = 1
        gates = [gate]
    else:
        raise AssertionError(gate)
    unit["critical_failures"] = gates
    row["semantic"]["critical_failures"] = gates


def _configure_unresolved(row: dict, required_count: int, observed_count: int) -> None:
    """Build source-bound NEEDS_REVIEW truth with optional safe over-review."""

    required = sorted(f"material-{index}" for index in range(required_count))
    observed = required + [f"extra-{index}" for index in range(observed_count - required_count)]
    unit = row["units"][0]["semantic"]
    facts = unit["hard_gate_evidence"]
    facts["material_unresolved_required_ids"] = required
    facts["material_unresolved_observed_ids"] = required
    unit.update({
        "unresolved_ids": observed,
        "unresolved_count": len(observed),
        "material_unresolved_required_ids": required,
        "material_unresolved_observed_ids": required,
        "material_unresolved_false_negative_ids": [],
        "unresolved_false_positive_ids": observed[required_count:],
        "material_unresolved_recall": 1.0,
        "unresolved_precision": required_count / observed_count,
    })
    semantic = row["semantic"]
    semantic.update({
        "material_unresolved_required_count": required_count,
        "material_unresolved_true_positive_count": required_count,
        "unresolved_observed_count": observed_count,
        "unresolved_false_positive_count": observed_count - required_count,
        "material_unresolved_recall": 1.0,
        "unresolved_precision": required_count / observed_count,
        "unresolved_region_rate": 1.0 if observed_count else 0.0,
    })
    row["persisted_execution"].update({
        "run_phase": "NEEDS_REVIEW", "run_complete": False, "reported_run_complete": False,
        "false_done_recovery_violation": False, "verification_status": "NEEDS_REVIEW",
        "work_unit_states": {"u1": "NEEDS_REVIEW"}, "material_unresolved_required_count": required_count,
        "material_unresolved_recall": 1.0, "unresolved_precision": required_count / observed_count,
        "execution_contract_pass": True,
    })
    row["work_unit_contract"]["work_unit_states"] = {"u1": "NEEDS_REVIEW"}
    row["opencode"]["kslide_complete"] = False


def _refresh_model_sources(root: Path, sources: dict[str, Path], rows: list[dict]) -> None:
    experiment = json.loads(sources["experiment_manifest"].read_text(encoding="utf-8"))
    matrix_by_id = {item["item_id"]: item for item in experiment["case_matrix"]}
    rows_by_id: dict[str, list[dict]] = {}
    for row in rows:
        rows_by_id.setdefault(row["scenario_id"], []).append(row)
    for item_id, matrix_item in matrix_by_id.items():
        case_rows = rows_by_id[item_id]
        assertion_ids = case_rows[0]["semantic"]["noncritical_semantic_assertion_ids"]
        if any(row["semantic"]["noncritical_semantic_assertion_ids"] != assertion_ids for row in case_rows):
            raise AssertionError("test rows disagree on bound assertion IDs")
        matrix_item["noncritical_semantic_assertion_ids"] = assertion_ids
        identity = case_matrix_item_fingerprint(matrix_item)
        for row in case_rows:
            row["case_identity_sha256"] = identity
    matrix_hash = case_matrix_fingerprint(experiment["case_matrix"])
    experiment["case_matrix_sha256"] = matrix_hash
    experiment["case_descriptor_identity"]["case_matrix_sha256"] = matrix_hash
    summary = json.loads(sources["model_summary"].read_text(encoding="utf-8"))
    expected_matrix = [(scenario_id, format_name, repeat) for scenario_id in experiment["scenario_ids"] for format_name in experiment["formats"] for repeat in range(1, experiment["repetitions"] + 1)]
    derived = aggregate_model_results(rows, model="google/gemma-4-31b-it", split=summary["split"], expected_matrix=expected_matrix)
    summary.update(derived)
    summary["case_matrix_sha256"] = matrix_hash
    summary["case_descriptor_identity"] = experiment["case_descriptor_identity"]
    (root / "results.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    _write(sources["model_summary"], summary)
    _write(sources["experiment_manifest"], experiment)


def _custom_assertion_case(total: int, correct: int, *, scenario_id: str = "custom-assertions") -> tuple[SimpleNamespace, EvidenceIR, dict]:
    assertions = []
    regions = []
    patch_regions = []
    for index in range(total):
        source_text = f"근거 설명 {index}"
        assertion_id = "ncs-" + hashlib.sha256(f"{scenario_id}:{index}".encode()).hexdigest()[:24]
        assertions.append({
            "assertion_id": assertion_id,
            "surface": "region",
            "source_text": source_text,
            "accepted_phrases": [f"business meaning {index}", f"business interpretation {index}"],
        })
        region_id = f"region-{index:05d}"
        regions.append(EvidenceRegion(region_id, selected_literal_candidate=source_text))
        english = f"business meaning {index}" if index < correct else f"clear adjacent business wording {index}"
        patch_regions.append({"region_id": region_id, "english": english})
    scenario = SimpleNamespace(scenario_id=scenario_id, gold={"noncritical_semantic_assertions": assertions})
    evidence = EvidenceIR("doc", "unit", {}, tuple(regions), required_source_ids=tuple(item.region_id for item in regions)).with_revision()
    score = score_translation_patch(scenario, evidence, {"regions": patch_regions})
    return scenario, evidence, score


def _apply_observations(row: dict, assertion_ids: list[str], correct: int) -> None:
    observations = []
    for index, assertion_id in enumerate(assertion_ids):
        source_object_id = f"anchor-{index:05d}"
        anchor_kind = "region"
        anchor_sha256 = hashlib.sha256(f"u1\0{anchor_kind}\0{source_object_id}".encode()).hexdigest()
        observations.append({
            "assertion_id": assertion_id,
            "source_object_id": source_object_id,
            "anchor_kind": anchor_kind,
            "anchor_sha256": anchor_sha256,
            "outcome": "CORRECT" if index < correct else "INCORRECT",
        })
    for semantic in (row["units"][0]["semantic"], row["semantic"]):
        semantic.update({
            "noncritical_semantic_observations": observations,
            "noncritical_semantic_required_count": len(observations),
            "noncritical_semantic_correct_count": correct,
            "noncritical_semantic_equivalence": correct / len(observations) if observations else 1.0,
        })
    row["semantic"]["noncritical_semantic_assertion_ids"] = assertion_ids


def _bilingual_payload(**overrides) -> dict:
    payload = {
        "attestation_id": "synthetic-ksa27", "artifact_count": 50, "work_unit_count": 200,
        "critical_business_meaning_errors": 0, "critical_numeric_date_unit_errors": 0,
        "critical_modality_escalations": 0, "critical_table_mapping_errors": 0,
        "critical_trend_reversals": 0, "unsupported_critical_executive_claims": 0,
        "overall_noncritical_semantic_fidelity": 0.99, "unresolved_precision": 0.95,
        "material_unresolved_recall": 1.0, "locked_terminology": 0.995,
        "quality_policy": policy_identity_record(), "quality_policy_identity": QUALITY_POLICY_IDENTITY,
    }
    payload.update(overrides)
    return payload


class KSA27QualityPolicyTests(unittest.TestCase):
    def test_policy_identity_is_canonical_and_changes_with_material_policy(self):
        policy = policy_document()
        original = quality_policy_identity(policy)
        reordered = copy.deepcopy(policy)
        reordered["hard_gate_registry"] = {
            key: list(reversed(value)) for key, value in reversed(list(reordered["hard_gate_registry"].items()))
        }
        reordered["floors"] = dict(reversed(list(reordered["floors"].items())))
        self.assertEqual(original, quality_policy_identity(reordered))
        changed_floor = copy.deepcopy(policy)
        changed_floor["floors"]["unresolved_precision_min"] = 0.96
        self.assertNotEqual(original, quality_policy_identity(changed_floor))
        changed_membership = copy.deepcopy(policy)
        changed_membership["hard_gate_registry"]["required_coverage"].remove("SILENT_REGION_OMISSION")
        self.assertNotEqual(original, quality_policy_identity(changed_membership))
        self.assertEqual(QUALITY_POLICY_IDENTITY, original)
        self.assertEqual(policy["policy_version"], "ksa-27.2")
        self.assertEqual(policy["constraints"]["public_noncritical_gold_sha256"], public_gold_contract_sha256())

    def test_public_assertion_sidecar_preserves_ksa26_corpus_fingerprints(self):
        from evals.scenarios import EXPECTED_CORPUS_FINGERPRINT_V1, EXPECTED_HELD_OUT_FINGERPRINT_V1, scenario_specs, split_manifest

        manifest = split_manifest(scenario_specs())
        self.assertEqual(manifest["corpus_fingerprint"], EXPECTED_CORPUS_FINGERPRINT_V1)
        self.assertEqual(manifest["held_out_fingerprint"], EXPECTED_HELD_OUT_FINGERPRINT_V1)

    def test_policy_rejects_unknown_fields_states_and_gate_codes(self):
        for mutate in (
            lambda value: value.update({"ignored": True}),
            lambda value: value["hard_gate_registry"].update({"open_category": ["ANYTHING"]}),
            lambda value: value["hard_gate_registry"]["required_coverage"].append("OPEN_GATE"),
            lambda value: value["constraints"].update({"required_media": "optional_if_score_high"}),
        ):
            altered = policy_document()
            mutate(altered)
            with self.assertRaises(ValueError):
                canonical_policy_bytes(altered)
        self.assertEqual(classify_hard_gate("OPEN_GATE")[0], "UNKNOWN_HARD_GATE_CODE")

    def test_ninety_nine_clean_cases_cannot_compensate_for_one_hard_gate(self):
        rows = [
            _model_result_row(scenario_id=f"case-{index}", category="simple_mixed_text", split="validation", repeat=1,
                              item_identity=f"{index:064x}", subject="a" * 40, deployment="b" * 64)
            for index in range(100)
        ]
        _inject_semantic_gate(rows[-1], "CRITICAL_NUMERIC_MISMATCH")
        summary = aggregate_model_results(rows, model="google/gemma-4-31b-it", split="validation")
        self.assertEqual(summary["mean_scores"], {"coverage": 1.0, "numeric_fidelity": 1.0, "modality": 1.0, "table_cell_fidelity": 1.0, "visual_relation_recall": 1.0})
        self.assertEqual(summary["critical_failure_count"], 1)
        self.assertEqual(summary["noncritical_semantic_equivalence"], 1.0)
        self.assertFalse(summary["hard_gate_pass"])
        self.assertEqual(summary["evaluation_state"], "CERTIFICATION_FAIL")

    def test_public_source_bound_assertions_miss_without_creating_a_hard_gate(self):
        from evals.noncritical_semantics import public_assertions_for
        from evals.scenarios import scenario_specs

        scenario = next(item for item in scenario_specs() if item.scenario_id == "scenario-0001")
        assertions = public_assertions_for(scenario.scenario_id)
        regions = (scenario.title_ko, *scenario.body_ko)
        evidence = EvidenceIR(
            "doc", "u-public", {},
            tuple(EvidenceRegion(f"region-{index}", selected_literal_candidate=text) for index, text in enumerate(regions)),
        ).with_revision()
        translations = {
            scenario.title_ko: "Operating plan and key risks",
            "KPI 개선 추진": "KPI improvement initiative",
            "Revenue 성장률 및 주요 리스크 검토": "review of revenue growth and key risks",
            "2H 적용 가능성 협의 필요": "discussion of possible 2H application",
        }
        patch = {"regions": [
            {"region_id": f"region-{index}", "english": translations[text]}
            for index, text in enumerate(regions)
        ]}
        clean = score_translation_patch(scenario, evidence, patch)
        self.assertEqual(len(assertions), 2)
        self.assertEqual(clean["critical_failures"], [])
        self.assertEqual(clean["noncritical_semantic_equivalence"], 1.0)

        patch["regions"][1]["english"] = "KPI declined after the pilot"
        missed = score_translation_patch(scenario, evidence, patch)
        self.assertEqual(missed["critical_failures"], [])
        self.assertEqual(missed["noncritical_semantic_required_count"], 2)
        self.assertEqual(missed["noncritical_semantic_correct_count"], 1)
        self.assertEqual(missed["noncritical_semantic_equivalence"], 0.5)
        self.assertEqual(missed["critical_axis_minimum_diagnostic"], 1.0)

    def test_approved_paraphrase_passes_fluent_wrong_meaning_fails_and_other_region_cannot_satisfy(self):
        from evals.noncritical_semantics import public_assertions_for
        from evals.scenarios import scenario_specs

        scenario = next(item for item in scenario_specs() if item.scenario_id == "scenario-0001")
        texts = (scenario.title_ko, *scenario.body_ko)
        evidence = EvidenceIR("doc", "u-public", {}, tuple(
            EvidenceRegion(f"region-{index}", selected_literal_candidate=text) for index, text in enumerate(texts)
        )).with_revision()
        accepted = {item["source_text"]: item["accepted_phrases"][0] for item in public_assertions_for(scenario.scenario_id)}
        accepted["KPI 개선 추진"] = "initiative to improve KPIs"
        patch = {"regions": [
            {"region_id": f"region-{index}", "english": accepted.get(text, "Operating plan and related business context")}
            for index, text in enumerate(texts)
        ]}
        paraphrase = score_translation_patch(scenario, evidence, patch)
        self.assertEqual(paraphrase["noncritical_semantic_equivalence"], 1.0)

        patch["regions"][1]["english"] = "not a KPI improvement initiative"
        contradictory = score_translation_patch(scenario, evidence, patch)
        self.assertEqual(contradictory["noncritical_semantic_observations"][0]["outcome"], "INCORRECT")

        patch["regions"][1]["english"] = "KPI reduced spend in the pilot"
        fluent_wrong = score_translation_patch(scenario, evidence, patch)
        self.assertEqual(fluent_wrong["noncritical_semantic_observations"][0]["outcome"], "INCORRECT")
        self.assertEqual(fluent_wrong["critical_failures"], [])

        patch["regions"][1]["english"] = public_assertions_for(scenario.scenario_id)[1]["accepted_phrases"][0]
        patch["regions"][2]["english"] = "Revenue growth and risks were deferred"
        wrong_region = score_translation_patch(scenario, evidence, patch)
        outcomes = {item["assertion_id"]: item["outcome"] for item in wrong_region["noncritical_semantic_observations"]}
        self.assertEqual(outcomes[public_assertions_for(scenario.scenario_id)[0]["assertion_id"]], "INCORRECT")
        self.assertEqual(wrong_region["critical_failures"], [])

    def test_scorer_observations_drive_exact_floor_and_below_floor_aggregation(self):
        for total, correct, expected_floor in ((100, 99, True), (1000, 989, False)):
            with self.subTest(total=total, correct=correct):
                scenario, _evidence, score = _custom_assertion_case(total, correct, scenario_id=f"custom-{total}")
                self.assertEqual(score["critical_failures"], [])
                row = _model_result_row(
                    scenario_id=scenario.scenario_id, category="simple_mixed_text", split="validation", repeat=1,
                    item_identity="a" * 64, subject="a" * 40, deployment="b" * 64,
                )
                score["noncritical_semantic_assertion_ids"] = sorted(item["assertion_id"] for item in scenario.gold["noncritical_semantic_assertions"])
                score.update({"term_consistency_recall": 1.0, "inconsistent_alternate_count": 0})
                row["semantic"] = copy.deepcopy(score)
                row["units"][0]["semantic"] = copy.deepcopy(score)
                summary = aggregate_model_results([row], model="google/gemma-4-31b-it", split="validation")
                self.assertTrue(summary["hard_gate_pass"])
                self.assertEqual(summary["noncritical_semantic_equivalence"], correct / total)
                self.assertEqual(summary["noncritical_floor_pass"], expected_floor)

    def test_gold_approved_unresolved_is_exempt_but_missed_material_unresolved_stays_critical(self):
        assertion_id = "ncs-0123456789abcdef01234567"
        scenario = SimpleNamespace(scenario_id="unresolved-contract", gold={
            "allowed_unresolved": True,
            "noncritical_semantic_assertions": [{
                "assertion_id": assertion_id, "surface": "region", "source_text": "흐린 보조 설명",
                "accepted_phrases": ["supporting descriptive note"],
            }],
        })
        region = EvidenceRegion(
            "region-blurred", selected_literal_candidate="흐린 보조 설명", evidence_state="LOW_CONFIDENCE",
            recovery_status="NEEDS_REVIEW", recovery_reason="Synthetic ambiguity fixture.",
        )
        evidence = EvidenceIR("doc", "u-unresolved", {}, (region,)).with_revision()
        review = score_translation_patch(scenario, evidence, {
            "regions": [{"region_id": region.region_id, "english": "", "unresolved": True, "unresolved_reason": "unclear source"}],
        })
        self.assertEqual(review["noncritical_semantic_observations"][0]["outcome"], "UNRESOLVED_EXEMPT")
        self.assertEqual(review["noncritical_semantic_required_count"], 0)
        self.assertEqual(review["noncritical_semantic_equivalence"], 1.0)
        self.assertEqual(review["material_unresolved_recall"], 1.0)
        self.assertEqual(review["critical_failures"], [])

        false_resolved = score_translation_patch(scenario, evidence, {
            "regions": [{"region_id": region.region_id, "english": "supporting note", "unresolved": False}],
        })
        self.assertIn("MATERIAL_UNRESOLVED_MISSED", false_resolved["critical_failures"])

    def test_authority_precedes_quality_and_hard_gates_precede_floors(self):
        row = _model_result_row(scenario_id="case", category="simple_mixed_text", split="validation", repeat=1,
                                item_identity="1" * 64, subject="a" * 40, deployment="b" * 64)
        _inject_semantic_gate(row, "CRITICAL_NUMERIC_MISMATCH")
        row["quality_metrics_authoritative"] = False
        row["opencode"]["reason"] = "model unavailable"
        summary = aggregate_model_results([row], model="google/gemma-4-31b-it", split="validation")
        self.assertEqual(summary["evaluation_state"], "CAPABILITY_BLOCKED")
        self.assertGreater(summary["hard_gate_failure_count"], 0)

    def test_closed_semantic_gate_surfaces_fail_individually(self):
        gates = (
            "SILENT_REGION_OMISSION", "CRITICAL_MODALITY_MISMATCH", "CRITICAL_TREND_REVERSAL",
            "UNSUPPORTED_EXECUTIVE_CLAIM", "SCORER_SOURCE_BINDING_FAILURE", "UNEXPECTED_HANGUL",
        )
        for index, gate in enumerate(gates):
            with self.subTest(gate=gate):
                row = _model_result_row(scenario_id=f"case-{index}", category="simple_mixed_text", split="validation", repeat=1,
                                        item_identity=f"{index + 1:064x}", subject="a" * 40, deployment="b" * 64)
                _inject_semantic_gate(row, gate)
                summary = aggregate_model_results([row], model="google/gemma-4-31b-it", split="validation")
                self.assertFalse(summary["hard_gate_pass"])
                self.assertEqual(summary["noncritical_semantic_equivalence"], 1.0)
                self.assertIn(gate, summary["hard_gate_failure_types"])

    def test_table_cell_cardinality_is_source_identity_based_and_noncompensable(self):
        table = EvidenceTable("tbl", row_count=1, column_count=2, cells=(
            EvidenceTableCell("tbl-c1", 0, 0, source_text="매출"),
            EvidenceTableCell("tbl-c2", 0, 1, source_text="이익"),
        ))
        evidence = EvidenceIR("doc", "u1", {}, (), (table,), required_source_ids=("tbl", "tbl-c1", "tbl-c2")).with_revision()
        scenario = type("Scenario", (), {"gold": {}})()
        patch = {"regions": [], "tables": [{"table_id": "tbl", "cells": [{"cell_id": "tbl-c1", "english": "Revenue"}]}]}
        score = score_translation_patch(scenario, evidence, patch)
        self.assertIn("TABLE_CARDINALITY_MISMATCH", score["critical_failures"])
        self.assertIn("MISSING_CELL:tbl-c2", score["table_failures"])
        self.assertEqual(score["hard_gate_evidence"]["table_cardinality_mismatch"], True)
        self.assertEqual(score["noncritical_semantic_equivalence"], 1.0)

    def test_table_cardinality_gate_fails_even_when_other_case_scores_are_perfect(self):
        row = _model_result_row(scenario_id="table", category="financial_table", split="validation", repeat=1,
                                item_identity="2" * 64, subject="a" * 40, deployment="b" * 64)
        unit = row["units"][0]["semantic"]
        unit["hard_gate_evidence"]["table_cardinality_mismatch"] = True
        unit["hard_gate_evidence"]["table_failure_codes"] = ["TABLE_CARDINALITY_MISMATCH"]
        unit["critical_failures"] = ["TABLE_CELL_SEMANTIC_FAILURE", "TABLE_CARDINALITY_MISMATCH"]
        row["semantic"]["critical_failures"] = unit["critical_failures"]
        rows = [copy.deepcopy(row) for _ in range(99)]
        for index, perfect in enumerate(rows):
            perfect["scenario_id"] = f"perfect-{index}"
            perfect["units"][0]["semantic"]["critical_failures"] = []
            perfect["units"][0]["semantic"]["hard_gate_evidence"]["table_cardinality_mismatch"] = False
            perfect["units"][0]["semantic"]["hard_gate_evidence"]["table_failure_codes"] = []
            perfect["semantic"]["critical_failures"] = []
        summary = aggregate_model_results(rows + [row], model="google/gemma-4-31b-it", split="validation")
        self.assertEqual(summary["mean_scores"]["table_cell_fidelity"], 1.0)
        self.assertEqual(summary["evaluation_state"], "CERTIFICATION_FAIL")

    def test_conflict_modality_tool_media_model_and_false_done_gates(self):
        def item(index: int) -> dict:
            return _model_result_row(scenario_id=f"case-{index}", category="simple_mixed_text", split="validation", repeat=1,
                                     item_identity=f"{index + 1:064x}", subject="a" * 40, deployment="b" * 64)

        conflict = item(1)
        conflict["persisted_execution"].update({"conflict_resolution_failure": True, "conflict_count": 1, "conflict_failure_codes": ["FALSE_CONFLICT_RESOLUTION"]})
        forbidden = item(2)
        forbidden["category"] = "prompt_injection"
        forbidden["opencode"].update({"tool_calls": ["websearch"], "tool_call_count": 1, "forbidden_attempts": ["websearch"], "forbidden_attempt_count": 1})
        missing_media = item(3)
        missing_media["media_by_work_unit"]["u1"].update({"read_count": 0, "required_context_image_read": False, "media_sequence_valid": False})
        missing_media["opencode"]["media_compliance"].update({"read_count": 0, "required_context_image_read": False, "media_sequence_valid": False})
        missing_media["opencode"]["media_compliance"]["work_units"]["u1"].update({"required_context_image_read": False, "media_sequence_valid": False, "items": [{"id": "context_image", "read_observed": False, "read_before_submit": False}]})
        wrong_model = item(4)
        wrong_model["model_identity"].update({"effective_model": "other/model", "approved": False})
        wrong_model["effective_model"] = "other/model"
        wrong_model["opencode"]["diagnostics"].update({"effective_model": "other/model", "model_identity_proven": False})
        false_done = item(5)
        false_done["persisted_execution"].update({"material_unresolved_required_count": 1, "false_done_recovery_violation": True})
        broken_contract = item(6)
        broken_contract["work_unit_contract"].update({"pass": False, "failures": []})
        for row in (conflict, forbidden, missing_media, wrong_model, false_done, broken_contract):
            findings = derive_result_hard_gate_findings(row)
            self.assertTrue(findings)
        all_rows = [conflict, forbidden, missing_media, wrong_model, false_done, broken_contract]
        summary = aggregate_model_results(all_rows, model="google/gemma-4-31b-it", split="validation")
        self.assertEqual(summary["evaluation_state"], "CERTIFICATION_FAIL")
        self.assertTrue({"MATERIAL_CONFLICT_RESOLUTION_FAILURE", "FORBIDDEN_TOOL_ATTEMPT", "REQUIRED_MEDIA_READ_FAILURE", "WRONG_MODEL_IDENTITY", "FALSE_DONE_WITH_MATERIAL_UNRESOLVED", "WORK_UNIT_CONTRACT_FAILURE"}.issubset(set(summary["hard_gate_failure_types"])))

    def test_one_missing_media_or_model_fallback_cannot_be_averaged_over_99_cases(self):
        for defect in ("media", "model"):
            with self.subTest(defect=defect):
                rows = [
                    _model_result_row(scenario_id=f"case-{index}", category="simple_mixed_text", split="validation", repeat=1,
                                      item_identity=f"{index:064x}", subject="a" * 40, deployment="b" * 64)
                    for index in range(100)
                ]
                if defect == "media":
                    projected = rows[-1]["media_by_work_unit"]["u1"]
                    projected.update({"read_count": 0, "required_context_image_read": False, "media_sequence_valid": False})
                    trace = rows[-1]["opencode"]["media_compliance"]
                    trace.update({"read_count": 0, "required_context_image_read": False, "media_sequence_valid": False})
                    trace["work_units"]["u1"].update({"required_context_image_read": False, "media_sequence_valid": False,
                                                        "items": [{"id": "context_image", "read_observed": False, "read_before_submit": False}]})
                else:
                    row = rows[-1]
                    row["model_identity"].update({"effective_model": "provider/fallback", "approved": False})
                    row["effective_model"] = "provider/fallback"
                    row["opencode"]["diagnostics"].update({"effective_model": "provider/fallback", "model_identity_proven": False})
                summary = aggregate_model_results(rows, model="google/gemma-4-31b-it", split="validation")
                self.assertEqual(summary["case_count"], 100)
                self.assertEqual(summary["evaluation_state"], "CERTIFICATION_FAIL")
                self.assertFalse(summary["hard_gate_pass"])

    def test_material_unresolved_recall_is_zero_tolerance(self):
        row = _model_result_row(scenario_id="unresolved", category="visual_degradation", split="validation", repeat=1,
                                item_identity="3" * 64, subject="a" * 40, deployment="b" * 64)
        unit = row["units"][0]["semantic"]
        facts = unit["hard_gate_evidence"]
        facts["material_unresolved_required_ids"] = ["r1"]
        unit.update({"material_unresolved_required_ids": ["r1"], "material_unresolved_false_negative_ids": ["r1"], "material_unresolved_recall": 0.0})
        unit["critical_failures"] = ["MATERIAL_UNRESOLVED_MISSED"]
        row["semantic"].update({"critical_failures": ["MATERIAL_UNRESOLVED_MISSED"], "material_unresolved_required_count": 1, "material_unresolved_recall": 0.0})
        row["persisted_execution"].update({"material_unresolved_required_count": 1, "false_done_recovery_violation": True})
        summary = aggregate_model_results([row], model="google/gemma-4-31b-it", split="validation")
        self.assertEqual(summary["material_unresolved_recall"], 0.0)
        self.assertEqual(summary["evaluation_state"], "CERTIFICATION_FAIL")

    def test_unresolved_precision_floor_and_no_positive_convention(self):
        empty = _model_result_row(scenario_id="empty", category="simple_mixed_text", split="validation", repeat=1,
                                  item_identity="4" * 64, subject="a" * 40, deployment="b" * 64)
        empty_summary = aggregate_model_results([empty], model="google/gemma-4-31b-it", split="validation")
        self.assertEqual(empty_summary["material_unresolved_recall"], 1.0)
        self.assertEqual(empty_summary["unresolved_precision"], 1.0)
        at_floor = _model_result_row(scenario_id="review", category="visual_degradation", split="validation", repeat=1,
                                     item_identity="5" * 64, subject="a" * 40, deployment="b" * 64)
        _configure_unresolved(at_floor, 19, 20)
        summary = aggregate_model_results([at_floor], model="google/gemma-4-31b-it", split="validation")
        self.assertEqual(summary["unresolved_precision"], 0.95)
        self.assertEqual(summary["material_unresolved_recall"], 1.0)
        self.assertTrue(summary["hard_gate_pass"])
        self.assertTrue(summary["noncritical_floor_pass"])

    def test_exact_machine_floors_pass_and_one_ulp_lower_floor_fails(self):
        for total, correct, precision_count, expected_pass in ((100, 99, (19, 20), True), (1000, 989, (19, 20), False), (100, 99, (9499, 10_000), False)):
            with self.subTest(total=total, correct=correct, precision=precision_count), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                sources = _model_sources(root, split="validation", repeats=3)
                rows = [json.loads(line) for line in sources["results_jsonl"].read_text(encoding="utf-8").splitlines()]
                assertion_ids = sorted("ncs-" + hashlib.sha256(f"machine-contract:{index}".encode()).hexdigest()[:24] for index in range(total))
                for row in rows:
                    _apply_observations(row, assertion_ids, correct)
                _configure_unresolved(rows[0], *precision_count)
                _refresh_model_sources(root, sources, rows)
                evidence = root / "evidence.json"
                if expected_pass:
                    build_machine_evidence(evidence, evidence_type="model_validation", subject_git_sha="a" * 40,
                                           deployment_fingerprint="b" * 64, sources=sources, root=Path.cwd())
                    payload = load_evidence(evidence, expected_type="model_validation")["payload"]
                    self.assertEqual(payload["noncritical_semantic_equivalence"], 0.99)
                    self.assertEqual(payload["noncritical_semantic_required_count"], 100 * len(rows))
                    self.assertEqual(payload["noncritical_semantic_correct_count"], 99 * len(rows))
                    self.assertEqual(payload["unresolved_precision"], 0.95)
                else:
                    with self.assertRaises(AdapterError):
                        build_machine_evidence(evidence, evidence_type="model_validation", subject_git_sha="a" * 40,
                                               deployment_fingerprint="b" * 64, sources=sources, root=Path.cwd())

    def test_result_summary_raw_findings_policy_and_floor_tampering_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _model_sources(root, split="validation", repeats=3, critical=1)
            summary = json.loads(sources["model_summary"].read_text(encoding="utf-8"))
            summary.update({"critical_failure_count": 0, "hard_gate_failure_count": 0, "critical_failure_types": [], "hard_gate_failure_types": [], "hard_gate_pass": True, "mean_scores": {"coverage": 1, "numeric_fidelity": 1, "modality": 1, "table_cell_fidelity": 1, "visual_relation_recall": 1}})
            _write(sources["model_summary"], summary)
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "evidence.json", evidence_type="model_validation", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources, root=Path.cwd())

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _model_sources(root, split="validation", repeats=3, critical=1)
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "evidence.json", evidence_type="model_validation", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources, root=Path.cwd())

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _model_sources(root, split="validation", repeats=3)
            rows = [json.loads(line) for line in sources["results_jsonl"].read_text(encoding="utf-8").splitlines()]
            assertion_ids = sorted("ncs-" + hashlib.sha256(f"summary-tamper:{index}".encode()).hexdigest()[:24] for index in range(100))
            for row in rows:
                _apply_observations(row, assertion_ids, 99)
            _refresh_model_sources(root, sources, rows)
            summary = json.loads(sources["model_summary"].read_text(encoding="utf-8"))
            summary["noncritical_semantic_equivalence"] = 1.0
            _write(sources["model_summary"], summary)
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "evidence.json", evidence_type="model_validation", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources, root=Path.cwd())

        for mutation in ("flip", "duplicate", "drop", "unknown"):
            with self.subTest(observation_mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                sources = _model_sources(root, split="validation", repeats=3)
                rows = [json.loads(line) for line in sources["results_jsonl"].read_text(encoding="utf-8").splitlines()]
                assertion_ids = sorted("ncs-" + hashlib.sha256(f"observation-tamper:{index}".encode()).hexdigest()[:24] for index in range(100))
                for row in rows:
                    _apply_observations(row, assertion_ids, 99)
                target = rows[0]
                parent_observations = target["semantic"]["noncritical_semantic_observations"]
                unit_observations = target["units"][0]["semantic"]["noncritical_semantic_observations"]
                if mutation == "flip":
                    parent_observations[-1]["outcome"] = "CORRECT"
                    target["semantic"]["noncritical_semantic_correct_count"] += 1
                    target["semantic"]["noncritical_semantic_equivalence"] = 1.0
                elif mutation == "duplicate":
                    unit_observations.append(copy.deepcopy(unit_observations[0]))
                elif mutation == "drop":
                    unit_observations.pop()
                else:
                    unit_observations[0]["outcome"] = "UNKNOWN"
                (root / "results.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
                with self.assertRaises(AdapterError):
                    build_machine_evidence(root / "evidence.json", evidence_type="model_validation", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources, root=Path.cwd())

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _model_sources(root, split="validation", repeats=3, critical=1)
            rows = [json.loads(line) for line in sources["results_jsonl"].read_text(encoding="utf-8").splitlines()]
            rows[0]["units"][0]["semantic"]["critical_failures"] = []
            rows[0]["semantic"]["critical_failures"] = []
            sources["results_jsonl"].write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "evidence.json", evidence_type="model_validation", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources, root=Path.cwd())

        for field_value in (("quality_policy_identity", "0" * 64), ("quality_policy_identity", None)):
            with self.subTest(policy_value=field_value[1]), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                sources = _model_sources(root, split="validation", repeats=3)
                summary = json.loads(sources["model_summary"].read_text(encoding="utf-8"))
                experiment = json.loads(sources["experiment_manifest"].read_text(encoding="utf-8"))
                if field_value[1] is None:
                    summary.pop(field_value[0], None)
                    experiment.pop(field_value[0], None)
                else:
                    summary[field_value[0]] = field_value[1]
                    experiment[field_value[0]] = field_value[1]
                _write(sources["model_summary"], summary)
                _write(sources["experiment_manifest"], experiment)
                with self.assertRaises(AdapterError):
                    build_machine_evidence(root / "evidence.json", evidence_type="model_validation", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources, root=Path.cwd())

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _model_sources(root, split="validation", repeats=3)
            summary = json.loads(sources["model_summary"].read_text(encoding="utf-8"))
            experiment = json.loads(sources["experiment_manifest"].read_text(encoding="utf-8"))
            rows = [json.loads(line) for line in sources["results_jsonl"].read_text(encoding="utf-8").splitlines()]
            predecessor_policy = {**policy_identity_record(), "policy_version": "ksa-27.1", "identity_sha256": "0" * 64}
            for value in (summary, experiment, *rows):
                value["quality_policy"] = predecessor_policy
                value["quality_policy_identity"] = predecessor_policy["identity_sha256"]
            _write(sources["model_summary"], summary)
            _write(sources["experiment_manifest"], experiment)
            sources["results_jsonl"].write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "evidence.json", evidence_type="model_validation", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources, root=Path.cwd())

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _model_sources(root, split="validation", repeats=3)
            summary = json.loads(sources["model_summary"].read_text(encoding="utf-8"))
            summary["noncritical_floor_pass"] = False
            _write(sources["model_summary"], summary)
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "evidence.json", evidence_type="model_validation", subject_git_sha="a" * 40,
                                       deployment_fingerprint="b" * 64, sources=sources, root=Path.cwd())

    def test_structured_tool_media_and_model_tampering_is_rederived(self):
        mutations = (
            lambda row: row["opencode"].update({"tool_calls": ["bash"], "tool_call_count": 1}),
            lambda row: row["opencode"]["media_compliance"]["work_units"]["u1"]["items"][0].update({"read_observed": False}),
            lambda row: row["model_identity"].update({"approved": False}),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate.__code__.co_firstlineno), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                sources = _model_sources(root, split="validation", repeats=3)
                rows = [json.loads(line) for line in sources["results_jsonl"].read_text(encoding="utf-8").splitlines()]
                mutate(rows[0])
                sources["results_jsonl"].write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
                with self.assertRaises(AdapterError):
                    build_machine_evidence(root / "evidence.json", evidence_type="model_validation", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources, root=Path.cwd())

    def test_unknown_result_gate_is_preserved_as_failing_closed_identity(self):
        row = _model_result_row(scenario_id="unknown", category="simple_mixed_text", split="validation", repeat=1,
                                item_identity="6" * 64, subject="a" * 40, deployment="b" * 64)
        row["semantic"]["critical_failures"] = ["UNREGISTERED"]
        expected = derive_result_hard_gate_findings(row)
        self.assertEqual(expected[0]["code"], "UNKNOWN_HARD_GATE_CODE")
        self.assertIn("unknown_code_sha256", expected[0])

    def test_injected_unknown_gate_in_authoritative_row_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _model_sources(root, split="validation", repeats=3)
            rows = [json.loads(line) for line in sources["results_jsonl"].read_text(encoding="utf-8").splitlines()]
            rows[0]["hard_gate_findings"] = [{"code": "UNKNOWN_HARD_GATE_CODE", "category": "ignored"}]
            sources["results_jsonl"].write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
            with self.assertRaises(AdapterError):
                build_machine_evidence(root / "evidence.json", evidence_type="model_validation", subject_git_sha="a" * 40,
                                       deployment_fingerprint="b" * 64, sources=sources, root=Path.cwd())

    def test_internal_bilingual_floors_are_policy_bound_and_inclusive(self):
        validate_evidence_payload("internal_bilingual", _bilingual_payload())
        for overrides in (
            {"overall_noncritical_semantic_fidelity": 0.989999},
            {"unresolved_precision": 0.949999},
            {"material_unresolved_recall": 0.999999},
            {"locked_terminology": 0.994999},
            {"quality_policy_identity": "f" * 64},
        ):
            with self.subTest(overrides=overrides), self.assertRaises(EvidenceValidationError):
                validate_evidence_payload("internal_bilingual", _bilingual_payload(**overrides))

    def test_legacy_evidence_envelope_cannot_be_loaded_as_current(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _model_sources(root, split="validation", repeats=3)
            path = root / "evidence.json"
            build_machine_evidence(path, evidence_type="model_validation", subject_git_sha="a" * 40, deployment_fingerprint="b" * 64, sources=sources, root=Path.cwd())
            envelope = json.loads(path.read_text(encoding="utf-8"))
            envelope["schema_version"] = "2.4"
            _write(path, envelope)
            with self.assertRaises(EvidenceValidationError):
                load_evidence(path, expected_type="model_validation")

    def test_security_hard_findings_remain_zero_tolerance(self):
        payload = {"dependency_audit_pass": True, "secret_scan_pass": True, "static_scan_pass": True,
                   "unresolved_high_findings": 1, "unresolved_critical_findings": 0, "secret_findings": 0}
        # Include the rest of the established security envelope contract.
        payload.update({key: "a" * 64 for key in (
            "audited_dependency_set_sha256", "resolved_dependency_set_sha256", "resolved_dependency_lock_sha256",
            "production_sbom_sha256", "candidate_constraints_sha256",
        )})
        payload.update({"pip_audit_version": "pip-audit 2.9.0", "semgrep_version": "semgrep 1.89.0",
                        "semgrep_ruleset_identity": "security/semgrep-production.yml", "semgrep_ruleset_sha256": "b" * 64})
        with self.assertRaises(EvidenceValidationError):
            validate_evidence_payload("security", payload)

    def test_repository_champion_remains_unset(self):
        champion = json.loads((Path(__file__).resolve().parents[1] / "evals" / "champion.json").read_text(encoding="utf-8"))
        self.assertEqual(champion["status"], "UNSET")


if __name__ == "__main__":
    unittest.main()
