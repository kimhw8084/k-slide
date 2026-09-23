from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from evals.model_results import aggregate_model_results, derive_result_hard_gate_findings
from evals.model_scorers import score_translation_patch
from k_slide.certification import EvidenceValidationError, load_evidence, validate_evidence_payload
from k_slide.evidence_adapters import AdapterError, build_machine_evidence
from k_slide.evidence_ir import EvidenceIR, EvidenceTable, EvidenceTableCell
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
    summary = json.loads(sources["model_summary"].read_text(encoding="utf-8"))
    derived = aggregate_model_results(rows, model="google/gemma-4-31b-it", split=summary["split"])
    summary.update(derived)
    (root / "results.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    _write(sources["model_summary"], summary)


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
        self.assertEqual(summary["evaluation_state"], "CERTIFICATION_FAIL")

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
        for fidelity, precision_count, expected_pass in ((0.99, (19, 20), True), (0.9899999999999999, (19, 20), False), (0.99, (9499, 10_000), False)):
            with self.subTest(fidelity=fidelity, precision=precision_count), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                sources = _model_sources(root, split="validation", repeats=3)
                rows = [json.loads(line) for line in sources["results_jsonl"].read_text(encoding="utf-8").splitlines()]
                for row in rows:
                    semantic = row["semantic"]
                    semantic["numeric_fidelity"] = fidelity
                    semantic["source_backed_semantic_fidelity"] = fidelity
                    unit = row["units"][0]["semantic"]
                    unit["numeric_fidelity"] = fidelity
                    unit["source_backed_semantic_fidelity"] = fidelity
                    semantic["term_consistency_recall"] = 0.995
                rows[0]["semantic"]["numeric_fidelity"] = fidelity
                _configure_unresolved(rows[0], *precision_count)
                _refresh_model_sources(root, sources, rows)
                evidence = root / "evidence.json"
                if expected_pass:
                    build_machine_evidence(evidence, evidence_type="model_validation", subject_git_sha="a" * 40,
                                           deployment_fingerprint="b" * 64, sources=sources, root=Path.cwd())
                    payload = load_evidence(evidence, expected_type="model_validation")["payload"]
                    self.assertEqual(payload["noncritical_semantic_fidelity"], 0.99)
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
            envelope["schema_version"] = "2.3"
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
