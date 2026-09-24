from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from evals.experiments import experiment_plan, experiment_plan_hash
from evals.model_eval import ModelEvaluationRunner
from evals.model_results import aggregate_model_results, derive_result_hard_gate_findings
from evals.noncritical_semantics import public_assertion_ids_by_scenario
from evals.scenarios import scenario_specs
from k_slide.evidence_adapters import AdapterError, _model_matrix, build_machine_evidence
from tests.test_certification_closure import _model_result_row, _model_sources, _write
from tests.test_ksa26_governed_runner import PROTECTED_CATEGORIES, _fixture, _run_fixture
from tests.test_ksa27_quality_policy import _inject_semantic_gate, _refresh_model_sources


TARGET = "google/gemma-4-31b-it"


def _expected_matrix(experiment: dict) -> list[tuple[str, str, int]]:
    return [
        (scenario_id, format_name, repeat)
        for scenario_id in experiment["scenario_ids"]
        for format_name in experiment["formats"]
        for repeat in range(1, experiment["repetitions"] + 1)
    ]


def _rewrite_rows(sources: dict[str, Path], rows: list[dict]) -> None:
    sources["results_jsonl"].write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def _build_validation_evidence(root: Path, sources: dict[str, Path]) -> dict:
    experiment = json.loads(sources["experiment_manifest"].read_text(encoding="utf-8"))
    path = root / "evidence.json"
    build_machine_evidence(
        path,
        evidence_type="model_validation",
        subject_git_sha=experiment["subject_git_sha"],
        deployment_fingerprint=experiment["deployment_fingerprint"],
        sources=sources,
        root=Path.cwd(),
    )
    return json.loads(path.read_text(encoding="utf-8"))


class KSA28StabilityCalibrationTests(unittest.TestCase):
    def test_default_repetitions_follow_certification_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(ModelEvaluationRunner(model=TARGET, output=root / "validation", split="validation").repeats, 3)
            self.assertEqual(ModelEvaluationRunner(model=TARGET, output=root / "held-out", split="held_out").repeats, 3)
            self.assertEqual(ModelEvaluationRunner(model=TARGET, output=root / "development").repeats, 1)
            self.assertEqual(ModelEvaluationRunner(model=TARGET, output=root / "protocol", split="validation", mode="protocol").repeats, 1)
            self.assertEqual(ModelEvaluationRunner(model=TARGET, output=root / "filtered", split="validation", scenario_ids=("scenario-0001",)).repeats, 1)
            self.assertEqual(ModelEvaluationRunner(model=TARGET, output=root / "governed", corpus_source="governed_external").repeats, 3)

            fixture_root = root / "governed-fixture"
            fixture_root.mkdir()
            fixture = _fixture(fixture_root, "private_representative")
            result, output = _run_fixture(fixture, repeats=None)
            experiment = json.loads((output / "experiment.json").read_text(encoding="utf-8"))
            self.assertEqual(experiment["repetitions"], 3)
            self.assertEqual(result["case_count"], 3)

    def test_high_risk_default_and_explicit_larger_repetition_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            high_risk = ModelEvaluationRunner(model=TARGET, output=root / "high-risk", split="validation", high_risk=True)
            self.assertGreaterEqual(high_risk.repeats, 5)
            larger = ModelEvaluationRunner(model=TARGET, output=root / "larger", split="validation", repeats=9)
            self.assertEqual(larger.repeats, 9)

    def test_frozen_governed_high_risk_omitted_default_is_five_and_larger_count_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = _fixture(Path(directory), "frozen_high_risk")
            result, output = _run_fixture(fixture, repeats=None)
            experiment = json.loads((output / "experiment.json").read_text(encoding="utf-8"))
            self.assertEqual(experiment["repetitions"], 5)
            self.assertEqual(result["case_count"], len(PROTECTED_CATEGORIES) * 5)
            self.assertTrue(result["quality_metrics_authoritative"])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _model_sources(root, repeats=7, evidence_type="model_validation")
            evidence = _build_validation_evidence(root, sources)
            self.assertEqual(evidence["payload"]["repetitions"], 7)

    def test_public_frozen_corpus_matrix_reconstructs_every_format_and_ordinal(self):
        scenarios = [item for item in scenario_specs() if item.split == "validation"]
        scenario_ids = [item.scenario_id for item in scenarios]
        formats = ["png", "pdf"]
        repetitions = 3
        plan = experiment_plan(split="validation", scenario_ids=scenario_ids, formats=formats, repetitions=repetitions)
        experiment = {
            "scenario_ids": scenario_ids,
            "formats": formats,
            "repetitions": repetitions,
            "categories": [],
            "experiment_plan": plan,
            "experiment_plan_hash": experiment_plan_hash(plan),
            "corpus_set_identity": {"role": "public_synthetic_regression"},
        }
        assertion_ids = public_assertion_ids_by_scenario()
        rows = [
            {
                "scenario_id": scenario.scenario_id,
                "category": scenario.category,
                "split": scenario.split,
                "format": format_name,
                "repeat": repeat,
                "semantic": {"noncritical_semantic_assertion_ids": assertion_ids.get(scenario.scenario_id, [])},
            }
            for scenario in scenarios
            for format_name in formats
            for repeat in range(1, repetitions + 1)
        ]
        matrix = _model_matrix(experiment, rows, expected_split="validation", require_full_split=True, root=Path.cwd())
        self.assertEqual(matrix["case_count"], len(scenarios) * len(formats) * repetitions)
        self.assertTrue(matrix["certification_matrix_complete"])
        self.assertEqual(matrix["certification_matrix_cell_count"], len(rows))
        for mutate in (
            lambda value: value.pop(),
            lambda value: value.append(copy.deepcopy(value[0])),
            lambda value: value[0].update(repeat=99),
            lambda value: value[0].update(scenario_id="scenario-not-in-corpus"),
        ):
            with self.subTest(mutation=mutate.__code__.co_firstlineno):
                changed = copy.deepcopy(rows)
                mutate(changed)
                with self.assertRaises(AdapterError):
                    _model_matrix(experiment, changed, expected_split="validation", require_full_split=True, root=Path.cwd())

    def test_governed_matrix_missing_duplicate_out_of_range_and_misbound_cells_fail(self):
        mutations = (
            lambda rows: rows.pop(),
            lambda rows: rows.append(copy.deepcopy(rows[0])),
            lambda rows: rows[0].update(repeat=99),
            lambda rows: rows[0].update(scenario_id="inactive-case-id"),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                sources = _model_sources(root, repeats=3, evidence_type="model_validation")
                rows = [json.loads(line) for line in sources["results_jsonl"].read_text(encoding="utf-8").splitlines()]
                experiment = json.loads(sources["experiment_manifest"].read_text(encoding="utf-8"))
                mutate(rows)
                with self.assertRaises(ValueError):
                    aggregate_model_results(rows, model=TARGET, split="validation", expected_matrix=_expected_matrix(experiment))
                _rewrite_rows(sources, rows)
                with self.assertRaises(AdapterError):
                    _build_validation_evidence(root, sources)

    def test_one_stochastic_critical_or_false_done_repeat_fails_the_set(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _model_sources(root, repeats=3, evidence_type="model_validation")
            rows = [json.loads(line) for line in sources["results_jsonl"].read_text(encoding="utf-8").splitlines()]
            target = next(row for row in rows if row["repeat"] == 2)
            _inject_semantic_gate(target, "CRITICAL_NUMERIC_MISMATCH")
            _refresh_model_sources(root, sources, rows)
            summary = json.loads(sources["model_summary"].read_text(encoding="utf-8"))
            self.assertEqual(summary["evaluation_state"], "CERTIFICATION_FAIL")
            target_group = summary["stability_groups"][f"{target['scenario_id']}/png"]
            self.assertEqual(target_group["critical_failure_runs"], 1)
            self.assertAlmostEqual(target_group["critical_frequency"], 1 / 3)
            with self.assertRaises(AdapterError):
                _build_validation_evidence(root, sources)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _model_sources(root, repeats=3, evidence_type="model_validation")
            experiment = json.loads(sources["experiment_manifest"].read_text(encoding="utf-8"))
            rows = [json.loads(line) for line in sources["results_jsonl"].read_text(encoding="utf-8").splitlines()]
            target = next(row for row in rows if row["repeat"] == 1)
            target["persisted_execution"].update({"material_unresolved_required_count": 1, "false_done_recovery_violation": True})
            summary = aggregate_model_results(rows, model=TARGET, split="validation", expected_matrix=_expected_matrix(experiment))
            self.assertEqual(summary["evaluation_state"], "CERTIFICATION_FAIL")
            self.assertIn("FALSE_DONE_WITH_MATERIAL_UNRESOLVED", summary["hard_gate_failure_types"])
            self.assertTrue(any(row["hard_gate_findings"] for row in rows))

    def test_all_clean_required_repetitions_build_certification_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = _model_sources(root, repeats=3, evidence_type="model_validation")
            evidence = _build_validation_evidence(root, sources)
            self.assertTrue(evidence["payload"]["hard_gate_pass"])
            self.assertEqual(evidence["payload"]["repetitions"], 3)

    def test_adapter_rejects_tampered_matrix_and_stability_summaries(self):
        for label, mutate in (
            ("matrix_complete", lambda summary: summary.update(certification_matrix_complete=False)),
            ("matrix_count", lambda summary: summary.update(certification_matrix_cell_count=summary["certification_matrix_cell_count"] + 1)),
            ("matrix_hash", lambda summary: summary.update(certification_matrix_sha256="0" * 64)),
            ("stability_count", lambda summary: next(iter(summary["stability_groups"].values())).update(repetitions=99)),
            ("stability_frequency", lambda summary: next(iter(summary["stability_groups"].values())).update(critical_frequency=0.5)),
            ("worst_frequency", lambda summary: summary.update(worst_case_critical_frequency=0.5)),
        ):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                sources = _model_sources(root, repeats=3, evidence_type="model_validation")
                summary = json.loads(sources["model_summary"].read_text(encoding="utf-8"))
                mutate(summary)
                _write(sources["model_summary"], summary)
                with self.assertRaises(AdapterError):
                    _build_validation_evidence(root, sources)

    def test_false_done_calibration_uses_persisted_execution_and_established_gates(self):
        cases = (
            (
                "unreadable uncertainty",
                {"run_phase": "NEEDS_REVIEW", "run_complete": False, "reported_run_complete": True, "material_unresolved_required_count": 1, "work_unit_states": {"u1": "NEEDS_REVIEW"}},
                {"FALSE_DONE_WITH_MATERIAL_UNRESOLVED"},
            ),
            (
                "cropped partial work unit",
                {"run_phase": "NEEDS_REVIEW", "run_complete": False, "reported_run_complete": True, "material_unresolved_required_count": 1, "work_unit_states": {"u1": "NEEDS_REVIEW"}},
                {"FALSE_DONE_WITH_MATERIAL_UNRESOLVED"},
            ),
            (
                "contradictory material conflict",
                {"run_phase": "COMPLETE", "run_complete": True, "reported_run_complete": True, "material_unresolved_required_count": 1, "unresolved_conflict_count": 1, "conflict_resolution_failure": True},
                {"FALSE_DONE_WITH_MATERIAL_UNRESOLVED", "MATERIAL_CONFLICT_RESOLUTION_FAILURE"},
            ),
            (
                "failed verification",
                {"run_phase": "COMPLETE", "run_complete": True, "reported_run_complete": True, "verification_status": "FAIL", "verification_critical_count": 1, "verification_contract_failure": True},
                {"FALSE_DONE_WITH_MATERIAL_UNRESOLVED", "ENGINE_EVIDENCE_CONTRACT_FAILURE"},
            ),
            (
                "under-evidenced completion",
                {"run_phase": "COMPLETE", "run_complete": True, "reported_run_complete": True, "work_unit_states": {}, "execution_contract_pass": False},
                {"FALSE_DONE_WITH_MATERIAL_UNRESOLVED"},
            ),
        )
        for index, (label, facts, expected) in enumerate(cases):
            with self.subTest(label=label):
                row = _model_result_row(
                    scenario_id=f"calibration-{index}", category="simple_mixed_text", split="validation", repeat=1,
                    item_identity=f"{index + 1:064x}", subject="a" * 40, deployment="b" * 64,
                )
                row["persisted_execution"].update(facts)
                findings = {item["code"] for item in derive_result_hard_gate_findings(row)}
                self.assertTrue(expected <= findings)


if __name__ == "__main__":
    unittest.main()
