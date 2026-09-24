from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from evals.model_eval import ModelEvaluationRunner
from evals.corpus_governance import public_synthetic_manifest
from evals.governed_corpus import case_matrix_fingerprint, governed_source_identity
from evals.scenarios import PROTECTED_CATEGORIES
from evals.generator import DEFAULT_VARIANT, generate_artifacts
from evals.model_scorers import score_translation_patch
from evals.scenarios import scenario_specs
from k_slide.certification import candidate_deployment_fingerprint, load_candidate_spec, resolve_candidate_spec
from k_slide.corpus_governance import (
    canonical_bytes,
    build_manifest,
    manifest_identity,
)
from k_slide.evidence_adapters import AdapterError, build_machine_evidence
from k_slide.evidence_ir import EvidenceIR, EvidenceRegion
from k_slide.model_policy import load_model_policy
from k_slide.quality_policy import QUALITY_POLICY_IDENTITY
from tests.test_certification_closure import _candidate_spec, _write


TARGET = "google/gemma-4-31b-it"


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _gold(category: str) -> dict:
    result = {"visible_items": 1, "expected_region_min": 1, "visual_elements": ["headline"]}
    if category == "modality_decision_state":
        result["modality"] = {"source_text": "상태 검토", "commitment": "under_review", "speech_act": "plan"}
    elif category == "financial_table":
        result["table"] = {"required_cells": [{"row": 0, "column": 0}], "header_roles": []}
    elif category == "chart":
        result["chart"] = {"chart_type": "line", "trend": "increasing"}
    elif category in {"process_diagram", "state_resume"}:
        result["process"] = {"nodes": [{"id": "step-1", "label": "단계"}], "relations": []}
    elif category == "cross_slide_consistency":
        result["locked_term"] = "AI Platform"
    elif category == "prompt_injection":
        result["prompt_injection_is_data"] = True
    return result


def _fixture(base: Path, role: str, *, active_ids: tuple[str, ...] | None = None, noncritical_assertions: list[dict] | None = None) -> dict:
    base = base.resolve()
    artifact_root = base / "approved-private-cases"
    artifact_root.mkdir()
    set_ids = {
        "public_synthetic_regression": "fixture-public",
        "private_representative": "fixture-private",
        "frozen_high_risk": "fixture-high-risk",
        "sealed_held_out": "fixture-sealed",
    }
    versions = {name: "v1" for name in set_ids}
    selected_categories = list(PROTECTED_CATEGORIES) if role == "frozen_high_risk" else ["simple_mixed_text"]
    active_ids = active_ids or tuple(f"{role}-case-{index + 1}" for index in range(len(selected_categories)))
    target_role_items = []
    raw_cases = []
    for index, (item_id, category) in enumerate(zip(active_ids, selected_categories)):
        protected_group = category if role == "frozen_high_risk" else None
        artifact_bytes = f"synthetic artifact {role} {item_id}".encode()
        artifact_rel = f"private artifact names/{item_id}-confidential.png"
        artifact_path = artifact_root / artifact_rel
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        artifact_path.write_bytes(artifact_bytes)
        artifact_hashes = {"png": _sha(artifact_bytes)}
        gold_contract = _gold(category)
        if noncritical_assertions is not None:
            gold_contract["noncritical_semantic_assertions"] = noncritical_assertions
        gold_value = {
            "schema_version": "1.0",
            "case": {
                "item_id": item_id,
                "role": role,
                "set_id": set_ids[role],
                "version": versions[role],
                "category": category,
                "protected_group": protected_group,
            },
            "gold": gold_contract,
        }
        gold_raw = canonical_bytes(gold_value) + b"\n"
        gold_rel = f"gold details/{item_id}-private-gold.json"
        gold_path = artifact_root / gold_rel
        gold_path.parent.mkdir(parents=True, exist_ok=True)
        gold_path.write_bytes(gold_raw)
        target_role_items.append({
            "item_id": item_id,
            "source_sha256": governed_source_identity(artifact_hashes),
            "gold_sha256": _sha(gold_raw),
            "state": "active",
        })
        raw_cases.append({
            "item_id": item_id,
            "category": category,
            "protected_group": protected_group,
            "artifacts": {"png": artifact_rel},
            "gold_path": gold_rel,
        })
    manifests = []
    for current_role, set_id in set_ids.items():
        if current_role == "public_synthetic_regression":
            manifests.append(public_synthetic_manifest())
            continue
        state = {"private_representative": "active", "frozen_high_risk": "frozen", "sealed_held_out": "sealed"}[current_role]
        if current_role == role:
            items = target_role_items
        else:
            category = PROTECTED_CATEGORIES[0] if current_role == "frozen_high_risk" else "simple_mixed_text"
            item_id = f"{current_role}-placeholder"
            source = _sha(f"source:{current_role}".encode())
            gold = _sha(f"gold:{current_role}".encode())
            if current_role == "frozen_high_risk":
                items = [{"item_id": item_id, "source_sha256": source, "gold_sha256": gold, "state": "active"}]
            else:
                items = [{"item_id": item_id, "source_sha256": source, "gold_sha256": gold, "state": "active"}]
        authority = "approved_private_evaluation" if current_role == "private_representative" else "evaluation_governance"
        manifests.append(build_manifest(
            set_id=set_id,
            role=current_role,
            version="v1",
            state=state,
            items=items,
            provenance={"authority": authority, "record_sha256": _sha(f"record:{current_role}".encode())},
        ))
    evaluated = next(item for item in manifests if item["role"] == role)
    identity = manifest_identity(evaluated)
    descriptor = {"schema_version": "1.0", "corpus_set_identity": identity, "cases": raw_cases}
    _write(artifact_root / "cases.json", descriptor)
    manifest_dir = base / "manifests"
    manifest_dir.mkdir()
    manifest_path = manifest_dir / "evaluated.json"
    manifest_path.write_bytes(canonical_bytes(evaluated) + b"\n")
    bundle_path = manifest_dir / "bundle.json"
    bundle_path.write_bytes(canonical_bytes(manifests) + b"\n")
    history_path = manifest_dir / "history.json"
    history_path.write_bytes(b"[]\n")
    contamination_path = None
    if role == "sealed_held_out":
        contamination_path = manifest_dir / "contamination.json"
        contamination_path.write_bytes(canonical_bytes({"schema_version": "1.0", "set_id": identity["set_id"], "version": identity["version"], "items": []}) + b"\n")
    corpus_identity = {"schema_version": "1.0", "sets": [manifest_identity(item) for item in manifests]}
    subject = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    candidate = _candidate_spec(subject)
    candidate["corpus_identity"] = corpus_identity
    candidate = resolve_candidate_spec(candidate, root=Path.cwd(), subject_git_sha=subject, model_policy=load_model_policy(), corpus=corpus_identity)
    candidate_path = base / "candidate.json"
    _write(candidate_path, candidate)
    return {
        "root": artifact_root,
        "manifest": manifest_path,
        "bundle": bundle_path,
        "history": history_path,
        "contamination": contamination_path,
        "candidate": candidate_path,
        "manifests": manifests,
        "evaluated": evaluated,
        "descriptor": descriptor,
        "role": role,
    }


def _fake_runtime():
    class FakeOpenCode:
        def run(self, **_kwargs):
            unit_media = {
                "required_context_image_read": True, "required_crop_recall": 1.0,
                "media_sequence_valid": True, "submit_observed": True,
                "items": [{"id": "context_image", "read_observed": True, "read_before_submit": True}],
            }
            media = {"u1": unit_media}
            return SimpleNamespace(
                status="PASS",
                reason=None,
                runtime_version="1.3.9",
                kslide_complete=True,
                media_compliance={"work_units": media},
                diagnostics={"effective_model": TARGET, "model_identity_proven": True},
                events=[{"type": "tool_result", "tool": "kslide_submit"}],
                as_dict=lambda: {
                    "status": "PASS", "mode": "quality", "model": TARGET,
                    "runtime_version": "1.3.9", "workspace": "/Users/private-user/private-root",
                    "final_text": "private source translation", "event_count": 2, "kslide_complete": True,
                    "tool_calls": [], "forbidden_attempts": [], "media_compliance": {
                        "planned": True, "required_count": 1, "read_count": 1,
                        "required_context_image_read": True, "required_crop_recall": 1.0,
                        "media_sequence_valid": True,
                        "work_units": {"u1": unit_media},
                    },
                    "diagnostics": {"effective_model": TARGET, "model_identity_proven": True, "mixed_effective_model_ids": False, "read_policy_violations": [], "RUN_STATE.json": {"source_text": "private source"}},
                },
            )

    runtime = SimpleNamespace(as_dict=lambda: {
        "opencode_version": "1.3.9", "python_version": "3.11.0", "provider": "google", "ocr_provider": "none",
        "opencode_path": "/opt/private-user/bin/opencode", "opencode_config_path": "/srv/confidential/opencode.json",
    })
    scored = {
        "coverage": 1.0,
        "numeric_fidelity": 1.0,
        "modality": 1.0,
        "table_cell_fidelity": 1.0,
        "chart_semantic_score": 1.0,
        "process_relation_score": 1.0,
        "visual_relation_recall": 1.0,
        "critical_failures": [],
        "unresolved_region_rate": 0.0,
        "unexpected_unresolved_rate": 0.0,
        "critical_axis_minimum_diagnostic": 1.0,
        "noncritical_semantic_observations": [], "noncritical_semantic_required_count": 0,
        "noncritical_semantic_correct_count": 0, "noncritical_semantic_equivalence": 1.0,
        "unresolved_ids": [],
        "unresolved_count": 0,
        "material_unresolved_required_ids": [],
        "material_unresolved_observed_ids": [],
        "material_unresolved_false_negative_ids": [],
        "unresolved_false_positive_ids": [],
        "material_unresolved_recall": 1.0,
        "unresolved_precision": 1.0,
        "hard_gate_evidence": {
            "missing_required_region_ids": [], "numeric_mismatch_fact_ids": [],
            "modality_score": 1.0, "modality_source_binding_failure": False,
            "noncritical_semantic_source_binding_failure": False,
            "hangul_violation_count": 0, "unsupported_claim_count": 0,
            "executive_claim_failure_codes": [], "duplicate_region_ids": [],
            "table_cardinality_mismatch": False, "table_failure_codes": [],
            "table_header_failure_ids": [], "chart_failure_codes": [], "process_failure_codes": [],
            "material_unresolved_required_ids": [], "material_unresolved_observed_ids": [],
        },
        "numeric_details": [{"target_text": "private scored content"}],
        "modality_detail": {"source_hint": "private source"},
    }
    consistency = {"term_consistency_recall": 1.0, "inconsistent_alternate_count": 0, "critical_failures": []}
    return FakeOpenCode(), runtime, scored, consistency


def _run_fixture(fixture: dict, *, repeats: int | None = None, scenario_ids: tuple[str, ...] = (), scorer=None, **overrides):
    fake, runtime, scored, consistency = _fake_runtime()
    defaults = {
        "model": TARGET,
        "output": fixture["root"].parent / "results",
        "split": "held_out" if fixture["role"] == "sealed_held_out" else "validation",
        "formats": ("png",),
        "repeats": repeats,
        "mode": "quality",
        "candidate_profile": fixture["candidate"],
        "corpus_source": "governed_external",
        "governed_manifest": fixture["manifest"],
        "governed_manifest_bundle": fixture["bundle"],
        "governed_history": fixture["history"],
        "evaluation_purpose": {"private_representative": "private_evaluation", "frozen_high_risk": "comparison", "sealed_held_out": "promotion"}[fixture["role"]],
        "artifact_root": fixture["root"],
        "case_descriptor": "cases.json",
        "contamination_report": fixture["contamination"],
        "scenario_ids": scenario_ids,
    }
    defaults.update(overrides)
    run = defaults["output"] / "fixture-run"
    (run / "verification").mkdir(parents=True, exist_ok=True)
    _write(run / "WORK_QUEUE.json", {"work_units": [{"work_unit_id": "u1", "status": "VERIFIED"}]})
    _write(run / "RUN_STATE.json", {"phase": "COMPLETE"})
    (run / "RUN_COMPLETE.md").write_text("verified fixture completion\n", encoding="utf-8")
    _write(run / "verification" / "summary.json", {"status": "PASS", "critical_count": 0, "issues": []})
    runner = ModelEvaluationRunner(**defaults)
    patches = (
        patch("evals.model_eval.OpenCodeEvalRunner", return_value=fake),
        patch("evals.model_eval.discover_runtime", return_value=runtime),
        patch("evals.model_eval._latest_run", return_value=run),
        patch("evals.model_eval.collect_run_artifacts", return_value=[{"work_unit_id": "u1", "evidence": {}, "patch": {}, "slide_ir": None}]),
        patch("evals.model_eval._engine_gate", return_value=("PASS", [])),
        patch("evals.model_eval._work_unit_contract", return_value=(True, [])),
        patch("evals.model_eval.score_translation_patch", side_effect=scorer) if scorer is not None else patch("evals.model_eval.score_translation_patch", return_value=scored),
        patch("evals.model_eval.score_deck_consistency", return_value=consistency),
    )
    with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7]:
        result = runner.run()
    return result, defaults["output"]


class KSA26GovernedRunnerTests(unittest.TestCase):
    def _assert_adapter_accepts(self, fixture: dict, output: Path, evidence_type: str):
        candidate = load_candidate_spec(fixture["candidate"], root=Path.cwd(), require_identity=True)
        experiment = json.loads((output / "experiment.json").read_text(encoding="utf-8"))
        evidence = output / "evidence.json"
        build_machine_evidence(
            evidence,
            evidence_type=evidence_type,
            subject_git_sha=experiment["subject_git_sha"],
            deployment_fingerprint=experiment["deployment_fingerprint"],
            sources={"model_summary": output / "summary.json", "experiment_manifest": output / "experiment.json", "results_jsonl": output / "results.jsonl"},
            root=Path.cwd(),
            candidate_spec=candidate,
        )
        return json.loads(evidence.read_text(encoding="utf-8"))

    def test_private_representative_executes_and_adapter_accepts_exact_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = _fixture(Path(directory), "private_representative")
            with patch("evals.model_eval.scenario_specs", side_effect=AssertionError("public registry membership consulted")), patch("evals.model_eval.generate_artifacts") as generate:
                result, output = _run_fixture(fixture, repeats=3)
            self.assertTrue(result["quality_metrics_authoritative"], msg=json.dumps(result, sort_keys=True))
            self.assertEqual(result["quality_policy_identity"], QUALITY_POLICY_IDENTITY)
            self.assertEqual(result["corpus_set_identity"]["role"], "private_representative")
            experiment = json.loads((output / "experiment.json").read_text(encoding="utf-8"))
            self.assertEqual(experiment["quality_policy_identity"], QUALITY_POLICY_IDENTITY)
            self.assertTrue(all(json.loads(line)["quality_policy_identity"] == QUALITY_POLICY_IDENTITY for line in (output / "results.jsonl").read_text(encoding="utf-8").splitlines()))
            generate.assert_not_called()
            evidence = self._assert_adapter_accepts(fixture, output, "model_validation")
            self.assertEqual(evidence["payload"]["corpus_set_identity"]["set_id"], "fixture-private")

    def test_hash_bound_private_assertions_score_and_persist_without_gold_text(self):
        assertion_id = "ncs-0123456789abcdef01234567"
        private_source = "비공개 보조 설명 문구"
        private_accepted = "approved secondary descriptive detail"
        assertion = {
            "assertion_id": assertion_id,
            "surface": "region",
            "source_text": private_source,
            "accepted_phrases": [private_accepted, "approved supporting business detail"],
        }
        with tempfile.TemporaryDirectory() as directory:
            fixture = _fixture(Path(directory), "private_representative", noncritical_assertions=[assertion])

            def scorer(scenario, _evidence, _patch):
                evidence = EvidenceIR("opaque-doc", "u1", {}, (
                    EvidenceRegion("region-private", selected_literal_candidate=private_source),
                )).with_revision()
                return score_translation_patch(scenario, evidence, {
                    "regions": [{"region_id": "region-private", "english": private_accepted}],
                })

            result, output = _run_fixture(fixture, repeats=3, scorer=scorer)
            self.assertTrue(result["quality_metrics_authoritative"])
            persisted = "".join(path.read_text(encoding="utf-8") for path in output.iterdir() if path.is_file())
            self.assertIn(assertion_id, persisted)
            self.assertIn("CORRECT", persisted)
            self.assertNotIn(private_source, persisted)
            self.assertNotIn(private_accepted, persisted)
            case_gold = json.loads((fixture["root"] / fixture["descriptor"]["cases"][0]["gold_path"]).read_text(encoding="utf-8"))
            self.assertEqual(case_gold["gold"]["noncritical_semantic_assertions"][0]["accepted_phrases"][0], private_accepted)
            evidence = self._assert_adapter_accepts(fixture, output, "model_validation")
            self.assertEqual(evidence["payload"]["noncritical_semantic_required_count"], 1 * 3)
            self.assertEqual(evidence["payload"]["noncritical_semantic_correct_count"], 1 * 3)

    def test_governed_assertion_gold_mutation_is_rejected_by_hash_before_execution(self):
        assertion = {
            "assertion_id": "ncs-fedcba9876543210fedcba98",
            "surface": "region",
            "source_text": "비공개 변경 검증",
            "accepted_phrases": ["approved private meaning"],
        }
        for field, replacement in (("accepted_phrases", ["tampered private meaning"]), ("assertion_id", "ncs-aaaaaaaaaaaaaaaaaaaaaaaa")):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                fixture = _fixture(Path(directory), "private_representative", noncritical_assertions=[assertion])
                gold_path = fixture["root"] / fixture["descriptor"]["cases"][0]["gold_path"]
                gold = json.loads(gold_path.read_text(encoding="utf-8"))
                gold["gold"]["noncritical_semantic_assertions"][0][field] = replacement
                gold_path.write_bytes(canonical_bytes(gold) + b"\n")
                output = fixture["root"].parent / "tampered-gold"
                fake, *_ = _fake_runtime()
                with patch("evals.model_eval.OpenCodeEvalRunner", return_value=fake) as execute:
                    blocked = ModelEvaluationRunner(
                        model=TARGET, output=output, split="validation", formats=("png",), repeats=3, mode="quality",
                        candidate_profile=fixture["candidate"], corpus_source="governed_external",
                        governed_manifest=fixture["manifest"], governed_manifest_bundle=fixture["bundle"],
                        governed_history=fixture["history"], evaluation_purpose="private_evaluation",
                        artifact_root=fixture["root"], case_descriptor="cases.json",
                    ).run()
                self.assertEqual(blocked["status"], "CANDIDATE_PROFILE_BLOCKED")
                execute.assert_not_called()

    def test_frozen_high_risk_uses_governed_protected_groups_and_repeats(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = _fixture(Path(directory), "frozen_high_risk")
            result, output = _run_fixture(fixture, repeats=5)
            self.assertEqual(result["case_count"], len(PROTECTED_CATEGORIES) * 5)
            experiment = json.loads((output / "experiment.json").read_text(encoding="utf-8"))
            self.assertEqual(set(experiment["high_risk_categories"]), set(PROTECTED_CATEGORIES))
            evidence = self._assert_adapter_accepts(fixture, output, "model_high_risk_stability")
            self.assertEqual(set(evidence["payload"]["category_coverage"]), set(PROTECTED_CATEGORIES))

    def test_sealed_held_out_requires_empty_report_and_adapter_accepts(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = _fixture(Path(directory), "sealed_held_out")
            result, output = _run_fixture(fixture, repeats=3)
            self.assertEqual(result["evaluation_purpose"], "promotion")
            self._assert_adapter_accepts(fixture, output, "model_held_out")
            report = json.loads(fixture["contamination"].read_text(encoding="utf-8"))
            item = fixture["evaluated"]["items"][0]
            report["items"] = [{"item_id": item["item_id"], "source_sha256": item["source_sha256"], "gold_sha256": item["gold_sha256"], "context": "development"}]
            _write(fixture["contamination"], report)
            output2 = fixture["root"].parent / "rejected"
            fake, *_ = _fake_runtime()
            with patch("evals.model_eval.OpenCodeEvalRunner", return_value=fake) as execute:
                blocked = ModelEvaluationRunner(
                    model=TARGET, output=output2, split="held_out", formats=("png",), repeats=3, mode="quality",
                    candidate_profile=fixture["candidate"], corpus_source="governed_external",
                    governed_manifest=fixture["manifest"], governed_manifest_bundle=fixture["bundle"],
                    governed_history=fixture["history"], evaluation_purpose="promotion", artifact_root=fixture["root"],
                    case_descriptor="cases.json", contamination_report=fixture["contamination"],
                ).run()
            self.assertEqual(blocked["status"], "CANDIDATE_PROFILE_BLOCKED")
            execute.assert_not_called()

    def test_candidate_bundle_membership_and_private_content_fail_closed_without_logging_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = _fixture(Path(directory), "private_representative")
            identity = json.loads(fixture["candidate"].read_text(encoding="utf-8"))["corpus_identity"]
            # Candidate identity drift is rejected before constructing the model runner.
            identity["sets"][1]["version"] = "v-mismatch"
            candidate = json.loads(fixture["candidate"].read_text(encoding="utf-8"))
            candidate["corpus_identity"] = identity
            _write(fixture["candidate"], candidate)
            output = fixture["root"].parent / "mismatch"
            fake, *_ = _fake_runtime()
            with patch("evals.model_eval.OpenCodeEvalRunner", return_value=fake) as execute:
                blocked = ModelEvaluationRunner(
                    model=TARGET, output=output, split="validation", formats=("png",), repeats=3, mode="quality",
                    candidate_profile=fixture["candidate"], corpus_source="governed_external",
                    governed_manifest=fixture["manifest"], governed_manifest_bundle=fixture["bundle"],
                    evaluation_purpose="private_evaluation", artifact_root=fixture["root"], case_descriptor="cases.json",
                ).run()
            self.assertEqual(blocked["status"], "CANDIDATE_PROFILE_BLOCKED")
            execute.assert_not_called()
            persisted = "".join(path.read_text(encoding="utf-8") for path in output.iterdir() if path.is_file())
            self.assertNotIn(str(fixture["root"]), persisted)
            self.assertNotIn("confidential.png", persisted)
            self.assertNotIn("private source", persisted)

    def test_governed_outputs_omit_absolute_runtime_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = _fixture(Path(directory), "private_representative")
            result, output = _run_fixture(fixture, repeats=3)
            self.assertTrue(result["quality_metrics_authoritative"])
            persisted = "".join(path.read_text(encoding="utf-8") for path in output.iterdir() if path.is_file())
            self.assertNotIn("/opt/private-user", persisted)
            self.assertNotIn("/srv/confidential", persisted)

    def test_descriptor_cannot_relabel_private_item_as_public_scenario(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = _fixture(Path(directory), "private_representative")
            descriptor = fixture["descriptor"]
            descriptor["cases"][0]["item_id"] = "scenario-0001"
            _write(fixture["root"] / "cases.json", descriptor)
            output = fixture["root"].parent / "relabelled"
            fake, *_ = _fake_runtime()
            with patch("evals.model_eval.OpenCodeEvalRunner", return_value=fake) as execute:
                result = ModelEvaluationRunner(
                    model=TARGET, output=output, split="validation", formats=("png",), repeats=3, mode="quality",
                    candidate_profile=fixture["candidate"], corpus_source="governed_external",
                    governed_manifest=fixture["manifest"], governed_manifest_bundle=fixture["bundle"],
                    evaluation_purpose="private_evaluation", artifact_root=fixture["root"], case_descriptor="cases.json",
                ).run()
            self.assertEqual(result["status"], "CANDIDATE_PROFILE_BLOCKED")
            execute.assert_not_called()

    def test_external_descriptor_hash_paths_and_public_artifacts_fail_before_execution(self):
        for mutation in ("set_identity", "membership", "artifact_hash", "gold_hash", "traversal", "symlink", "public_generator"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                fixture = _fixture(Path(directory), "private_representative")
                descriptor = json.loads((fixture["root"] / "cases.json").read_text(encoding="utf-8"))
                if mutation == "set_identity":
                    descriptor["corpus_set_identity"]["version"] = "v-wrong"
                    _write(fixture["root"] / "cases.json", descriptor)
                elif mutation == "membership":
                    descriptor["cases"] = []
                    _write(fixture["root"] / "cases.json", descriptor)
                elif mutation == "artifact_hash":
                    artifact = fixture["root"] / descriptor["cases"][0]["artifacts"]["png"]
                    artifact.write_bytes(b"changed artifact bytes")
                elif mutation == "gold_hash":
                    gold = fixture["root"] / descriptor["cases"][0]["gold_path"]
                    gold.write_bytes(gold.read_bytes() + b" ")
                elif mutation == "traversal":
                    descriptor["cases"][0]["artifacts"]["png"] = "../outside.png"
                    _write(fixture["root"] / "cases.json", descriptor)
                elif mutation == "symlink":
                    original = fixture["root"] / descriptor["cases"][0]["artifacts"]["png"]
                    link = fixture["root"] / "linked.png"
                    link.symlink_to(original)
                    descriptor["cases"][0]["artifacts"]["png"] = "linked.png"
                    _write(fixture["root"] / "cases.json", descriptor)
                else:
                    _write(fixture["root"] / "CORPUS_MANIFEST.json", {"schema_version": "1.0", "scenario_count": 1, "variants": [{"name": "default"}], "formats": ["png"]})
                output = fixture["root"].parent / "blocked"
                fake, *_ = _fake_runtime()
                with patch("evals.model_eval.OpenCodeEvalRunner", return_value=fake) as execute:
                    result = ModelEvaluationRunner(
                        model=TARGET, output=output, split="validation", formats=("png",), repeats=3, mode="quality",
                        candidate_profile=fixture["candidate"], corpus_source="governed_external",
                        governed_manifest=fixture["manifest"], governed_manifest_bundle=fixture["bundle"],
                        governed_history=fixture["history"], evaluation_purpose="private_evaluation",
                        artifact_root=fixture["root"], case_descriptor="cases.json",
                    ).run()
                self.assertEqual(result["status"], "CANDIDATE_PROFILE_BLOCKED")
                execute.assert_not_called()

    def test_renamed_public_artifact_bytes_fail_without_generator_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = _fixture(Path(directory), "private_representative")
            public_root = fixture["root"].parent / "public-material"
            public_scenario = scenario_specs()[0]
            generate_artifacts([public_scenario], public_root, formats=("png",), variants=(DEFAULT_VARIANT,))
            public_artifact = public_root / public_scenario.scenario_id / DEFAULT_VARIANT.name / "png" / "source.png"
            case = fixture["descriptor"]["cases"][0]
            local_artifact = fixture["root"] / case["artifacts"]["png"]
            local_artifact.write_bytes(public_artifact.read_bytes())

            digest = _sha(public_artifact.read_bytes())
            source_identity = governed_source_identity({"png": digest})
            updated_items = [dict(item) for item in fixture["evaluated"]["items"]]
            updated_items[0]["source_sha256"] = source_identity
            updated_manifest = build_manifest(
                set_id=fixture["evaluated"]["set_id"],
                role=fixture["evaluated"]["role"],
                version=fixture["evaluated"]["version"],
                state=fixture["evaluated"]["state"],
                items=updated_items,
                provenance=fixture["evaluated"]["provenance"],
            )
            manifests = [updated_manifest if item["role"] == "private_representative" else item for item in fixture["manifests"]]
            fixture["manifest"].write_bytes(canonical_bytes(updated_manifest) + b"\n")
            fixture["bundle"].write_bytes(canonical_bytes(manifests) + b"\n")
            case["item_id"] = updated_items[0]["item_id"]
            descriptor = {
                "schema_version": "1.0",
                "corpus_set_identity": manifest_identity(updated_manifest),
                "cases": fixture["descriptor"]["cases"],
            }
            _write(fixture["root"] / "cases.json", descriptor)
            candidate = load_candidate_spec(fixture["candidate"], root=Path.cwd(), require_identity=False, strict=True)
            corpus_identity = {"schema_version": "1.0", "sets": [manifest_identity(item) for item in manifests]}
            candidate["corpus_identity"] = corpus_identity
            candidate = resolve_candidate_spec(candidate, root=Path.cwd(), subject_git_sha=candidate["subject_git_sha"], model_policy=load_model_policy(), corpus=corpus_identity)
            _write(fixture["candidate"], candidate)

            output = fixture["root"].parent / "public-clone-rejected"
            fake, *_ = _fake_runtime()
            with patch("evals.model_eval.OpenCodeEvalRunner", return_value=fake) as execute:
                result = ModelEvaluationRunner(
                    model=TARGET, output=output, split="validation", formats=("png",), repeats=3, mode="quality",
                    candidate_profile=fixture["candidate"], corpus_source="governed_external",
                    governed_manifest=fixture["manifest"], governed_manifest_bundle=fixture["bundle"],
                    evaluation_purpose="private_evaluation", artifact_root=fixture["root"], case_descriptor="cases.json",
                ).run()
            self.assertEqual(result["status"], "CANDIDATE_PROFILE_BLOCKED")
            execute.assert_not_called()

    def test_scenario_filter_must_equal_active_membership_and_public_split_label_has_no_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = _fixture(Path(directory), "private_representative")
            active = fixture["evaluated"]["items"][0]["item_id"]
            fake, *_ = _fake_runtime()
            output = fixture["root"].parent / "subset"
            with patch("evals.model_eval.OpenCodeEvalRunner", return_value=fake) as execute:
                result = ModelEvaluationRunner(
                    model=TARGET, output=output, split="validation", formats=("png",), repeats=3, mode="quality",
                    candidate_profile=fixture["candidate"], corpus_source="governed_external",
                    governed_manifest=fixture["manifest"], governed_manifest_bundle=fixture["bundle"],
                    evaluation_purpose="private_evaluation", artifact_root=fixture["root"], case_descriptor="cases.json",
                    scenario_ids=("unknown-item",),
                ).run()
            self.assertEqual(result["status"], "CANDIDATE_PROFILE_BLOCKED")
            execute.assert_not_called()

    def test_sealed_held_out_requires_a_well_formed_empty_report(self):
        for report_state in ("missing", "malformed"):
            with self.subTest(report_state=report_state), tempfile.TemporaryDirectory() as directory:
                fixture = _fixture(Path(directory), "sealed_held_out")
                if report_state == "missing":
                    fixture["contamination"].unlink()
                else:
                    fixture["contamination"].write_text("{}\n", encoding="utf-8")
                fake, *_ = _fake_runtime()
                output = fixture["root"].parent / "blocked"
                with patch("evals.model_eval.OpenCodeEvalRunner", return_value=fake) as execute:
                    result = ModelEvaluationRunner(
                        model=TARGET, output=output, split="held_out", formats=("png",), repeats=3, mode="quality",
                        candidate_profile=fixture["candidate"], corpus_source="governed_external",
                        governed_manifest=fixture["manifest"], governed_manifest_bundle=fixture["bundle"],
                        evaluation_purpose="promotion", artifact_root=fixture["root"], case_descriptor="cases.json",
                        contamination_report=fixture["contamination"],
                    ).run()
                self.assertEqual(result["status"], "CANDIDATE_PROFILE_BLOCKED")
                execute.assert_not_called()

    def test_adapter_reload_rejects_case_metadata_result_and_contract_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = _fixture(Path(directory), "private_representative")
            _result, output = _run_fixture(fixture, repeats=3)
            candidate = load_candidate_spec(fixture["candidate"], root=Path.cwd(), require_identity=True)
            mutations = (
                ("purpose", lambda experiment, summary, rows: experiment.update(evaluation_purpose="regression")),
                ("manifest_bundle", lambda experiment, summary, rows: experiment.update(governed_corpus_manifests=experiment["governed_corpus_manifests"][:1])),
                ("case_identity", lambda experiment, summary, rows: experiment["case_matrix"][0].update(gold_sha256="0" * 64)),
                ("assertion_ids", lambda experiment, summary, rows: experiment["case_matrix"][0].update(noncritical_semantic_assertion_ids=["ncs-aaaaaaaaaaaaaaaaaaaaaaaa"])),
                ("category", lambda experiment, summary, rows: experiment["case_matrix"][0].update(category="chart")),
                ("group", lambda experiment, summary, rows: experiment["case_matrix"][0].update(protected_group="chart")),
                ("result_id", lambda experiment, summary, rows: rows[0].update(scenario_id="renamed")),
                ("format", lambda experiment, summary, rows: rows[0].update(format="pdf")),
                ("repetition", lambda experiment, summary, rows: rows[0].update(repeat=99)),
            )
            for label, mutate in mutations:
                with self.subTest(label=label):
                    pristine = {name: (output / name).read_bytes() for name in ("experiment.json", "summary.json", "results.jsonl")}
                    experiment = json.loads(pristine["experiment.json"])
                    summary = json.loads(pristine["summary.json"])
                    rows = [json.loads(line) for line in pristine["results.jsonl"].splitlines()]
                    mutate(experiment, summary, rows)
                    _write(output / "experiment.json", experiment)
                    _write(output / "summary.json", summary)
                    (output / "results.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
                    with self.assertRaises(AdapterError):
                        build_machine_evidence(
                            output / "tampered-evidence.json", evidence_type="model_validation",
                            subject_git_sha=experiment["subject_git_sha"], deployment_fingerprint=experiment["deployment_fingerprint"],
                            sources={"model_summary": output / "summary.json", "experiment_manifest": output / "experiment.json", "results_jsonl": output / "results.jsonl"},
                            root=Path.cwd(), candidate_spec=candidate,
                        )
                    for name, content in pristine.items():
                        (output / name).write_bytes(content)


if __name__ == "__main__":
    unittest.main()
