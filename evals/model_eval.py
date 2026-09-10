"""Corpus-level OpenCode K-Slide model evaluator.

This runner is the certification boundary. It executes one isolated real
OpenCode command per artifact/repetition, then scores persisted K-Slide
artifacts rather than trusting terminal text or process exit status.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from k_slide.evidence_ir import load_evidence
from k_slide.ir import SlideIR
from k_slide import __version__

from .experiments import configuration_hash
from .certification import EvaluationState, certification_fingerprint, load_model_policy
from k_slide.certification import build_deployment_factors, deployment_fingerprint as deployment_identity
from .generator import DEFAULT_VARIANT, generate_artifacts
from .model_results import aggregate_model_results, write_results
from .model_scorers import score_deck_consistency, score_translation_patch
from .opencode_runner import OpenCodeEvalRunner, _latest_run
from .scenarios import DATASET_VERSION, Scenario, scenario_specs, split_manifest


def is_target_gemma(model: str, *, effective_model: str | None = None, policy: Any | None = None) -> bool:
    selected = policy or load_model_policy()
    return selected.approved(requested=model, effective=effective_model or model)


def _artifact_path(root: Path, scenario_id: str, format_name: str) -> Path:
    suffix = format_name.lower()
    return root / scenario_id / DEFAULT_VARIANT.name / suffix / f"source.{suffix}"


def collect_run_artifacts(run: Path | None) -> list[dict[str, Any]]:
    """Load every persisted translation/evidence/IR triple in a run."""

    if run is None:
        return []
    translations = sorted((run / "translations").glob("*.json")) if (run / "translations").is_dir() else []
    collected: list[dict[str, Any]] = []
    for patch_path in translations:
        try:
            patch = json.loads(patch_path.read_text(encoding="utf-8"))
            work_unit_id = str(patch["work_unit_id"])
            evidence = load_evidence(run, work_unit_id)
            ir_path = run / "ir" / f"{work_unit_id}.json"
            ir = SlideIR.from_dict(json.loads(ir_path.read_text(encoding="utf-8")))
            collected.append({"work_unit_id": work_unit_id, "evidence": evidence, "patch": patch, "slide_ir": ir, "patch_path": str(patch_path)})
        except (OSError, KeyError, TypeError, ValueError):
            continue
    return collected


def _aggregate_unit_semantics(unit_scores: list[dict[str, Any]]) -> dict[str, Any]:
    if not unit_scores:
        return {}
    numeric = ("coverage", "numeric_fidelity", "modality", "table_cell_fidelity", "visual_relation_recall")
    failures = sorted({failure for score in unit_scores for failure in score.get("critical_failures", [])})
    return {
        "unit_count": len(unit_scores),
        **{name: sum(float(score.get(name, 0.0)) for score in unit_scores) / len(unit_scores) for name in numeric},
        "critical_failures": failures,
        "units": unit_scores,
        "unresolved_region_rate": sum(float(score.get("unresolved_region_rate", 0.0)) for score in unit_scores) / len(unit_scores),
        "unexpected_unresolved_rate": sum(float(score.get("unexpected_unresolved_rate", 0.0)) for score in unit_scores) / len(unit_scores),
    }


def _engine_gate(run: Path | None, result: Any) -> tuple[str, list[str]]:
    failures: list[str] = []
    if result.status in {"BLOCKED", "INSTALL_FAILED", "TIMEOUT"}:
        failures.append(result.status)
    if run is None:
        failures.append("ENGINE_EVIDENCE_MISSING")
    else:
        try:
            state = json.loads((run / "RUN_STATE.json").read_text(encoding="utf-8"))
            if state.get("phase") in {"FAILED_NORMALIZATION", "FAILED_EXTRACTION", "FAILED_INTERNAL"}:
                failures.append(f"ENGINE_{state.get('phase')}")
        except (OSError, json.JSONDecodeError):
            failures.append("ENGINE_STATE_UNREADABLE")
    return ("PASS" if not failures else "ENGINE_BLOCKED"), failures


def _work_unit_contract(run: Path | None, artifacts: list[dict[str, Any]]) -> tuple[bool, list[str]]:
    """Require every queued unit to have one persisted scored artifact."""

    if run is None:
        return False, ["WORK_QUEUE_MISSING"]
    try:
        queue = json.loads((run / "WORK_QUEUE.json").read_text(encoding="utf-8"))
        units = queue.get("work_units", [])
        expected = {str(item.get("work_unit_id")) for item in units if isinstance(item, dict)}
        actual = {str(item.get("work_unit_id")) for item in artifacts}
        failures: list[str] = []
        if expected != actual:
            failures.append("WORK_UNIT_ARTIFACT_SET_MISMATCH")
        if any(str(item.get("status")) != "VERIFIED" for item in units if isinstance(item, dict)):
            failures.append("WORK_UNIT_NOT_VERIFIED")
        return not failures, failures
    except (OSError, json.JSONDecodeError, TypeError):
        return False, ["WORK_QUEUE_UNREADABLE"]


class ModelEvaluationRunner:
    def __init__(self, *, model: str, output: Path, split: str = "development", formats: tuple[str, ...] = ("png",), repeats: int = 1, timeout: int = 180, mode: str = "quality", limit: int | None = None, categories: tuple[str, ...] = (), scenario_ids: tuple[str, ...] = (), configuration: dict[str, Any] | None = None, ocr_provider: str = "none"):
        self.model = model
        self.output = output
        self.split = split
        self.formats = tuple(item.lower() for item in formats)
        self.repeats = repeats
        self.timeout = timeout
        self.mode = mode
        self.limit = limit
        self.categories = set(categories)
        self.scenario_ids = set(scenario_ids)
        self.ocr_provider = ocr_provider
        self.configuration = {"formats": self.formats, "repeats": repeats, "timeout": timeout, "mode": mode, "ocr_provider": ocr_provider, **(configuration or {})}

    def selected_scenarios(self) -> list[Scenario]:
        selected = scenario_specs()
        if self.split != "all":
            selected = [item for item in selected if item.split == self.split]
        if self.categories:
            selected = [item for item in selected if item.category in self.categories]
        if self.scenario_ids:
            selected = [item for item in selected if item.scenario_id in self.scenario_ids]
        return selected[: self.limit] if self.limit is not None else selected

    def run(self) -> dict[str, Any]:
        self.output.mkdir(parents=True, exist_ok=True)
        scenarios = self.selected_scenarios()
        manifest = split_manifest()
        model_policy = load_model_policy()
        repo_root = Path(__file__).resolve().parents[1]
        try:
            subject_result = subprocess.run(["git", "-C", str(repo_root), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=5, check=False)
            subject_sha = subject_result.stdout.strip() if subject_result.returncode == 0 else "UNSET"
        except (OSError, subprocess.TimeoutExpired):
            subject_sha = "UNSET"
        deployment = deployment_identity(build_deployment_factors(repo_root, subject_git_sha=subject_sha, runtime={"reported_model_id": self.model}, profile={"evaluation_configuration_hash": configuration_hash(self.configuration), "ocr_provider": self.ocr_provider}, model_policy=model_policy, corpus=manifest))
        run_manifest = {
            "experiment_id": self.output.name,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "git_commit": subject_sha,
            "subject_git_sha": subject_sha,
            "deployment_fingerprint": deployment,
            "k_slide_version": __version__,
            "corpus_version": DATASET_VERSION,
            "split": self.split,
            "scenario_ids": [item.scenario_id for item in scenarios],
            "formats": self.formats,
            "model": self.model,
            "runtime": "opencode",
            "repetitions": self.repeats,
            "configuration": self.configuration,
            "configuration_hash": configuration_hash(self.configuration),
            "certification_fingerprint": certification_fingerprint({"model": self.model, "configuration": self.configuration, "prompt_version": self.configuration.get("prompt_version"), "ocr_provider": self.configuration.get("ocr_provider"), "normalization": self.configuration.get("normalization"), "vision": self.configuration.get("vision"), "repair_policy": self.configuration.get("repair_policy")}),
            "split_manifest_hash": configuration_hash(manifest),
            "corpus_fingerprint": manifest["corpus_fingerprint"],
            "held_out_fingerprint": manifest["held_out_fingerprint"],
            "model_policy": {"approved_model_ids": list(model_policy.approved_model_ids), "approved_aliases": list(model_policy.approved_aliases)},
        }
        (self.output / "experiment.json").write_text(json.dumps(run_manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        if self.mode == "quality" and not model_policy.approved(requested=self.model, effective=self.model):
            record = {"status": "GEMMA_QUALITY_EVALUATION_BLOCKED", "evaluation_state": EvaluationState.CAPABILITY_BLOCKED.value, "reason": "GEMMA CERTIFICATION BLOCKED — target endpoint is not the selected model", "model": self.model, "split": self.split, "quality_metrics_authoritative": False}
            write_results(self.output, [], {**record, "case_count": 0}, "# K-Slide Model Evaluation\n\n`GEMMA CERTIFICATION BLOCKED`\n\nNon-target model runs are protocol smoke only.\n")
            return record
        try:
            corpus_root = self.output / "corpus" / "artifacts"
            generate_artifacts(scenarios, corpus_root, formats=self.formats, variants=(DEFAULT_VARIANT,))
        except Exception as exc:
            record = {"status": "CAPABILITY_BLOCK", "evaluation_state": EvaluationState.CAPABILITY_BLOCKED.value, "reason": f"Artifact generation unavailable: {exc}", "model": self.model, "split": self.split, "quality_metrics_authoritative": False}
            write_results(self.output, [], {**record, "case_count": 0}, "# K-Slide Model Evaluation\n\n`CAPABILITY_BLOCK`\n\n" + str(exc) + "\n")
            return record
        results: list[dict[str, Any]] = []
        runner = OpenCodeEvalRunner(model=self.model, timeout_seconds=self.timeout, ocr_policy=self.ocr_provider)
        for scenario in scenarios:
            for format_name in self.formats:
                artifact = _artifact_path(corpus_root, scenario.scenario_id, format_name)
                for repetition in range(1, self.repeats + 1):
                    workspace = self.output / "cases" / scenario.scenario_id / format_name / f"repeat-{repetition:02d}"
                    workspace.mkdir(parents=True, exist_ok=True)
                    result = runner.run(source=artifact, workspace=workspace, mode=self.mode)
                    latest = _latest_run(workspace)
                    artifacts = collect_run_artifacts(latest)
                    engine_gate, engine_failures = _engine_gate(latest, result)
                    units_complete, unit_contract_failures = _work_unit_contract(latest, artifacts)
                    engine_failures.extend(unit_contract_failures)
                    unit_scores = [
                        {"work_unit_id": item["work_unit_id"], **score_translation_patch(scenario, item["evidence"], item["patch"])}
                        for item in artifacts
                    ]
                    semantic = _aggregate_unit_semantics(unit_scores)
                    term_consistency = score_deck_consistency([item["patch"] for item in artifacts], scenario.gold)
                    semantic["term_consistency_recall"] = float(term_consistency["term_consistency_recall"])
                    semantic["inconsistent_alternate_count"] = int(term_consistency["inconsistent_alternate_count"])
                    semantic["critical_failures"] = sorted(set(semantic.get("critical_failures", [])) | set(term_consistency.get("critical_failures", [])))
                    effective_model = result.diagnostics.get("effective_model")
                    media_units = result.media_compliance.get("work_units", {})
                    media_valid = bool(artifacts) and all(media_units.get(item["work_unit_id"], {}).get("media_sequence_valid") is True for item in artifacts)
                    quality_contract = bool(
                        model_policy.approved(requested=self.model, effective=effective_model)
                        and result.diagnostics.get("model_identity_proven") is True
                        and result.status == "PASS"
                        and result.kslide_complete
                        and engine_gate == "PASS"
                        and units_complete
                        and artifacts
                        and len(artifacts) == len(media_units)
                        and media_valid
                    )
                    results.append({
                        "scenario_id": scenario.scenario_id,
                        "category": scenario.category,
                        "split": scenario.split,
                        "format": format_name,
                        "repeat": repetition,
                        "status": result.status,
                        "engine_gate": engine_gate,
                        "engine_failures": engine_failures,
                        "work_unit_contract": {"pass": units_complete, "failures": unit_contract_failures},
                        "semantic_scored": bool(unit_scores),
                        "semantic": semantic,
                        "units": [{"work_unit_id": item["work_unit_id"], "semantic": score} for item, score in zip(artifacts, unit_scores)],
                        "media_by_work_unit": media_units,
                        "quality_metrics_authoritative": quality_contract,
                        "opencode": result.as_dict(),
                    })
        summary = aggregate_model_results(results, model=self.model, split=self.split)
        summary["requested_model"] = self.model
        summary["configuration_hash"] = run_manifest["configuration_hash"]
        summary["corpus_fingerprint"] = manifest["corpus_fingerprint"]
        summary["held_out_fingerprint"] = manifest["held_out_fingerprint"]
        summary["repetitions"] = self.repeats
        summary["subject_git_sha"] = subject_sha
        summary["deployment_fingerprint"] = deployment
        summary["target_model_approved"] = model_policy.approved(requested=self.model, effective=next((item.get("opencode", {}).get("diagnostics", {}).get("effective_model") for item in results if item.get("opencode", {}).get("diagnostics", {}).get("effective_model")), None))
        if summary["quality_metrics_authoritative"] and summary.get("critical_failure_count", 0):
            summary["status"] = EvaluationState.CERTIFICATION_FAIL.value
        elif summary["quality_metrics_authoritative"]:
            summary["status"] = EvaluationState.MEASURED.value
        elif summary.get("evaluation_state") == EvaluationState.PROTOCOL_SMOKE_ONLY.value:
            summary["status"] = EvaluationState.PROTOCOL_SMOKE_ONLY.value
        elif self.mode == "quality" and summary.get("target_endpoint_blocked"):
            summary["status"] = "GEMMA_QUALITY_EVALUATION_BLOCKED"
        else:
            summary["status"] = "NON_AUTHORITATIVE"
        report = "\n".join([
            "# K-Slide Model Evaluation",
            "",
            f"Model: `{self.model}`",
            f"Split: `{self.split}`",
            f"Cases: `{len(results)}`",
            f"Semantic cases scored: `{summary['semantic_scored_case_count']}`",
            f"Quality metrics authoritative: `{summary['quality_metrics_authoritative']}`",
            f"Critical failures: `{summary['critical_failure_count']}`",
            "",
            "This report is authoritative only when the target Gemma model, actual OpenCode K-Slide workflow, complete artifacts, required media reads, and semantic scorers all pass.",
            "",
        ])
        write_results(self.output, results, summary, report)
        return summary
