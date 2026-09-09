"""Corpus-level OpenCode K-Slide model evaluator.

This runner is the certification boundary. It executes one isolated real
OpenCode command per artifact/repetition, then scores persisted K-Slide
artifacts rather than trusting terminal text or process exit status.
"""

from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from k_slide.evidence_ir import load_evidence
from k_slide.ir import SlideIR

from .experiments import configuration_hash
from .generator import DEFAULT_VARIANT, generate_artifacts
from .model_results import aggregate_model_results, write_results
from .model_scorers import score_translation_patch
from .opencode_runner import OpenCodeEvalRunner, _latest_run
from .scenarios import DATASET_VERSION, Scenario, scenario_specs, split_manifest


def is_target_gemma(model: str) -> bool:
    normalized = model.lower().strip()
    return normalized.endswith("gemma-4-31b-it") or normalized.endswith("gemma4-31b-it") or "/gemma-4-31b-it" in normalized


def _artifact_path(root: Path, scenario_id: str, format_name: str) -> Path:
    suffix = format_name.lower()
    return root / scenario_id / DEFAULT_VARIANT.name / suffix / f"source.{suffix}"


def _artifact_inputs(run: Path | None) -> tuple[Any | None, dict[str, Any] | None, SlideIR | None]:
    if run is None:
        return None, None, None
    translations = sorted((run / "translations").glob("*.json")) if (run / "translations").is_dir() else []
    if not translations:
        return None, None, None
    patch_path = translations[0]
    try:
        patch = json.loads(patch_path.read_text(encoding="utf-8"))
        work_unit_id = patch["work_unit_id"]
        evidence = load_evidence(run, work_unit_id)
        ir = SlideIR.from_dict(json.loads((run / "ir" / f"{work_unit_id}.json").read_text(encoding="utf-8")))
        return evidence, patch, ir
    except (OSError, KeyError, TypeError, ValueError):
        return None, None, None


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


class ModelEvaluationRunner:
    def __init__(self, *, model: str, output: Path, split: str = "development", formats: tuple[str, ...] = ("png",), repeats: int = 1, timeout: int = 180, mode: str = "quality", limit: int | None = None, categories: tuple[str, ...] = (), scenario_ids: tuple[str, ...] = (), configuration: dict[str, Any] | None = None):
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
        self.configuration = configuration or {"formats": self.formats, "repeats": repeats, "timeout": timeout, "mode": mode}

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
        run_manifest = {
            "experiment_id": self.output.name,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "git_commit": None,
            "k_slide_version": "0.3.2",
            "corpus_version": DATASET_VERSION,
            "split": self.split,
            "scenario_ids": [item.scenario_id for item in scenarios],
            "formats": self.formats,
            "model": self.model,
            "runtime": "opencode",
            "repetitions": self.repeats,
            "configuration": self.configuration,
            "configuration_hash": configuration_hash(self.configuration),
            "split_manifest_hash": configuration_hash(manifest),
        }
        (self.output / "experiment.json").write_text(json.dumps(run_manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        if self.mode == "quality" and not is_target_gemma(self.model):
            record = {"status": "GEMMA_QUALITY_EVALUATION_BLOCKED", "reason": "GEMMA CERTIFICATION BLOCKED — target endpoint is not the selected model", "model": self.model, "split": self.split, "quality_metrics_authoritative": False}
            write_results(self.output, [], {**record, "case_count": 0}, "# K-Slide Model Evaluation\n\n`GEMMA CERTIFICATION BLOCKED`\n\nNon-target model runs are protocol smoke only.\n")
            return record
        try:
            corpus_root = self.output / "corpus" / "artifacts"
            generate_artifacts(scenarios, corpus_root, formats=self.formats, variants=(DEFAULT_VARIANT,))
        except Exception as exc:
            record = {"status": "CAPABILITY_BLOCK", "reason": f"Artifact generation unavailable: {exc}", "model": self.model, "split": self.split, "quality_metrics_authoritative": False}
            write_results(self.output, [], {**record, "case_count": 0}, "# K-Slide Model Evaluation\n\n`CAPABILITY_BLOCK`\n\n" + str(exc) + "\n")
            return record
        results: list[dict[str, Any]] = []
        runner = OpenCodeEvalRunner(model=self.model, timeout_seconds=self.timeout)
        for scenario in scenarios:
            for format_name in self.formats:
                artifact = _artifact_path(corpus_root, scenario.scenario_id, format_name)
                for repetition in range(1, self.repeats + 1):
                    workspace = self.output / "cases" / scenario.scenario_id / format_name / f"repeat-{repetition:02d}"
                    workspace.mkdir(parents=True, exist_ok=True)
                    result = runner.run(source=artifact, workspace=workspace, mode=self.mode)
                    latest = _latest_run(workspace)
                    evidence, patch, slide_ir = _artifact_inputs(latest)
                    engine_gate, engine_failures = _engine_gate(latest, result)
                    semantic = score_translation_patch(scenario, evidence, patch) if evidence is not None and patch is not None else {}
                    effective_model = result.diagnostics.get("effective_model")
                    quality_contract = bool(
                        is_target_gemma(self.model)
                        and is_target_gemma(effective_model or "")
                        and result.diagnostics.get("model_identity_proven") is True
                        and result.status == "PASS"
                        and result.kslide_complete
                        and engine_gate == "PASS"
                        and patch
                        and slide_ir
                        and result.media_compliance.get("media_sequence_valid")
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
                        "semantic_scored": bool(semantic),
                        "semantic": semantic,
                        "quality_metrics_authoritative": quality_contract,
                        "opencode": result.as_dict(),
                    })
        summary = aggregate_model_results(results, model=self.model, split=self.split)
        if summary["quality_metrics_authoritative"]:
            summary["status"] = "PASS"
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
