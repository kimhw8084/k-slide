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

from .experiments import behavior_configuration, behavior_configuration_hash, experiment_plan, experiment_plan_hash
from .certification import EvaluationState, load_model_policy
from k_slide.certification import (
    CANDIDATE_SPEC_SCHEMA_VERSION,
    EvidenceValidationError,
    candidate_deployment_fingerprint,
    canonical_candidate_factors,
    canonical_corpus_identity,
    canonical_bytes,
    load_candidate_spec,
    resolve_candidate_spec,
    sha256_bytes,
)
from k_slide.runtime import discover_runtime
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
    def __init__(self, *, model: str, output: Path, split: str = "development", formats: tuple[str, ...] = ("png",), repeats: int = 1, timeout: int = 180, mode: str = "quality", limit: int | None = None, categories: tuple[str, ...] = (), scenario_ids: tuple[str, ...] = (), configuration: dict[str, Any] | None = None, ocr_provider: str = "none", candidate_profile: Path | None = None, high_risk: bool = False, model_policy: Any | None = None):
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
        self.configuration = dict(configuration or {})
        self.behavior_configuration = behavior_configuration(self.configuration, model=model, ocr_provider=ocr_provider)
        self.candidate_profile = candidate_profile.expanduser() if candidate_profile is not None else None
        self.high_risk = high_risk
        self.authoritative_policy = model_policy

    def selected_scenarios(self) -> list[Scenario]:
        selected = scenario_specs()
        if self.split != "all":
            selected = [item for item in selected if item.split == self.split]
        if self.high_risk:
            protected = __import__("evals.scenarios", fromlist=["PROTECTED_CATEGORIES"]).PROTECTED_CATEGORIES
            selected = [next(item for item in selected if item.category == category) for category in protected]
        if self.categories:
            selected = [item for item in selected if item.category in self.categories]
        if self.scenario_ids:
            selected = [item for item in selected if item.scenario_id in self.scenario_ids]
        return selected[: self.limit] if self.limit is not None else selected

    def _candidate_spec(self, repo_root: Path, subject_sha: str, manifest: dict[str, Any], model_policy: Any) -> dict[str, Any]:
        corpus = canonical_corpus_identity(manifest)
        if self.candidate_profile is not None:
            spec = load_candidate_spec(self.candidate_profile, root=repo_root, require_identity=False, strict=True)
        else:
            spec = {
                "schema_version": CANDIDATE_SPEC_SCHEMA_VERSION,
                "subject_git_sha": subject_sha,
                "kslide_version": __version__,
                "requested_model": self.model,
                "effective_model": "UNSET",
                "ocr_provider": self.ocr_provider,
                "behavior_configuration": self.behavior_configuration,
            }
        if str(spec.get("requested_model") or self.model) != self.model:
            raise EvidenceValidationError("candidate requested_model does not match evaluation model")
        if spec.get("subject_git_sha") not in {None, "", "UNSET", subject_sha}:
            raise EvidenceValidationError("candidate subject_git_sha does not match evaluation subject")
        declared_ocr = str(spec.get("ocr_provider") or "")
        if declared_ocr and declared_ocr.upper() != "UNSET" and declared_ocr != self.ocr_provider:
            raise EvidenceValidationError("candidate ocr_provider does not match evaluation provider")
        spec["subject_git_sha"] = subject_sha
        spec["requested_model"] = self.model
        spec["ocr_provider"] = self.ocr_provider
        spec = resolve_candidate_spec(
            spec,
            root=repo_root,
            subject_git_sha=subject_sha,
            model_policy=model_policy,
            corpus=corpus,
            require_sources=self.mode == "quality" and (self.split in {"validation", "held_out"} or self.high_risk),
        )
        spec["behavior_configuration"] = behavior_configuration(
            spec.get("behavior_configuration") or self.behavior_configuration,
            model=self.model,
            ocr_provider=self.ocr_provider,
            strict=self.candidate_profile is not None and self.mode == "quality",
        )
        return spec

    @staticmethod
    def _blocked_record(output: Path, *, model: str, split: str, reason: str) -> dict[str, Any]:
        record = {"status": "CANDIDATE_PROFILE_BLOCKED", "evaluation_state": EvaluationState.CAPABILITY_BLOCKED.value, "reason": reason, "model": model, "split": split, "quality_metrics_authoritative": False}
        write_results(output, [], {**record, "case_count": 0}, "# K-Slide Model Evaluation\n\n`CANDIDATE_PROFILE_BLOCKED`\n\n" + reason + "\n")
        return record

    def run(self) -> dict[str, Any]:
        self.output.mkdir(parents=True, exist_ok=True)
        certifying_request = self.mode == "quality" and self.split in {"validation", "held_out"} and self.limit is None and not self.categories and not self.scenario_ids
        if self.mode == "quality" and (certifying_request or self.high_risk) and self.candidate_profile is None:
            return self._blocked_record(self.output, model=self.model, split=self.split, reason="certification-quality model evaluation requires --candidate-profile")
        if self.high_risk and (self.split != "validation" or self.repeats < 5 or self.limit is not None or self.categories or self.scenario_ids):
            return self._blocked_record(self.output, model=self.model, split=self.split, reason="high-risk evaluation requires validation protected categories, repetitions >= 5, and no filters")
        scenarios = self.selected_scenarios()
        manifest = split_manifest()
        repo_root = Path(__file__).resolve().parents[1]
        model_policy = self.authoritative_policy or load_model_policy(repo_root)
        try:
            subject_result = subprocess.run(["git", "-C", str(repo_root), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=5, check=False)
            subject_sha = subject_result.stdout.strip() if subject_result.returncode == 0 else "UNSET"
        except (OSError, subprocess.TimeoutExpired):
            subject_sha = "UNSET"
        try:
            candidate_spec = self._candidate_spec(repo_root, subject_sha, manifest, model_policy)
        except (EvidenceValidationError, OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            if self.mode == "quality" and (self.split in {"validation", "held_out"} or self.high_risk):
                return self._blocked_record(self.output, model=self.model, split=self.split, reason=str(exc))
            candidate_spec = {
                "schema_version": CANDIDATE_SPEC_SCHEMA_VERSION,
                "subject_git_sha": subject_sha,
                "kslide_version": __version__,
                "requested_model": self.model,
                "effective_model": "UNSET",
                "ocr_provider": self.ocr_provider,
                "behavior_configuration": self.behavior_configuration,
                "model_policy": model_policy.as_dict(),
                "corpus_identity": canonical_corpus_identity(manifest),
            }
        if self.candidate_profile is not None and self.mode == "quality" and (self.split in {"validation", "held_out"} or self.high_risk):
            unresolved = [field for field in ("effective_model", "opencode_version") if not str(candidate_spec.get(field) or "") or str(candidate_spec[field]).upper() == "UNSET"]
            if unresolved:
                return self._blocked_record(self.output, model=self.model, split=self.split, reason="certification candidate must be frozen before model execution: " + ", ".join(unresolved))
            if not model_policy.approved(requested=self.model, effective=str(candidate_spec["effective_model"])):
                return self._blocked_record(self.output, model=self.model, split=self.split, reason="certification candidate effective_model is not an approved target for the requested model")
        # The candidate file is authoritative for certifying behavior.  Keep
        # the persisted experiment contract identical to the candidate inputs
        # so changing a material setting cannot leave model evidence bound to
        # a different execution configuration.
        self.behavior_configuration = dict(candidate_spec["behavior_configuration"])
        provisional_deployment = candidate_deployment_fingerprint(candidate_spec)
        behavior_hash = behavior_configuration_hash(candidate_spec["behavior_configuration"], strict=True)
        high_risk_categories = list(__import__("evals.scenarios", fromlist=["PROTECTED_CATEGORIES"]).PROTECTED_CATEGORIES) if self.high_risk else []
        plan = experiment_plan(split=self.split, scenario_ids=[item.scenario_id for item in scenarios], formats=self.formats, repetitions=self.repeats, categories=tuple(high_risk_categories or self.categories), limit=self.limit, timeout=self.timeout, mode=self.mode, scenario_filter=tuple(self.scenario_ids))
        plan_hash = experiment_plan_hash(plan)
        run_manifest = {
            "experiment_id": self.output.name,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "git_commit": subject_sha,
            "subject_git_sha": subject_sha,
            "deployment_fingerprint": provisional_deployment,
            "deployment_fingerprint_provisional": provisional_deployment,
            "candidate_spec": canonical_candidate_factors(candidate_spec),
            "effective_model": candidate_spec.get("effective_model", "UNSET"),
            "candidate_identity_status": "PROVISIONAL",
            "k_slide_version": __version__,
            "corpus_version": DATASET_VERSION,
            "split": self.split,
            "scenario_ids": [item.scenario_id for item in scenarios],
            "formats": self.formats,
            "model": self.model,
            "runtime": "opencode",
            "repetitions": self.repeats,
            "configuration": self.behavior_configuration,
            "behavior_configuration": self.behavior_configuration,
            "behavior_configuration_hash": behavior_hash,
            "configuration_hash": behavior_hash,
            "experiment_plan": plan,
            "experiment_plan_hash": plan_hash,
            "high_risk_categories": high_risk_categories,
            "experiment_identity": sha256_bytes(canonical_bytes({"model": self.model, "behavior_configuration": self.behavior_configuration, "ocr_provider": self.ocr_provider})),
            "split_manifest_hash": sha256_bytes(canonical_bytes(manifest)),
            "corpus_fingerprint": manifest["corpus_fingerprint"],
            "held_out_fingerprint": manifest["held_out_fingerprint"],
            "model_policy": model_policy.as_dict(),
            "execution_runtime_provenance": discover_runtime(repo_root).as_dict(),
        }
        if self.mode == "quality" and self.model not in set(model_policy.approved_model_ids) | set(model_policy.approved_aliases):
            record = {"status": "GEMMA_QUALITY_EVALUATION_BLOCKED", "evaluation_state": EvaluationState.CAPABILITY_BLOCKED.value, "reason": "GEMMA CERTIFICATION BLOCKED — target endpoint is not the selected model", "model": self.model, "split": self.split, "quality_metrics_authoritative": False}
            write_results(self.output, [], {**record, "case_count": 0}, "# K-Slide Model Evaluation\n\n`GEMMA CERTIFICATION BLOCKED`\n\nNon-target model runs are protocol smoke only.\n")
            (self.output / "experiment.json").write_text(json.dumps(run_manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            return record
        try:
            corpus_root = self.output / "corpus" / "artifacts"
            generate_artifacts(scenarios, corpus_root, formats=self.formats, variants=(DEFAULT_VARIANT,))
        except Exception as exc:
            record = {"status": "CAPABILITY_BLOCK", "evaluation_state": EvaluationState.CAPABILITY_BLOCKED.value, "reason": f"Artifact generation unavailable: {exc}", "model": self.model, "split": self.split, "quality_metrics_authoritative": False}
            write_results(self.output, [], {**record, "case_count": 0}, "# K-Slide Model Evaluation\n\n`CAPABILITY_BLOCK`\n\n" + str(exc) + "\n")
            return record
        results: list[dict[str, Any]] = []
        runner = OpenCodeEvalRunner(model=self.model, timeout_seconds=self.timeout, ocr_policy=self.ocr_provider, policy=model_policy, policy_root=repo_root, candidate_spec=candidate_spec, candidate_root=repo_root)
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
        raw_effective_models = [item.get("opencode", {}).get("diagnostics", {}).get("effective_model") for item in results]
        runtime_versions = {str(item.get("opencode", {}).get("runtime_version")) for item in results if item.get("opencode", {}).get("runtime_version")}
        canonical_effective_models: set[str] = set()
        for effective in raw_effective_models:
            canonical = model_policy.canonical_effective(requested=self.model, effective=effective) if effective else None
            if canonical:
                canonical_effective_models.add(canonical)
        expected_effective = str(candidate_spec.get("effective_model") or "")
        expected_canonical = model_policy.canonical_effective(requested=self.model, effective=expected_effective) if expected_effective and expected_effective.upper() != "UNSET" else None
        effective_identity = next(iter(canonical_effective_models)) if len(canonical_effective_models) == 1 else None
        if expected_canonical and effective_identity != expected_canonical:
            effective_identity = None
        expected_runtime = str(candidate_spec.get("opencode_version") or "")
        runtime_identity = next(iter(runtime_versions)) if len(runtime_versions) == 1 else None
        runtime_proven = bool(results) and len(runtime_versions) == 1 and (not expected_runtime or expected_runtime.upper() == "UNSET" or runtime_identity == expected_runtime)
        authoritative_effective = bool(results) and runtime_proven and all(item.get("opencode", {}).get("diagnostics", {}).get("model_identity_proven") is True for item in results) and len(canonical_effective_models) == 1 and (expected_canonical is None or effective_identity == expected_canonical)
        final_spec = dict(candidate_spec)
        final_spec["effective_model"] = effective_identity or "UNSET"
        if runtime_identity is not None:
            final_spec["opencode_version"] = runtime_identity
        final_deployment = candidate_deployment_fingerprint(final_spec)
        for item in results:
            item["subject_git_sha"] = subject_sha
            item["deployment_fingerprint"] = final_deployment
            item["candidate_deployment_fingerprint"] = final_deployment
            item["effective_model"] = item.get("opencode", {}).get("diagnostics", {}).get("effective_model") or "UNSET"
        run_manifest["deployment_fingerprint"] = final_deployment
        run_manifest["candidate_spec"] = canonical_candidate_factors(final_spec)
        run_manifest["effective_model"] = effective_identity or "UNSET"
        run_manifest["runtime_identity_proven"] = runtime_proven
        run_manifest["candidate_identity_status"] = "FINAL" if authoritative_effective else "UNPROVEN"
        if not authoritative_effective:
            run_manifest["deployment_fingerprint_provisional"] = provisional_deployment
        (self.output / "experiment.json").write_text(json.dumps(run_manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        summary = aggregate_model_results(results, model=self.model, split=self.split)
        summary["requested_model"] = self.model
        summary["effective_model"] = effective_identity or "UNSET"
        summary["effective_model_identity_proven"] = authoritative_effective
        summary["candidate_spec"] = canonical_candidate_factors(final_spec)
        summary["configuration_hash"] = run_manifest["behavior_configuration_hash"]
        summary["behavior_configuration_hash"] = run_manifest["behavior_configuration_hash"]
        summary["experiment_plan_hash"] = run_manifest["experiment_plan_hash"]
        summary["corpus_fingerprint"] = manifest["corpus_fingerprint"]
        summary["held_out_fingerprint"] = manifest["held_out_fingerprint"]
        summary["repetitions"] = self.repeats
        summary["subject_git_sha"] = subject_sha
        summary["deployment_fingerprint"] = final_deployment
        summary["target_model_approved"] = authoritative_effective and model_policy.approved(requested=self.model, effective=effective_identity)
        summary["execution_runtime_provenance"] = run_manifest["execution_runtime_provenance"]
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
