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
from .corpus_governance import (
    canonical_corpus_identity as canonical_governed_identity,
    manifest_identity,
    public_synthetic_manifest,
)
from k_slide.corpus_governance import CorpusGovernanceError, corpus_identity_fingerprint
from .governed_corpus import (
    GovernedCase,
    GovernedCaseError,
    case_matrix_fingerprint,
    case_matrix_item_fingerprint,
    load_governed_external_cases,
)


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


def _source_free_semantic(value: dict[str, Any]) -> dict[str, Any]:
    """Keep scorer metrics while omitting source text and gold-derived details."""

    allowed = (
        "coverage", "numeric_fidelity", "modality", "table_cell_fidelity",
        "chart_semantic_score", "process_relation_score", "visual_relation_recall",
        "residual_hangul", "unsupported_executive_claims", "unresolved_count",
        "unresolved_region_rate", "unexpected_unresolved", "unexpected_unresolved_rate",
        "critical_failures", "term_consistency_recall", "inconsistent_alternate_count",
    )
    return {key: value[key] for key in allowed if key in value}


def _source_free_opencode(result: Any, workspace_label: str) -> dict[str, Any]:
    value = result.as_dict()
    media = value.get("media_compliance") if isinstance(value.get("media_compliance"), dict) else {}
    safe_media = {key: media[key] for key in (
        "planned", "required_count", "read_count", "required_context_image_read",
        "required_crop_recall", "media_sequence_valid", "attempt_count", "evidence_event_count",
    ) if key in media}
    diagnostics = value.get("diagnostics") if isinstance(value.get("diagnostics"), dict) else {}
    safe_diagnostics = {key: diagnostics[key] for key in ("effective_model", "model_identity_proven", "structured_error_count") if key in diagnostics}
    return {
        "status": value.get("status"),
        "mode": value.get("mode"),
        "model": value.get("model"),
        "runtime_version": value.get("runtime_version"),
        "workspace": workspace_label,
        "duration_seconds": value.get("duration_seconds"),
        "event_count": value.get("event_count"),
        "tool_call_count": len(value.get("tool_calls", [])),
        "forbidden_attempt_count": len(value.get("forbidden_attempts", [])),
        "media_read_observed": value.get("media_read_observed"),
        "media_compliance": safe_media,
        "run_artifact_count": value.get("run_artifact_count", 0),
        "kslide_complete": value.get("kslide_complete", False),
        "quality_metrics_authoritative": value.get("quality_metrics_authoritative", False),
        "diagnostics": safe_diagnostics,
    }


def _source_free_runtime_provenance(value: dict[str, Any]) -> dict[str, Any]:
    """Retain adapter-relevant runtime facts without local executable/config paths."""

    allowed = (
        "kslide_version", "opencode_version", "provider", "reported_model_id",
        "model_family", "model_size", "instruction_tuned_status", "vision_support",
        "thinking_support", "provider_backend", "quantization_or_dtype",
        "context_configuration", "image_preprocessing_settings", "model_compatibility",
        "model_revision", "python_version", "paddle_version", "paddleocr_version",
        "libreoffice_version", "ocr_provider",
    )
    return {key: value[key] for key in allowed if key in value}


class ModelEvaluationRunner:
    def __init__(self, *, model: str, output: Path, split: str = "development", formats: tuple[str, ...] = ("png",), repeats: int = 1, timeout: int = 180, mode: str = "quality", limit: int | None = None, categories: tuple[str, ...] = (), scenario_ids: tuple[str, ...] = (), configuration: dict[str, Any] | None = None, ocr_provider: str = "none", candidate_profile: Path | None = None, high_risk: bool = False, model_policy: Any | None = None, corpus_source: str = "public_synthetic", governed_manifest: Path | None = None, governed_manifest_bundle: Path | None = None, governed_history: Path | None = None, evaluation_purpose: str | None = None, artifact_root: Path | None = None, case_descriptor: str | Path = "cases.json", contamination_report: Path | None = None):
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
        self.requested_scenario_ids = tuple(scenario_ids)
        self.ocr_provider = ocr_provider
        self.configuration = dict(configuration or {})
        self.behavior_configuration = behavior_configuration(self.configuration, model=model, ocr_provider=ocr_provider)
        self.candidate_profile = candidate_profile.expanduser() if candidate_profile is not None else None
        self.high_risk = high_risk
        self.authoritative_policy = model_policy
        self.corpus_source = corpus_source
        self.governed_manifest = governed_manifest.expanduser() if governed_manifest is not None else None
        self.governed_manifest_bundle = governed_manifest_bundle.expanduser() if governed_manifest_bundle is not None else None
        self.governed_history = governed_history.expanduser() if governed_history is not None else None
        self.evaluation_purpose = evaluation_purpose
        self.artifact_root = artifact_root.expanduser() if artifact_root is not None else None
        self.case_descriptor = case_descriptor
        self.contamination_report = contamination_report.expanduser() if contamination_report is not None else None

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
        corpus = manifest
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
        repo_root = Path(__file__).resolve().parents[1]
        governed = self.corpus_source == "governed_external"
        if self.corpus_source not in {"public_synthetic", "governed_external"}:
            self.output.mkdir(parents=True, exist_ok=True)
            return self._blocked_record(self.output, model=self.model, split=self.split, reason="unknown corpus source")
        if governed:
            output_path = self.output.expanduser().absolute()
            if output_path.is_symlink():
                return {"status": "CANDIDATE_PROFILE_BLOCKED", "evaluation_state": EvaluationState.CAPABILITY_BLOCKED.value, "reason": "governed evaluation output path contains a symlink", "model": self.model, "split": self.split, "quality_metrics_authoritative": False}
            try:
                output_path.resolve().relative_to(repo_root.resolve())
            except ValueError:
                pass
            else:
                return {"status": "CANDIDATE_PROFILE_BLOCKED", "evaluation_state": EvaluationState.CAPABILITY_BLOCKED.value, "reason": "governed evaluation output must be outside the public repository", "model": self.model, "split": self.split, "quality_metrics_authoritative": False}
            if self.artifact_root is not None:
                try:
                    output_path.resolve().relative_to(self.artifact_root.resolve())
                except ValueError:
                    pass
                else:
                    return {"status": "CANDIDATE_PROFILE_BLOCKED", "evaluation_state": EvaluationState.CAPABILITY_BLOCKED.value, "reason": "governed evaluation output must be outside the approved artifact root", "model": self.model, "split": self.split, "quality_metrics_authoritative": False}
        self.output.mkdir(parents=True, exist_ok=True)
        external_cases: list[GovernedCase] = []
        case_descriptor_identity: dict[str, Any] | None = None
        contamination_report: dict[str, Any] | None = None
        governed_history: list[Any] = []
        if governed:
            required_inputs = (self.governed_manifest, self.governed_manifest_bundle, self.artifact_root)
            if any(item is None for item in required_inputs) or self.candidate_profile is None or self.evaluation_purpose is None:
                return self._blocked_record(self.output, model=self.model, split=self.split, reason="governed external evaluation requires candidate, manifest bundle, purpose, and artifact root")
            if self.mode != "quality":
                return self._blocked_record(self.output, model=self.model, split=self.split, reason="governed authoritative evaluation requires quality mode")
            if self.limit is not None or self.categories:
                return self._blocked_record(self.output, model=self.model, split=self.split, reason="governed authoritative evaluation cannot use limit or category filters")
            if len(self.requested_scenario_ids) != len(set(self.requested_scenario_ids)):
                return self._blocked_record(self.output, model=self.model, split=self.split, reason="governed scenario IDs must not be duplicated")
            if len(self.formats) != len(set(self.formats)):
                return self._blocked_record(self.output, model=self.model, split=self.split, reason="governed formats must be unique")
        else:
            if any((
                self.governed_manifest is not None,
                self.governed_manifest_bundle is not None,
                self.governed_history is not None,
                self.evaluation_purpose is not None,
                self.artifact_root is not None,
                self.contamination_report is not None,
            )):
                self.output.mkdir(parents=True, exist_ok=True)
                return self._blocked_record(self.output, model=self.model, split=self.split, reason="governed external inputs require --corpus-source governed_external")
            certifying_request = self.mode == "quality" and self.split in {"validation", "held_out"} and self.limit is None and not self.categories and not self.scenario_ids
            if self.mode == "quality" and (certifying_request or self.high_risk) and self.candidate_profile is None:
                return self._blocked_record(self.output, model=self.model, split=self.split, reason="certification-quality model evaluation requires --candidate-profile")
            if self.high_risk and (self.split != "validation" or self.repeats < 5 or self.limit is not None or self.categories or self.scenario_ids):
                return self._blocked_record(self.output, model=self.model, split=self.split, reason="high-risk evaluation requires validation protected categories, repetitions >= 5, and no filters")
        manifest = split_manifest() if not governed else None
        corpus_bundle: list[dict[str, Any]] = [] if governed else [public_synthetic_manifest()]
        corpus_history: list[Any] = []
        corpus_set_identity: dict[str, Any]
        evaluation_purpose: str
        corpus_identity_for_candidate: dict[str, Any]
        if governed:
            try:
                manifest, corpus_bundle, governed_history, contamination_report, external_cases, case_descriptor_identity = load_governed_external_cases(
                    manifest_path=self.governed_manifest,
                    bundle_path=self.governed_manifest_bundle,
                    history_path=self.governed_history,
                    evaluation_purpose=self.evaluation_purpose,
                    artifact_root=self.artifact_root,
                    descriptor_path=self.case_descriptor,
                    formats=self.formats,
                    contamination_report_path=self.contamination_report,
                    repo_root=repo_root,
                )
                corpus_history = governed_history
                role = manifest["role"]
                expected_split = "held_out" if role == "sealed_held_out" else "validation"
                if self.split != expected_split:
                    raise GovernedCaseError("governed role does not match the explicit matrix split")
                if role == "frozen_high_risk" and self.repeats < 5:
                    raise GovernedCaseError("frozen high-risk evaluation requires at least five repetitions")
                if self.high_risk and role != "frozen_high_risk":
                    raise GovernedCaseError("high-risk option disagrees with evaluated governed role")
                active_ids = {item["item_id"] for item in manifest["items"] if item["state"] == "active"}
                if self.scenario_ids and (self.scenario_ids != active_ids or len(self.requested_scenario_ids) != len(active_ids)):
                    raise GovernedCaseError("requested scenario IDs must equal exact active governed membership")
                scenarios = [item.scenario for item in external_cases]
                case_matrix = [item.matrix_item for item in external_cases]
                case_matrix.sort(key=lambda item: item["item_id"])
                corpus_set_identity = manifest_identity(manifest)
                corpus_identity_for_candidate = canonical_governed_identity({
                    "schema_version": "1.0",
                    "sets": [manifest_identity(item) for item in corpus_bundle],
                }, require_complete=True)
                evaluation_purpose = str(self.evaluation_purpose)
            except (EvidenceValidationError, CorpusGovernanceError, OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
                return self._blocked_record(self.output, model=self.model, split=self.split, reason=f"Governed evaluation blocked ({type(exc).__name__}).")
        else:
            scenarios = self.selected_scenarios()
            corpus_set_identity = manifest["governed_set_identity"]
            corpus_bundle = [public_synthetic_manifest()]
            evaluation_purpose = "regression"
            corpus_identity_for_candidate = manifest
            case_matrix = []
        model_policy = self.authoritative_policy or load_model_policy(repo_root)
        try:
            subject_result = subprocess.run(["git", "-C", str(repo_root), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=5, check=False)
            subject_sha = subject_result.stdout.strip() if subject_result.returncode == 0 else "UNSET"
        except (OSError, subprocess.TimeoutExpired):
            subject_sha = "UNSET"
        try:
            if governed:
                raw_candidate = load_candidate_spec(self.candidate_profile, root=repo_root, require_identity=False, strict=True)
                declared_corpus = canonical_governed_identity(raw_candidate.get("corpus_identity"), require_complete=True)
                if declared_corpus != corpus_identity_for_candidate:
                    raise EvidenceValidationError("candidate governed identities do not exactly match the supplied manifest bundle")
            candidate_spec = self._candidate_spec(repo_root, subject_sha, corpus_identity_for_candidate, model_policy)
        except (EvidenceValidationError, OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            if governed or (self.mode == "quality" and (self.split in {"validation", "held_out"} or self.high_risk)):
                return self._blocked_record(self.output, model=self.model, split=self.split, reason=f"Model evaluation blocked ({type(exc).__name__}).")
            candidate_spec = {
                "schema_version": CANDIDATE_SPEC_SCHEMA_VERSION,
                "subject_git_sha": subject_sha,
                "kslide_version": __version__,
                "requested_model": self.model,
                "effective_model": "UNSET",
                "ocr_provider": self.ocr_provider,
                "behavior_configuration": self.behavior_configuration,
                "model_policy": model_policy.as_dict(),
                "corpus_identity": canonical_corpus_identity(corpus_identity_for_candidate),
            }
        if self.candidate_profile is not None and self.mode == "quality" and (governed or self.split in {"validation", "held_out"} or self.high_risk):
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
        high_risk_categories = sorted({item["protected_group"] for item in case_matrix if item.get("protected_group")}) if governed and manifest["role"] == "frozen_high_risk" else list(__import__("evals.scenarios", fromlist=["PROTECTED_CATEGORIES"]).PROTECTED_CATEGORIES) if self.high_risk else []
        plan = experiment_plan(split=self.split, scenario_ids=[item.scenario_id for item in scenarios], formats=self.formats, repetitions=self.repeats, categories=tuple(high_risk_categories or self.categories), limit=self.limit, timeout=self.timeout, mode=self.mode, scenario_filter=() if governed else tuple(self.scenario_ids))
        plan_hash = experiment_plan_hash(plan)
        run_manifest = {
            "experiment_id": "governed-external-model-evaluation" if governed else self.output.name,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "git_commit": subject_sha,
            "subject_git_sha": subject_sha,
            "deployment_fingerprint": provisional_deployment,
            "deployment_fingerprint_provisional": provisional_deployment,
            "candidate_spec": canonical_candidate_factors(candidate_spec),
            "effective_model": candidate_spec.get("effective_model", "UNSET"),
            "candidate_identity_status": "PROVISIONAL",
            "k_slide_version": __version__,
            "corpus_version": manifest["version"] if governed else DATASET_VERSION,
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
            "split_manifest_hash": sha256_bytes(canonical_bytes(manifest)) if not governed else corpus_identity_fingerprint(corpus_identity_for_candidate),
            "corpus_fingerprint": manifest["corpus_fingerprint"] if not governed else corpus_identity_fingerprint(corpus_identity_for_candidate),
            "held_out_fingerprint": manifest["held_out_fingerprint"] if not governed else (manifest["manifest_fingerprint"] if manifest["role"] == "sealed_held_out" else None),
            "corpus_set_identity": corpus_set_identity,
            "corpus_manifest": manifest if governed else public_synthetic_manifest(),
            "governed_corpus_manifests": corpus_bundle,
            "governed_corpus_history": corpus_history,
            "evaluation_purpose": evaluation_purpose,
            "model_policy": model_policy.as_dict(),
            "execution_runtime_provenance": _source_free_runtime_provenance(discover_runtime(repo_root).as_dict()) if governed else discover_runtime(repo_root).as_dict(),
        }
        if governed:
            run_manifest["case_matrix"] = case_matrix
            run_manifest["case_matrix_sha256"] = case_matrix_fingerprint(case_matrix)
            run_manifest["case_descriptor_identity"] = case_descriptor_identity
            run_manifest["case_descriptor_identity"]["case_matrix_sha256"] = run_manifest["case_matrix_sha256"]
            if contamination_report is not None:
                run_manifest["contamination_report"] = contamination_report
        if self.mode == "quality" and self.model not in set(model_policy.approved_model_ids) | set(model_policy.approved_aliases):
            record = {"status": "GEMMA_QUALITY_EVALUATION_BLOCKED", "evaluation_state": EvaluationState.CAPABILITY_BLOCKED.value, "reason": "GEMMA CERTIFICATION BLOCKED — target endpoint is not the selected model", "model": self.model, "split": self.split, "quality_metrics_authoritative": False}
            write_results(self.output, [], {**record, "case_count": 0}, "# K-Slide Model Evaluation\n\n`GEMMA CERTIFICATION BLOCKED`\n\nNon-target model runs are protocol smoke only.\n")
            (self.output / "experiment.json").write_text(json.dumps(run_manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            return record
        try:
            corpus_root = self.output / "corpus" / "artifacts"
            if not governed:
                generate_artifacts(scenarios, corpus_root, formats=self.formats, variants=(DEFAULT_VARIANT,))
        except Exception as exc:
            record = {"status": "CAPABILITY_BLOCK", "evaluation_state": EvaluationState.CAPABILITY_BLOCKED.value, "reason": f"Artifact generation unavailable ({type(exc).__name__}).", "model": self.model, "split": self.split, "quality_metrics_authoritative": False}
            write_results(self.output, [], {**record, "case_count": 0}, "# K-Slide Model Evaluation\n\n`CAPABILITY_BLOCK`\n\nArtifact generation unavailable.\n")
            return record
        results: list[dict[str, Any]] = []
        runner = OpenCodeEvalRunner(model=self.model, timeout_seconds=self.timeout, ocr_policy=self.ocr_provider, policy=model_policy, policy_root=repo_root, candidate_spec=candidate_spec, candidate_root=repo_root)
        external_by_id = {item.scenario.scenario_id: item for item in external_cases}
        for scenario in scenarios:
            for format_name in self.formats:
                external_case = external_by_id.get(scenario.scenario_id) if governed else None
                artifact = external_case.artifacts[format_name] if external_case is not None else _artifact_path(corpus_root, scenario.scenario_id, format_name)
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
                    result_row = {
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
                        "semantic": _source_free_semantic(semantic) if governed else semantic,
                        "units": [{"work_unit_id": item["work_unit_id"], "semantic": _source_free_semantic(score) if governed else score} for item, score in zip(artifacts, unit_scores)],
                        "media_by_work_unit": ({key: {"media_sequence_valid": value.get("media_sequence_valid") is True} for key, value in media_units.items()} if governed else media_units),
                        "quality_metrics_authoritative": quality_contract,
                        "opencode": _source_free_opencode(result, f"cases/{scenario.scenario_id}/{format_name}/repeat-{repetition:02d}") if governed else result.as_dict(),
                    }
                    if governed and external_case is not None:
                        result_row["case_identity_sha256"] = case_matrix_item_fingerprint(external_case.matrix_item)
                    results.append(result_row)
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
        summary["corpus_fingerprint"] = run_manifest["corpus_fingerprint"]
        summary["held_out_fingerprint"] = run_manifest["held_out_fingerprint"]
        summary["corpus_set_identity"] = corpus_set_identity
        summary["evaluation_purpose"] = evaluation_purpose
        if governed:
            summary["case_matrix_sha256"] = run_manifest["case_matrix_sha256"]
            summary["case_descriptor_identity"] = run_manifest["case_descriptor_identity"]
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
