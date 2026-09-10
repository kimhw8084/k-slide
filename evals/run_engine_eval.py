"""Run format-independent deterministic ingestion/evidence evaluation.

This tier never calls a language model. It proves which source facts the
engine can extract from each actual artifact format and reports optional
capability blocks separately from artifact generation.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from .fonts import KoreanFontUnavailable
from .generator import DEFAULT_VARIANT, generate_artifacts
from .scenarios import scenario_specs, split_manifest, write_specs
from .scorers import aggregate_engine_scores, score_artifact, score_engine_case
from k_slide import __version__
from k_slide.certification import CANDIDATE_SPEC_SCHEMA_VERSION, EvidenceValidationError, candidate_deployment_fingerprint, canonical_behavior_configuration, canonical_candidate_factors, canonical_corpus_identity, load_candidate_spec
from k_slide.model_policy import load_model_policy
from k_slide.runtime import discover_runtime


def _selected_scenarios(split: str, limit: int | None, scenario_ids: tuple[str, ...] = ()):
    scenarios = scenario_specs()
    if split != "all":
        scenarios = [item for item in scenarios if item.split == split]
    if scenario_ids:
        requested = set(scenario_ids)
        scenarios = [item for item in scenarios if item.scenario_id in requested]
    if limit is not None:
        scenarios = scenarios[:limit]
    return scenarios


def _case_artifact(root: Path, scenario_id: str, format_name: str) -> Path:
    suffix = format_name.lower()
    return root / scenario_id / DEFAULT_VARIANT.name / suffix / f"source.{suffix}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run K-Slide engine/evidence evaluation without a model")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--split", choices=("development", "validation", "held_out", "all"), default="development")
    parser.add_argument("--formats", nargs="+", default=["png"])
    parser.add_argument("--ocr-provider", choices=("none", "paddle", "auto"), default="none")
    parser.add_argument("--scenario-ids", nargs="*", default=())
    parser.add_argument("--fail-on-critical", action="store_true")
    parser.add_argument("--candidate-profile", type=Path, help="Explicit candidate deployment specification")
    parser.add_argument("--subject-sha", help="Subject Git SHA when the evaluation environment has no checkout metadata")
    args = parser.parse_args(argv)
    scenarios = scenario_specs()
    selected = _selected_scenarios(args.split, args.limit, tuple(args.scenario_ids))
    args.output.mkdir(parents=True, exist_ok=True)
    if args.split in {"validation", "held_out"} and args.candidate_profile is None:
        blocked = {
            "evaluation_tier": "synthetic_engine_evidence",
            "status": "CANDIDATE_PROFILE_BLOCKED",
            "subject_git_sha": "UNSET",
            "split": args.split,
            "reason": "certification-quality engine evaluation requires --candidate-profile",
            "model_evaluated": False,
            "semantic_translation_scored": False,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "results": [],
        }
        (args.output / "summary.json").write_text(json.dumps(blocked, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (args.output / "EVAL_REPORT.md").write_text("# K-Slide Engine Evidence Evaluation\n\n`CANDIDATE_PROFILE_BLOCKED`\n\n" + blocked["reason"] + "\n", encoding="utf-8")
        print(json.dumps(blocked, ensure_ascii=False))
        return 2
    repo_root = Path(__file__).resolve().parents[1]
    subject_sha = args.subject_sha or "UNSET"
    try:
        git_result = subprocess.run(["git", "-C", str(repo_root), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=5, check=False)
        if not args.subject_sha:
            subject_sha = git_result.stdout.strip() if git_result.returncode == 0 else "UNSET"
    except (OSError, subprocess.TimeoutExpired):
        subject_sha = "UNSET"
    corpus = canonical_corpus_identity(split_manifest())
    try:
        if args.candidate_profile:
            candidate = load_candidate_spec(args.candidate_profile, root=repo_root, require_identity=False, strict=True)
        else:
            candidate = {"schema_version": CANDIDATE_SPEC_SCHEMA_VERSION, "subject_git_sha": subject_sha, "kslide_version": __version__, "requested_model": "UNSET", "effective_model": "UNSET", "ocr_provider": args.ocr_provider}
        declared_subject = str(candidate.get("subject_git_sha") or "")
        if declared_subject and declared_subject.upper() != "UNSET" and declared_subject != subject_sha:
            raise EvidenceValidationError("candidate subject_git_sha does not match engine subject")
        declared_ocr = str(candidate.get("ocr_provider") or "")
        if declared_ocr and declared_ocr.upper() != "UNSET" and declared_ocr != args.ocr_provider:
            raise EvidenceValidationError("candidate ocr_provider does not match engine request")
        candidate["subject_git_sha"] = subject_sha
        candidate["ocr_provider"] = args.ocr_provider
        behavior = dict(candidate.get("behavior_configuration") or {})
        behavior["ocr_provider"] = args.ocr_provider
        candidate["behavior_configuration"] = canonical_behavior_configuration(behavior)
        candidate["model_policy"] = load_model_policy(repo_root).as_dict()
        candidate["corpus_identity"] = corpus
        deployment = candidate_deployment_fingerprint(candidate)
    except (EvidenceValidationError, OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        blocked = {"evaluation_tier": "synthetic_engine_evidence", "status": "CANDIDATE_PROFILE_BLOCKED", "subject_git_sha": subject_sha, "split": args.split, "reason": str(exc), "model_evaluated": False, "semantic_translation_scored": False, "generated_at": datetime.now(timezone.utc).isoformat(), "results": []}
        (args.output / "summary.json").write_text(json.dumps(blocked, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (args.output / "EVAL_REPORT.md").write_text(f"# K-Slide Engine Evidence Evaluation\n\n`CANDIDATE_PROFILE_BLOCKED`\n\n{exc}\n", encoding="utf-8")
        print(json.dumps(blocked, ensure_ascii=False))
        return 2
    write_specs(args.output / "specs")
    try:
        counts = generate_artifacts(selected, args.output / "artifacts", formats=tuple(args.formats), variants=(DEFAULT_VARIANT,))
    except KoreanFontUnavailable as exc:
        summary = {"evaluation_tier": "synthetic_engine_evidence", "status": "CAPABILITY_BLOCK", "subject_git_sha": subject_sha, "deployment_fingerprint": deployment, "candidate_spec": canonical_candidate_factors(candidate), "runtime_provenance": discover_runtime().as_dict(), "model_evaluated": False, "semantic_translation_scored": False, "scenario_specs": len(scenarios), "split": args.split, "scenarios_selected": len(selected), "case_count": 0, "formats_requested": [item.lower() for item in args.formats], "generated_artifacts": {}, "engine": {"capability_block": str(exc)}, "generated_at": datetime.now(timezone.utc).isoformat(), "results": []}
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (args.output / "EVAL_REPORT.md").write_text(f"# K-Slide Engine Evidence Evaluation\n\n`CAPABILITY_BLOCK`\n\n{exc}\n", encoding="utf-8")
        print(json.dumps(summary, ensure_ascii=False))
        return 0
    results: list[dict[str, object]] = []
    for scenario in selected:
        for format_name in args.formats:
            artifact = _case_artifact(args.output / "artifacts", scenario.scenario_id, format_name)
            artifact_result = score_artifact(artifact, scenario)
            normalized = None
            evidence = None
            run_dir = None
            error = None
            try:
                from k_slide.errors import KSlideError
                from k_slide.extraction import extract_run
                from k_slide.ingest import prepare_run
                from k_slide.normalization import normalize_run

                case_workspace = args.output / "runs" / scenario.scenario_id / format_name.lower()
                case_workspace.mkdir(parents=True, exist_ok=True)
                run_dir = prepare_run(case_workspace, explicit_paths=[str(artifact)])
                normalized = normalize_run(run_dir)
                evidence = extract_run(run_dir, ocr_policy=args.ocr_provider)
            except Exception as exc:  # the scorer records capability failures without hiding them
                error = exc.code.value if hasattr(exc, "code") else "ENGINE_RUNTIME_ERROR"
                if isinstance(exc, OSError):
                    error = "ENGINE_IO_ERROR"
            results.append({"format": format_name.lower(), **score_engine_case(scenario, artifact_result=artifact_result, normalized=normalized, evidence=evidence, run_dir=run_dir, error=error)})
    aggregate = aggregate_engine_scores(results)
    summary = {
        "evaluation_tier": "synthetic_engine_evidence",
        "subject_git_sha": subject_sha,
        "deployment_fingerprint": deployment,
        "candidate_spec": canonical_candidate_factors(candidate),
        "runtime_provenance": discover_runtime().as_dict(),
        "model_evaluated": False,
        "semantic_translation_scored": False,
        "scenario_specs": len(scenarios),
        "split": args.split,
        "scenarios_selected": len(selected),
        "case_count": len(results),
        "formats_requested": [item.lower() for item in args.formats],
        "ocr_policy_requested": args.ocr_provider,
        "ocr_providers_effective": sorted({str(item.get("ocr", {}).get("ocr_provider_effective")) for item in results if item.get("ocr", {}).get("ocr_provider_effective")}),
        "generated_artifacts": counts,
        "engine": aggregate,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "results": results,
    }
    (args.output / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# K-Slide Engine Evidence Evaluation",
        "",
        "Tier: `synthetic_engine_evidence`",
        "",
        f"Scenario specifications: `{len(scenarios)}`",
        f"Split: `{args.split}`",
        f"Cases run: `{len(results)}`",
        f"Artifact generation pass rate: `{aggregate['artifact_generation_pass_rate']:.3f}`",
        f"Engine normalization pass rate: `{aggregate['engine_normalization_pass_rate']:.3f}`",
        f"Evidence generation pass rate: `{aggregate['evidence_generation_pass_rate']:.3f}`",
        f"Critical engine failure count: `{aggregate['critical_failure_count']}`",
        f"Capability-blocked findings: `{aggregate['capability_block_count']}`",
        f"Algorithmic/evidence findings: `{aggregate['algorithmic_failure_count']}`",
        f"Failure classes: `{json.dumps(aggregate['failure_classes'], sort_keys=True)}`",
        "",
        "This tier measures actual artifact generation, normalization, and engine-owned EvidenceIR extraction. It does not call Gemma and is not a semantic translation or production-certification result.",
        "",
    ]
    (args.output / "EVAL_REPORT.md").write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({"evaluation_tier": summary["evaluation_tier"], "split": args.split, "case_count": len(results), "generated_artifacts": counts, "engine": aggregate}, ensure_ascii=False))
    if any(not item["artifact"].get("artifact_generation_pass") for item in results):
        return 1
    if args.fail_on_critical and aggregate["critical_failure_count"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
