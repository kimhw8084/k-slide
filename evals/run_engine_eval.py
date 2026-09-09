"""Run format-independent deterministic ingestion/evidence evaluation.

This tier never calls a language model. It proves which source facts the
engine can extract from each actual artifact format and reports optional
capability blocks separately from artifact generation.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from .fonts import KoreanFontUnavailable
from .generator import DEFAULT_VARIANT, generate_artifacts
from .scenarios import scenario_specs, write_specs
from .scorers import aggregate_engine_scores, score_artifact, score_engine_case


def _selected_scenarios(split: str, limit: int | None):
    scenarios = scenario_specs()
    if split != "all":
        scenarios = [item for item in scenarios if item.split == split]
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
    parser.add_argument("--fail-on-critical", action="store_true")
    args = parser.parse_args(argv)
    scenarios = scenario_specs()
    selected = _selected_scenarios(args.split, args.limit)
    args.output.mkdir(parents=True, exist_ok=True)
    write_specs(args.output / "specs")
    try:
        counts = generate_artifacts(selected, args.output / "artifacts", formats=tuple(args.formats), variants=(DEFAULT_VARIANT,))
    except KoreanFontUnavailable as exc:
        summary = {"evaluation_tier": "synthetic_engine_evidence", "status": "CAPABILITY_BLOCK", "model_evaluated": False, "semantic_translation_scored": False, "scenario_specs": len(scenarios), "split": args.split, "scenarios_selected": len(selected), "case_count": 0, "formats_requested": [item.lower() for item in args.formats], "generated_artifacts": {}, "engine": {"capability_block": str(exc)}, "generated_at": datetime.now(timezone.utc).isoformat(), "results": []}
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
