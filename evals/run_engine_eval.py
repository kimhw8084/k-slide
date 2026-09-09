"""Run the dependency-free synthetic artifact/evidence boundary evaluation.

This runner does not call a language model. It measures generated-artifact and
engine-fixture health only; target Gemma certification remains a separate tier.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from .generator import generate_artifacts
from .scenarios import scenario_specs, write_specs
from .scorers import score_artifact


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--formats", nargs="+", default=["png"])
    args = parser.parse_args(argv)
    scenarios = scenario_specs()
    selected = scenarios[: args.limit] if args.limit else scenarios
    args.output.mkdir(parents=True, exist_ok=True)
    write_specs(args.output / "specs")
    counts = generate_artifacts(selected, args.output / "artifacts", formats=tuple(args.formats))
    results = [score_artifact(args.output / "artifacts" / scenario.scenario_id / "source.png", scenario) for scenario in selected if "png" in args.formats]
    engine_summary: dict[str, object] = {"status": "NOT_RUN"}
    if results:
        from k_slide.extraction import extract_run
        from k_slide.ingest import prepare_run
        from k_slide.normalization import normalize_run

        workspace = args.output / "engine_workspace"
        source_paths = [str(args.output / "artifacts" / scenario.scenario_id / "source.png") for scenario in selected]
        run = prepare_run(workspace, explicit_paths=source_paths)
        normalized = normalize_run(run)
        evidence = extract_run(run)
        engine_summary = {"status": "PASS", "run_id": run.name, "normalized_documents": len(normalized.documents), "normalized_units": sum(len(document.units) for document in normalized.documents), "evidence_units": len(evidence), "regions_detected": sum(len(item.regions) for item in evidence), "numeric_facts": sum(len(item.numeric_facts) for item in evidence)}
    summary = {"evaluation_tier": "synthetic_engine_boundary", "model_evaluated": False, "scenario_specs": len(scenarios), "scenarios_run": len(selected), "formats": counts, "hard_pass_rate": (sum(bool(item["hard_pass"]) for item in results) / len(results) if results else 0.0), "engine": engine_summary, "generated_at": datetime.now(timezone.utc).isoformat(), "results": results}
    (args.output / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    lines = ["# K-Slide Synthetic Evaluation", "", "Tier: `synthetic_engine_boundary`", "", f"Scenario specifications: `{len(scenarios)}`", f"Scenarios run: `{len(selected)}`", f"Artifact hard-pass rate: `{summary['hard_pass_rate']:.3f}`", f"Engine evidence status: `{engine_summary.get('status')}`", "", "This evaluation exercises generated artifacts through normalization and EvidenceIR extraction. It does not call Gemma and is not a translation-quality or production-certification result.", ""]
    (args.output / "EVAL_REPORT.md").write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({key: summary[key] for key in ("evaluation_tier", "scenario_specs", "scenarios_run", "formats", "hard_pass_rate")}, ensure_ascii=False))
    return 0 if summary["hard_pass_rate"] == 1.0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
