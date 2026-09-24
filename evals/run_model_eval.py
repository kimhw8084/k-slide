"""CLI for corpus-level OpenCode protocol smoke and Gemma evaluation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .model_eval import ModelEvaluationRunner
from k_slide.redaction import sanitize_operational
from k_slide.corpus_governance import EVALUATION_PURPOSES


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run K-Slide cases through the actual OpenCode workflow.")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--split", choices=("development", "validation", "held_out", "all"), default="development")
    parser.add_argument("--formats", nargs="+", default=["png"])
    parser.add_argument("--repeats", type=int, help="Explicit artifact repetition count; certification defaults to 3 (5 for high-risk)")
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--mode", choices=("protocol", "quality"), default="quality")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--category", action="append", default=[])
    parser.add_argument("--scenario-id", action="append", default=[])
    parser.add_argument("--deck-id")
    parser.add_argument("--config", type=Path)
    parser.add_argument("--ocr-provider", choices=("none", "paddle", "auto"), default="none")
    parser.add_argument("--candidate-profile", type=Path, help="Explicit candidate deployment specification for certification-quality runs")
    parser.add_argument("--high-risk", action="store_true", help="Run the protected-category validation stability matrix")
    parser.add_argument("--corpus-source", choices=("public_synthetic", "governed_external"), default="public_synthetic", help="Select repository synthetic data or an externally materialized governed corpus")
    parser.add_argument("--governed-manifest", type=Path, help="Evaluated source-free governed manifest")
    parser.add_argument("--governed-manifest-bundle", type=Path, help="Canonical JSON list containing all four candidate-bound governed manifests")
    parser.add_argument("--governed-history", type=Path, help="Optional canonical JSON list of required predecessor/history manifests and exposure contexts")
    parser.add_argument("--evaluation-purpose", choices=EVALUATION_PURPOSES, help="Explicit governed evaluation intent")
    parser.add_argument("--artifact-root", type=Path, help="Approved external root containing case descriptors, artifacts, and gold")
    parser.add_argument("--case-descriptor", default="cases.json", help="Descriptor path relative to --artifact-root")
    parser.add_argument("--contamination-report", type=Path, help="Required empty contamination report for sealed held-out evaluation")
    args = parser.parse_args(argv)
    if args.deck_id:
        from .run_deck_eval import main as run_deck_main

        return run_deck_main(["--output", str(args.output), "--deck-id", args.deck_id, "--model", args.model, "--mode", args.mode, "--timeout", str(max(1, args.timeout)), "--ocr-provider", args.ocr_provider])
    configuration = {}
    if args.config:
        configuration = json.loads(args.config.read_text(encoding="utf-8"))
    result = ModelEvaluationRunner(
        model=args.model,
        output=args.output,
        split=args.split,
        formats=tuple(args.formats),
        repeats=args.repeats,
        timeout=max(1, args.timeout),
        mode=args.mode,
        limit=args.limit,
        categories=tuple(args.category),
        scenario_ids=tuple(args.scenario_id),
        configuration=configuration or None,
        ocr_provider=args.ocr_provider,
        candidate_profile=args.candidate_profile,
        high_risk=args.high_risk,
        corpus_source=args.corpus_source,
        governed_manifest=args.governed_manifest,
        governed_manifest_bundle=args.governed_manifest_bundle,
        governed_history=args.governed_history,
        evaluation_purpose=args.evaluation_purpose,
        artifact_root=args.artifact_root,
        case_descriptor=args.case_descriptor,
        contamination_report=args.contamination_report,
    ).run()
    roots = tuple(item for item in (args.artifact_root, args.governed_manifest, args.governed_manifest_bundle, args.governed_history, args.contamination_report) if item is not None)
    print(json.dumps(sanitize_operational(result, roots=roots), ensure_ascii=False))
    if result.get("status") in {"GEMMA_QUALITY_EVALUATION_BLOCKED", "CAPABILITY_BLOCK", "NON_AUTHORITATIVE", "PROTOCOL_SMOKE_ONLY", "CAPABILITY_BLOCKED"}:
        return 0
    return 0 if result.get("status") == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
