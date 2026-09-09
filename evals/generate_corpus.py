"""Generate the fixed public visual corpus without running a model."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .generator import CORPUS_VARIANTS, DEFAULT_VARIANT, generate_artifacts
from .scenarios import scenario_specs, write_specs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--split", choices=("development", "validation", "held_out", "all"), default="all")
    parser.add_argument("--formats", nargs="+", default=["png", "jpg", "webp", "pdf", "pptx"])
    parser.add_argument("--all-variants", action="store_true", help="Generate the full resolution/degradation matrix")
    args = parser.parse_args(argv)
    scenarios = scenario_specs()
    if args.split != "all":
        scenarios = [item for item in scenarios if item.split == args.split]
    write_specs(args.output / "specs")
    variants = CORPUS_VARIANTS if args.all_variants else (DEFAULT_VARIANT,)
    counts = generate_artifacts(scenarios, args.output / "artifacts", formats=tuple(args.formats), variants=variants)
    expected = len(scenarios) * len(args.formats) * len(variants)
    actual = sum(counts.values())
    summary = {"tier": "artifact_corpus_generation", "split": args.split, "scenario_specs": len(scenarios), "variants": [item.name for item in variants], "formats": [item.lower() for item in args.formats], "expected_artifact_cases": expected, "generated_artifact_cases": actual, "counts": counts, "semantic_translation_scored": False}
    (args.output / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False))
    return 0 if actual == expected else 1


if __name__ == "__main__":
    raise SystemExit(main())
