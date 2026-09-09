"""CLI for corpus-level OpenCode protocol smoke and Gemma evaluation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .model_eval import ModelEvaluationRunner


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run K-Slide cases through the actual OpenCode workflow.")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--split", choices=("development", "validation", "held_out", "all"), default="development")
    parser.add_argument("--formats", nargs="+", default=["png"])
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--mode", choices=("protocol", "quality"), default="quality")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--category", action="append", default=[])
    parser.add_argument("--scenario-id", action="append", default=[])
    parser.add_argument("--config", type=Path)
    args = parser.parse_args(argv)
    configuration = {}
    if args.config:
        configuration = json.loads(args.config.read_text(encoding="utf-8"))
    result = ModelEvaluationRunner(
        model=args.model,
        output=args.output,
        split=args.split,
        formats=tuple(args.formats),
        repeats=max(1, args.repeats),
        timeout=max(1, args.timeout),
        mode=args.mode,
        limit=args.limit,
        categories=tuple(args.category),
        scenario_ids=tuple(args.scenario_id),
        configuration=configuration or None,
    ).run()
    print(json.dumps(result, ensure_ascii=False))
    if result.get("status") in {"GEMMA_QUALITY_EVALUATION_BLOCKED", "CAPABILITY_BLOCK", "NON_AUTHORITATIVE", "PROTOCOL_SMOKE_ONLY", "CAPABILITY_BLOCKED"}:
        return 0
    return 0 if result.get("status") == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
