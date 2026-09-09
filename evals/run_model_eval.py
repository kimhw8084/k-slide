"""Run OpenCode protocol smoke or target-model quality evaluation.

Quality mode is intentionally blocked unless the requested model is the
approved Gemma 4 31B-it target. A locally available Qwen model can exercise
the command/tool protocol but cannot select linguistic defaults.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from .opencode_runner import OpenCodeEvalRunner
from .scenarios import scenario_specs


def _is_target(model: str) -> bool:
    normalized = model.lower().strip()
    return normalized.endswith("gemma-4-31b-it") or normalized.endswith("gemma4-31b-it") or "/gemma-4-31b-it" in normalized


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Exercise K-Slide through the actual OpenCode command surface")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--runtime", default="opencode")
    parser.add_argument("--mode", choices=("protocol", "quality"), default="protocol")
    parser.add_argument("--source", type=Path)
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args(argv)
    args.output.mkdir(parents=True, exist_ok=True)
    if args.mode == "quality" and not _is_target(args.model):
        record = {
            "status": "GEMMA_QUALITY_EVALUATION_BLOCKED",
            "model": args.model,
            "runtime": args.runtime,
            "scenario_specs": len(scenario_specs()),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "protocol_smoke_allowed": True,
            "quality_block_reason": "GEMMA QUALITY EVALUATION BLOCKED — TARGET ENDPOINT UNAVAILABLE",
            "reason": "Target Gemma 4 31B-it endpoint is not the selected model. Non-target runs cannot certify or tune production translation quality.",
        }
        (args.output / "model-eval-status.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(record))
        return 0
    result = OpenCodeEvalRunner(model=args.model, timeout_seconds=args.timeout).run(source=args.source, workspace=args.output / "workspace", mode=args.mode)
    status = result.status
    if args.mode == "quality" and _is_target(args.model) and result.status != "PASS":
        status = "GEMMA_QUALITY_EVALUATION_BLOCKED"
    record = {
        "status": status,
        "model": args.model,
        "runtime": args.runtime,
        "mode": args.mode,
        "scenario_specs": len(scenario_specs()),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "result": result.as_dict(),
        "quality_metrics_authoritative": args.mode == "quality" and _is_target(args.model) and result.status == "PASS",
        "quality_block_reason": "GEMMA QUALITY EVALUATION BLOCKED — TARGET ENDPOINT UNAVAILABLE" if status == "GEMMA_QUALITY_EVALUATION_BLOCKED" else None,
    }
    (args.output / "model-eval-status.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(record, ensure_ascii=False))
    return 0 if status in {"PASS", "PROTOCOL_SMOKE_ONLY", "GEMMA_QUALITY_EVALUATION_BLOCKED"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
