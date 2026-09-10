"""Run a real OpenCode protocol/quality attempt against a linked multi-slide deck."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .deck_scenarios import deck_scenarios
from .generator import generate_deck_pptx
from .model_eval import collect_run_artifacts
from .model_scorers import score_deck_consistency
from .opencode_runner import OpenCodeEvalRunner, _latest_run


def deck_completion_contract(result: Any, *, expected_units: int, artifact_units: int) -> dict[str, Any]:
    media_units = result.media_compliance.get("work_units", {}) if isinstance(result.media_compliance, dict) else {}
    media_pass = len(media_units) == expected_units and all(
        isinstance(item, dict) and item.get("media_sequence_valid") is True
        for item in media_units.values()
    )
    failures: list[str] = []
    if result.status not in {"PASS", "PROTOCOL_SMOKE_ONLY"}:
        failures.append(f"OPENCODE_{result.status}")
    if not result.kslide_complete:
        failures.append("KSLIDE_NOT_COMPLETE")
    if artifact_units != expected_units:
        failures.append("DECK_INCOMPLETE")
    if len(media_units) != expected_units:
        failures.append("MEDIA_WORK_UNIT_COUNT_MISMATCH")
    if not media_pass:
        failures.append("MEDIA_COMPLIANCE_FAILURE")
    return {"pass": not failures, "failures": sorted(set(failures)), "expected_units": expected_units, "artifact_units": artifact_units, "media_unit_count": len(media_units), "media_pass": media_pass}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run OpenCode K-Slide against a real linked deck")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--deck-size", type=int, choices=(3, 5, 10, 20, 50), default=3)
    parser.add_argument("--deck-id")
    parser.add_argument("--model", required=True)
    parser.add_argument("--mode", choices=("protocol", "quality"), default="protocol")
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--ocr-provider", choices=("none", "paddle", "auto"), default="none")
    args = parser.parse_args(argv)
    deck = next((item for item in deck_scenarios() if item.deck_id == args.deck_id), None) if args.deck_id else None
    deck = deck or next(item for item in deck_scenarios() if item.slide_count == args.deck_size)
    args.output.mkdir(parents=True, exist_ok=True)
    source = args.output / f"{deck.deck_id}.pptx"
    if not generate_deck_pptx(deck.slides, source):
        print(json.dumps({"status": "CAPABILITY_BLOCKED", "reason": "python-pptx is unavailable"}))
        return 0
    workspace = args.output / "workspace"
    result = OpenCodeEvalRunner(model=args.model, timeout_seconds=args.timeout, ocr_policy=args.ocr_provider).run(source=source, workspace=workspace, mode=args.mode)
    run = _latest_run(workspace)
    artifacts = collect_run_artifacts(run)
    payload = {
        "deck_id": deck.deck_id,
        "expected_units": deck.slide_count,
        "status": result.status,
        "reason": result.reason,
        "model": args.model,
        "runtime_version": result.runtime_version,
        "artifact_units": len(artifacts),
        "deck_semantics": score_deck_consistency([item["patch"] for item in artifacts], deck.gold),
        "media": result.media_compliance,
        "tool_calls": list(result.tool_calls),
        "forbidden_attempts": list(result.forbidden_attempts),
        "diagnostics": result.diagnostics,
    }
    payload["completion_contract"] = deck_completion_contract(result, expected_units=deck.slide_count, artifact_units=len(artifacts))
    if not payload["completion_contract"]["pass"]:
        payload["status"] = "DECK_INCOMPLETE" if "DECK_INCOMPLETE" in payload["completion_contract"]["failures"] else result.status
    (args.output / "deck-result.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, ensure_ascii=False))
    return 0 if payload["completion_contract"]["pass"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
