"""Target-model evaluation entry point.

The repository intentionally does not guess at a provider API. An approved
environment should provide a TranslationPatch callable and invoke this runner
with the exact runtime/model metadata. Without one, the command records a
blocked evaluation instead of substituting a different model.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from .scenarios import scenario_specs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--runtime", required=True)
    parser.add_argument("--translation-provider", help="Approved environment-specific provider entry point")
    args = parser.parse_args(argv)
    args.output.mkdir(parents=True, exist_ok=True)
    record = {"status": "BLOCKED" if not args.translation_provider else "READY_FOR_PROVIDER", "model": args.model, "runtime": args.runtime, "translation_provider": args.translation_provider, "scenario_specs": len(scenario_specs()), "generated_at": datetime.now(timezone.utc).isoformat(), "reason": "No target-model provider was available in this workspace." if not args.translation_provider else "Provider integration is environment-specific and must be implemented by the approved runner."}
    (args.output / "model-eval-status.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(record))
    return 2 if record["status"] == "BLOCKED" else 0


if __name__ == "__main__":
    raise SystemExit(main())
