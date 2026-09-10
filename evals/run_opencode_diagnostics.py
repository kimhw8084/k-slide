from __future__ import annotations

import argparse
import json
from pathlib import Path

from .opencode_diagnostics import run_diagnostic_ladder


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the bounded OpenCode provider-to-K-Slide diagnostic ladder.")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--opencode")
    parser.add_argument("--cold-timeout", type=int, default=300)
    parser.add_argument("--warm-timeout", type=int, default=60)
    parser.add_argument("--candidate-profile", type=Path, help="Explicit candidate deployment specification")
    args = parser.parse_args(argv)
    result = run_diagnostic_ladder(model=args.model, output=args.output, opencode=args.opencode, cold_timeout=args.cold_timeout, warm_timeout=args.warm_timeout, candidate_profile=args.candidate_profile)
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
