#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../../../../" && pwd)"
ENGINE_ROOT="$PROJECT_ROOT"
if [[ -d "$PROJECT_ROOT/.k-slide-engine/src/k_slide" ]]; then ENGINE_ROOT="$PROJECT_ROOT/.k-slide-engine"; fi
ARGS=()
if [[ $# -gt 0 ]]; then ARGS=(--run "$1"); fi
PYTHONPATH="$ENGINE_ROOT/src${PYTHONPATH:+:$PYTHONPATH}" exec python3 -m k_slide.cli status --root "$PROJECT_ROOT" --json "${ARGS[@]}"
