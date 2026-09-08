#!/usr/bin/env bash
set -euo pipefail
SOURCE_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${1:-.}"
PYTHONPATH="$SOURCE_ROOT/src${PYTHONPATH:+:$PYTHONPATH}" exec python3 -m k_slide.cli verify-install --target "$TARGET" --scope project
