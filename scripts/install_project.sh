#!/usr/bin/env bash
set -euo pipefail
SOURCE_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${1:-}"
if [[ -z "$TARGET" ]]; then
  echo "Usage: ./scripts/install_project.sh /path/to/project"
  exit 1
fi
PYTHONPATH="$SOURCE_ROOT/src${PYTHONPATH:+:$PYTHONPATH}" exec python3 -m k_slide.cli install --source-root "$SOURCE_ROOT" --target "$TARGET" --scope project
