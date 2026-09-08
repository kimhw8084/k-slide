#!/usr/bin/env bash
set -euo pipefail
SOURCE_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
HOME_DIR="${HOME:?HOME is required}"
DEST="${KSLIDE_OPENCODE_CONFIG:-$HOME_DIR/.config/opencode}"
PYTHONPATH="$SOURCE_ROOT/src${PYTHONPATH:+:$PYTHONPATH}" exec python3 -m k_slide.cli install --source-root "$SOURCE_ROOT" --target "$DEST" --scope global
