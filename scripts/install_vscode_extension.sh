#!/usr/bin/env bash
set -euo pipefail
SOURCE_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
if ! command -v code >/dev/null 2>&1; then
  echo "The VS Code 'code' CLI is unavailable. Build a VSIX with scripts/build_vscode_extension.sh and use Extensions: Install from VSIX… in Cloud VS Code." >&2
  exit 2
fi
WORK="$(mktemp -d "${TMPDIR:-/tmp}/k-slide-vscode-install.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
"$SOURCE_ROOT/scripts/build_vscode_extension.sh" "$WORK/k-slide.vsix"
code --install-extension "$WORK/k-slide.vsix"
