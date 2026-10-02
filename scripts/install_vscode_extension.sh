#!/usr/bin/env bash
set -euo pipefail
SOURCE_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
VSIX="${1:-}"
if ! command -v code >/dev/null 2>&1; then
  echo "The VS Code 'code' CLI is unavailable. Build a VSIX with scripts/build_vscode_extension.sh and use Extensions: Install from VSIX… in Cloud VS Code." >&2
  exit 2
fi
if [[ -z "$VSIX" ]]; then
  WORK="$(mktemp -d "${TMPDIR:-/tmp}/k-slide-vscode-install.XXXXXX")"
  trap 'rm -rf "$WORK"' EXIT
  VSIX="$WORK/k-slide.vsix"
  "$SOURCE_ROOT/scripts/build_vscode_extension.sh" "$VSIX"
fi
python3 - "$VSIX" <<'PY'
import json
import sys
import zipfile

with zipfile.ZipFile(sys.argv[1]) as archive:
    manifest = json.loads(archive.read("extension/package.json"))
    if manifest.get("name") != "k-slide-cloud-vscode" or manifest.get("publisher") != "k-slide":
        raise SystemExit("The selected VSIX is not the K-Slide extension.")
PY
code --install-extension "$VSIX"
