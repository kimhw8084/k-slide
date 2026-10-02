#!/usr/bin/env bash
set -euo pipefail
SOURCE_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/k-slide-vscode-verify.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
OUTPUT="${1:-$WORK/k-slide.vsix}"
"$SOURCE_ROOT/scripts/build_vscode_extension.sh" "$OUTPUT"
python3 - "$OUTPUT" <<'PY'
import json
import sys
import zipfile

with zipfile.ZipFile(sys.argv[1]) as archive:
    manifest = json.loads(archive.read("extension/package.json"))
    assert manifest["name"] == "k-slide-cloud-vscode"
    assert manifest["publisher"] == "k-slide"
    assert manifest["main"] == "./dist/src/extension.js"
    assert "extension/dist/src/extension.js" in archive.namelist()
    assert not any(name.startswith("extension/node_modules/") for name in archive.namelist())
print("VS Code package manifest, entrypoint, and dependency boundary passed.")
PY
