#!/usr/bin/env bash
set -euo pipefail
SOURCE_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
PACKAGE_ROOT="$SOURCE_ROOT/integrations/vscode"
OUTPUT="${1:-${TMPDIR:-/tmp}/k-slide-cloud-vscode.vsix}"
EXPECTED_NODE="22.15.0"
EXPECTED_NPM="10.9.2"
ACTUAL_NODE="$(node --version | sed 's/^v//')"
ACTUAL_NPM="$(npm --version)"
if [[ "$ACTUAL_NODE" != "$EXPECTED_NODE" || "$ACTUAL_NPM" != "$EXPECTED_NPM" ]]; then
  echo "K-Slide VS Code build requires Node $EXPECTED_NODE and npm $EXPECTED_NPM (found Node $ACTUAL_NODE and npm $ACTUAL_NPM)." >&2
  exit 2
fi
WORK="$(mktemp -d "${TMPDIR:-/tmp}/k-slide-vscode-build.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/package"
cp "$PACKAGE_ROOT/package.json" "$PACKAGE_ROOT/package-lock.json" "$PACKAGE_ROOT/tsconfig.json" "$PACKAGE_ROOT/README.md" "$PACKAGE_ROOT/.vscodeignore" "$WORK/package/"
cp -R "$PACKAGE_ROOT/src" "$WORK/package/src"
(
  cd "$WORK/package"
  npm ci --no-audit --no-fund
  npm test
  ./node_modules/.bin/vsce package --no-dependencies --skip-license --out "$OUTPUT"
)
node -e 'const cp=require("child_process"); const p=process.argv[1]; cp.execFileSync("unzip",["-tq",p],{stdio:"ignore"}); const listing=cp.execFileSync("unzip",["-Z1",p],{encoding:"utf8"}).split(/\r?\n/); if(!listing.includes("extension/package.json") || listing.some(name => name.endsWith(".test.js"))) process.exit(2);' "$OUTPUT"
echo "K-Slide VS Code package validated: $OUTPUT"
