#!/usr/bin/env bash
set -euo pipefail
SOURCE_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${KSLIDE_TEST_PYTHON:-python3}"
cd "$SOURCE_ROOT"
npm ci --prefix .opencode --ignore-scripts --no-audit --no-fund
npm exec --yes --package=bun@1.3.9 -- bun tests/test_host_runtime.ts
KSLIDE_TEST_PYTHON="$PYTHON" KSLIDE_PYTHON="$PYTHON" npm exec --yes --package=bun@1.3.9 -- bun tests/test_chg16_opencode_plugin.ts
