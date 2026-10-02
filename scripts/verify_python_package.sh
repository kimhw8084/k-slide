#!/usr/bin/env bash
set -euo pipefail
SOURCE_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${KSLIDE_BUILD_PYTHON:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/k-slide-wheel-verify.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/source" "$WORK/workspace" "$WORK/wheels"
cp "$SOURCE_ROOT/pyproject.toml" "$SOURCE_ROOT/setup.py" "$SOURCE_ROOT/MANIFEST.in" "$SOURCE_ROOT/README.md" "$SOURCE_ROOT/constraints-production.txt" "$WORK/source/"
cp -R "$SOURCE_ROOT/src" "$SOURCE_ROOT/termbase" "$SOURCE_ROOT/schemas" "$SOURCE_ROOT/prompts" "$SOURCE_ROOT/security" "$WORK/source/"
"$PYTHON" -m pip wheel --disable-pip-version-check --no-deps --wheel-dir "$WORK/wheels" "$WORK/source"
"$PYTHON" -m venv "$WORK/venv"
"$WORK/venv/bin/python" -m pip install --disable-pip-version-check --no-index --no-deps --find-links "$WORK/wheels" k-slide
cd "$WORK/workspace"
"$WORK/venv/bin/python" -I - "$SOURCE_ROOT" <<'PY'
import hashlib
import sys
from pathlib import Path

import k_slide
from k_slide.assets import runtime_asset
from k_slide.governed_terminology import resolve_governed_termbase
from k_slide.security_release import load_pinned_security_policy

source = Path(sys.argv[1]).resolve()
assert not Path(k_slide.__file__).resolve().is_relative_to(source)
for directory in ("termbase", "schemas", "prompts", "security"):
    for expected in (source / directory).rglob("*"):
        if expected.is_file():
            actual = runtime_asset(str(expected.relative_to(source)))
            assert actual.is_relative_to(Path(k_slide.__file__).resolve().parent / "data"), str(actual)
            assert hashlib.sha256(actual.read_bytes()).digest() == hashlib.sha256(expected.read_bytes()).digest()
assert resolve_governed_termbase(Path.cwd()).records
assert load_pinned_security_policy()
print("Clean wheel: governed termbase, schemas, prompts and release policy match source.")
PY
"$WORK/venv/bin/python" -I -m k_slide.cli --help >/dev/null
"$WORK/venv/bin/python" -I -m k_slide.worker --help >/dev/null
echo "Installed CLI and worker import without the checkout or PYTHONPATH."
