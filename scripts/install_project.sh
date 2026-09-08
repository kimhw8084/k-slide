#!/usr/bin/env bash
set -euo pipefail
TARGET="${1:-}"
if [[ -z "$TARGET" ]]; then echo "Usage: ./scripts/install_project.sh /path/to/project"; exit 1; fi
mkdir -p "$TARGET/.opencode" "$TARGET/.k-slide-input" "$TARGET/.k-slide-runs"
cp -R .opencode/commands "$TARGET/.opencode/"
cp -R .opencode/agents "$TARGET/.opencode/"
mkdir -p "$TARGET/.opencode/skills"
cp -R .opencode/skills/k-slide "$TARGET/.opencode/skills/"
cp AGENTS.md "$TARGET/AGENTS.md"
chmod +x "$TARGET/.opencode/skills/k-slide/bin/"*.sh
echo "Installed K-Slide v6 into $TARGET"
echo "Next: cd $TARGET && opencode, then run /k-slide"
