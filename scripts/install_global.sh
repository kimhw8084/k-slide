#!/usr/bin/env bash
set -euo pipefail
DEST="$HOME/.config/opencode"
mkdir -p "$DEST/skills"
cp -R .opencode/commands "$DEST/"
cp -R .opencode/agents "$DEST/"
cp -R .opencode/skills/k-slide "$DEST/skills/"
chmod +x "$DEST/skills/k-slide/bin/"*.sh
echo "Installed K-Slide v6 globally into $DEST"
