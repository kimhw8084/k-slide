#!/usr/bin/env bash
set -euo pipefail
fail=0
check(){ if eval "$2"; then echo "[OK] $1"; else echo "[FAIL] $1"; fail=1; fi }
check "main command" "test -f .opencode/commands/k-slide.md"
check "agent" "test -f .opencode/agents/k-slide.md"
check "skill file" "test -f .opencode/skills/k-slide/SKILL.md"
check "skill frontmatter" "grep -q '^name: k-slide' .opencode/skills/k-slide/SKILL.md"
check "prepare script executable" "test -x .opencode/skills/k-slide/bin/prepare_run.sh"
mkdir -p .k-slide-input .k-slide-runs
check "input folder" "test -d .k-slide-input"
check "run folder" "test -d .k-slide-runs"
echo test > .k-slide-runs/_doctor_write_test.txt
check "write/read smoke test" "grep -q test .k-slide-runs/_doctor_write_test.txt"
rm -f .k-slide-runs/_doctor_write_test.txt
if [[ $fail -eq 0 ]]; then echo "DONE — K-Slide v6 install looks structurally valid."; else echo "FAILED — Fix failed checks."; fi
