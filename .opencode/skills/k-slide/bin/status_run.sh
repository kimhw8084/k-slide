#!/usr/bin/env bash
set -euo pipefail
RUN_DIR="${1:-}"
if [[ -z "$RUN_DIR" ]]; then echo "FAILED — Missing run folder. Usage: /k-slide-status .k-slide-runs/<run-id>"; exit 0; fi
python3 - "$RUN_DIR" <<'PY'
import sys,json
from pathlib import Path
run=Path(sys.argv[1])
print('K-Slide status for: '+str(run))
if not run.exists(): print('FAILED — Run folder does not exist.'); sys.exit(0)
p=run/'RUN_STATE.json'
if p.exists():
    try:
        st=json.loads(p.read_text()); print('State: '+str(st.get('status'))+' | phase: '+str(st.get('phase'))+' | mode: '+str(st.get('mode')))
    except Exception as e: print('State: corrupt RUN_STATE.json '+str(e))
else: print('State: missing RUN_STATE.json')
for c in ['00_input_inventory.json','01_slide_understanding.json','05_final_report.md','06_verification.md','RUN_COMPLETE.md','RUN_INCOMPLETE.md','RUN_FAILED.md','RUN_TOOL_ERROR.md']:
    fp=run/c
    if not fp.exists(): print('[ ] '+c)
    else:
        txt=fp.read_text(errors='ignore')[:200].lower(); ph='placeholder' in txt and c!='RUN_INCOMPLETE.md'
        print((' [~] ' if ph else ' [x] ')+c+(' (placeholder)' if ph else ''))
if (run/'RUN_COMPLETE.md').exists(): print('DONE — open 05_final_report.md')
elif (run/'RUN_FAILED.md').exists() or (run/'RUN_TOOL_ERROR.md').exists(): print('FAILED — inspect RUN_FAILED.md or RUN_TOOL_ERROR.md')
else: print('NEEDS REVIEW — continue with:\n/k-slide-continue '+str(run))
PY
