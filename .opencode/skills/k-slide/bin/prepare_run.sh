#!/usr/bin/env bash
set -euo pipefail
MODE="${1:-smart}"
shift || true
python3 - "$MODE" "$@" <<'PY'
import sys, json, uuid
from pathlib import Path
from datetime import datetime
mode = sys.argv[1] if len(sys.argv) > 1 else 'smart'
args = sys.argv[2:]
root = Path.cwd()
input_dir = root / '.k-slide-input'
run_root = root / '.k-slide-runs'
input_dir.mkdir(exist_ok=True)
run_root.mkdir(exist_ok=True)
supported = {'.png','.jpg','.jpeg','.webp','.pdf'}

def natural_key(p):
    import re
    return [int(t) if t.isdigit() else t.lower() for t in re.split(r'(\d+)', str(p))]

def collect(a):
    p=Path(a)
    if p.is_dir(): return [x for x in p.rglob('*') if x.suffix.lower() in supported]
    return [p] if p.suffix.lower() in supported else []
files=[]
if args:
    for a in args: files.extend(collect(a))
else:
    files=[x for x in input_dir.rglob('*') if x.suffix.lower() in supported]
files=sorted(dict.fromkeys(files), key=natural_key)
run_id='k-slide-'+datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+uuid.uuid4().hex[:4]
run_dir=run_root/run_id
run_dir.mkdir(parents=True, exist_ok=False)
rel=[]
for f in files:
    try: rel.append(str(f.relative_to(root)))
    except Exception: rel.append(str(f))
(run_dir/'00_input_inventory.json').write_text(json.dumps({'status':'generated','mode':mode,'input_count':len(rel),'input_files':rel,'no_input':len(rel)==0,'supported_extensions':sorted(supported)}, indent=2, ensure_ascii=False))
(run_dir/'00_run_manifest.md').write_text('# K-Slide Run Manifest\n\nRun ID: '+run_id+'\nMode: '+mode+'\nInput count: '+str(len(rel))+'\n\n'+'\n'.join('- '+x for x in rel)+'\n')
state={'run_id':run_id,'mode':mode,'status':'setup_complete' if rel else 'failed_no_input','phase':'setup','run_dir':str(run_dir.relative_to(root)),'input_files':rel,'next_action':('/k-slide-continue '+str(run_dir.relative_to(root))) if rel else 'Add images to .k-slide-input/ or pass a valid path, then run /k-slide.','task_policy':'single_agent_no_task_default'}
(run_dir/'RUN_STATE.json').write_text(json.dumps(state, indent=2, ensure_ascii=False))
(run_dir/'RUN_RECOVERY_GUIDE.md').write_text('# K-Slide Recovery Guide\n\nRun folder: `'+str(run_dir.relative_to(root))+'`\n\nIf OpenCode stops unexpectedly, run:\n\n```text\n/k-slide-status '+str(run_dir.relative_to(root))+'\n/k-slide-continue '+str(run_dir.relative_to(root))+'\n```\n')
(run_dir/'ARTIFACT_MANIFEST.json').write_text(json.dumps({'required_for_complete':['01_slide_understanding.json','05_final_report.md','06_verification.md','RUN_COMPLETE.md'],'optional_strict_artifacts':['02_layout_coverage.json','03_translation_audit.md','04_visual_interpretation.md','07_unresolved_items.md','08_coverage_ledger.md','09_glossary_suggestions.json','10_reader_quiz.md']}, indent=2))
(run_dir/'01_slide_understanding.json').write_text(json.dumps({'status':'placeholder','generated':False,'message':'Not generated yet.'}, indent=2))
(run_dir/'05_final_report.md').write_text('# Placeholder\n\nStatus: not generated yet.\n')
(run_dir/'06_verification.md').write_text('# Placeholder\n\nStatus: not generated yet.\n')
for name, content in {
 '02_layout_coverage.json': json.dumps({'status':'optional_placeholder','generated':False}, indent=2),
 '03_translation_audit.md':'# Optional placeholder\n',
 '04_visual_interpretation.md':'# Optional placeholder\n',
 '07_unresolved_items.md':'# Optional placeholder\n',
 '08_coverage_ledger.md':'# Optional placeholder\n',
 '09_glossary_suggestions.json': json.dumps({'status':'optional_placeholder','suggestions':[]}, indent=2),
 '10_reader_quiz.md':'# Optional placeholder\n'
}.items(): (run_dir/name).write_text(content)
if not rel:
    (run_dir/'RUN_FAILED.md').write_text('# FAILED — No input files found\n\nPut slide images in `.k-slide-input/` or run `/k-slide path/to/slide.png`.\n')
print('RUN_DIR='+str(run_dir.relative_to(root)))
print('run_dir='+str(run_dir.relative_to(root)))
print('MODE='+mode)
print('INPUT_COUNT='+str(len(rel)))
print('NO_INPUT='+('1' if not rel else '0'))
print('NEXT_COMMAND=/k-slide-continue '+str(run_dir.relative_to(root)))
PY
