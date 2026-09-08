---
description: Continue a K-Slide v6 run from an existing run folder.
agent: k-slide
subtask: false
---

Continue this K-Slide run: `$ARGUMENTS`

Do not use Task/subagents.

If `$ARGUMENTS` is empty, ask the user for the run folder.

Read `RUN_STATE.json`, then resume from the next missing/placeholder artifact:
- `01_slide_understanding.json`
- `05_final_report.md`
- `06_verification.md`
- `RUN_COMPLETE.md`

Do not say DONE unless `RUN_COMPLETE.md` exists and verification passes.
