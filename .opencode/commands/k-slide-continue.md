---
description: Continue the current or most recent incomplete K-Slide run.
agent: k-slide
subtask: false
---

Continue this K-Slide run: `$ARGUMENTS`

Do not use shell, edit, write, web, or Task/subagent tools. Use `kslide_status`, `kslide_next`, `kslide_evidence`, `kslide_submit`, `kslide_verify`, and `kslide_finalize`.

If `$ARGUMENTS` is empty, resolve the current session's run automatically.

Use `kslide_status` and `kslide_next` to resume from persisted state. Do not invent paths or run IDs.

Do not say DONE unless `RUN_COMPLETE.md` exists and verification passes.
