---
description: Continue the current or most recent incomplete K-Slide run.
agent: k-slide
subtask: false
---

Continue this K-Slide run: `$ARGUMENTS`

Do not use shell, edit, write, web, or Task/subagent tools. Use `kslide_status`, `kslide_next`, `kslide_evidence`, `kslide_submit`, `kslide_verify`, and `kslide_finalize`.

If `$ARGUMENTS` is empty, resolve the current session's run automatically.

Use `kslide_status` and loop with `kslide_next` to resume from persisted queue state. Do not invent paths or run IDs. Process each returned work unit through `kslide_evidence` and structured `kslide_submit`; do not repeat verified units.

When `kslide_next` returns `VERIFIED`, call `kslide_finalize`. Do not say DONE unless `RUN_COMPLETE.md` exists and current verification passes.
