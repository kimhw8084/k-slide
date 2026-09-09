---
description: Safe fallback mode for fragile K-Slide tool environments.
agent: k-slide
subtask: false
---

You are running K-Slide in `safe` mode.

User arguments: `$ARGUMENTS`

Do not use shell, edit, write, web, or Task/subagent tools. Use the typed `kslide_*` tools only.

First call `kslide_prepare` with mode `safe`. Pass explicit input paths only when the user supplied them. Use the returned run metadata exactly.

Loop on `kslide_next` until `VERIFIED`, `NEEDS_REVIEW`, or `COMPLETE`. Process each `READY`/`REPAIR_READY` work unit through `kslide_evidence` and structured `kslide_submit`. Verify the whole run when all units are translated, then finalize on `VERIFIED`; repair exact targets only.
