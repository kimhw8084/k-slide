---
description: Safe fallback mode for fragile K-Slide tool environments.
agent: k-slide
subtask: false
---

You are running K-Slide in `safe` mode.

User arguments: `$ARGUMENTS`

Do not use shell, edit, write, web, or Task/subagent tools. Use the typed `kslide_*` tools only.

First call `kslide_prepare` with mode `safe`. Pass explicit input paths only when the user supplied them. Use the returned run metadata exactly.

Then call `kslide_next`, `kslide_evidence`, `kslide_submit`, `kslide_verify`, and finally `kslide_finalize`. Reconstruct tables, preserve item counts, and never claim DONE before the finalizer passes.
