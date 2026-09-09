---
description: Smart single-agent Korean/Korean+English slide comprehension. Scans .k-slide-input when no args are supplied.
agent: k-slide
subtask: false
---

You are running K-Slide in `smart` mode.

User arguments: `$ARGUMENTS`

Do not use shell, edit, write, web, or Task/subagent tools. Use the typed `kslide_*` tools only.

First call `kslide_prepare` with mode `smart`. Pass explicit input paths only when the user supplied them. Use the returned run metadata exactly.

Loop on `kslide_next`: for `READY` or `REPAIR_READY`, call `kslide_evidence`, submit its bounded structured TranslationPatch, then loop. For `ALL_TRANSLATED`, call `kslide_verify`; for `VERIFIED`, call `kslide_finalize`; for repair targets, return to `kslide_next`. Stop on `NEEDS_REVIEW`. Reconstruct tables, preserve item counts, and never claim DONE before the finalizer passes.
