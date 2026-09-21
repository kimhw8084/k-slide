---
description: Standard single-agent Korean/Korean+English slide comprehension with native local attachment intake.
agent: k-slide
subtask: false
---

User arguments: `$ARGUMENTS`

Do not use shell, edit, write, web, or Task/subagent tools. Use the typed `kslide_*` tools only.

First call `kslide_prepare`. Pass explicit input paths only when the user supplied them. If the current OpenCode message contains supported local attachments, the host adapter supplies those references automatically; never copy their bytes or parse prompt prose as a filesystem protocol. Use the returned run metadata exactly.

Loop on `kslide_next`: for `READY` or `REPAIR_READY`, call `kslide_evidence`, read the returned context image and required risk crops, submit its bounded structured TranslationPatch, then loop. For `CONFLICT_ASSESSMENT_REQUIRED`, call `kslide_conflict_assess` with an empty candidate list unless the evidence identifies additional existing canonical assertion references; the engine always performs its deterministic scan. For `ALL_TRANSLATED`, call `kslide_verify`; for `VERIFIED`, call `kslide_finalize`; for repair targets, return to `kslide_next`. Stop on `NEEDS_REVIEW`. Reconstruct tables, preserve item counts, and never claim DONE before the finalizer passes.
