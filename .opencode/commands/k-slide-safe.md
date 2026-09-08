---
description: Safe fallback mode for fragile tool-call environments.
agent: k-slide
subtask: false
---

You are running K-Slide v6 in `safe` mode.

User arguments: `$ARGUMENTS`

Do not use Task/subagents.

First, ensure setup exists. Your first tool action should be to run this with the bash tool unless a valid RUN_DIR is already available:

```bash
.opencode/skills/k-slide/bin/prepare_run.sh safe $ARGUMENTS
```

After setup succeeds, use the printed `RUN_DIR` exactly. If setup fails or bash is denied, do not analyze images. Print friendly manual setup instructions and end `FAILED`.

Then follow the v6 workflow: reconstruct tables, preserve item counts, write compact artifacts, verify before DONE, and write `RUN_COMPLETE.md` only after verification passes.
