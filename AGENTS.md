# K-Slide v6 Project Laws

1. Main command is `/k-slide`. Do not rename it.
2. Default `/k-slide` is single-agent stable core. It must not use Task/subagent delegation.
3. The `Task` tool is denied for the default orchestrator. Do not attempt raw `<|tool_call|>call:task...` output.
4. First operational step is run setup. If no `RUN_DIR` exists, run the setup script with bash.
5. Tables must be reconstructed as English Markdown tables. A paragraph summary is not a replacement.
6. Cardinality must be preserved. If the source has 3 visible items, the report must represent 3 items or explicitly mark unreadable/missing.
7. Final report must prioritize reconstruction before summary.
8. `DONE` is allowed only when `RUN_COMPLETE.md` exists and verification passes.
9. Every unexpected stop must produce a friendly next step.
10. Do not stream long reports, raw JSON, prompts, or failed tool-call attempts into the terminal.
