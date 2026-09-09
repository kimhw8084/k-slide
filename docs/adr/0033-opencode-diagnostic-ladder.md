# ADR 0033 — Diagnose OpenCode before changing K-Slide orchestration

## Decision

Protocol readiness is tested in order: provider health, plain OpenCode,
explicit model, K-Slide agent startup, and the real `/k-slide` command. Each
level stores structured events, timing, exit state, and the last observed tool.
Timeouts terminate the process group and preserve diagnostics.

## Consequences

A provider/model hang is not misclassified as a K-Slide tool-loop defect, and
the same bounded command can be rerun in an approved environment.
