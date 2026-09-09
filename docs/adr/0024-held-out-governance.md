# ADR 0024 — Held-out evaluation governance

## Decision

Validation drives tuning. Held-out is evaluated only for a frozen candidate or
release workflow. Champion promotion rejects new critical types, protected
category regression, worse worst-case behavior, and any held-out critical
failure.

## Consequence

The current champion remains `UNSET` until a target Gemma run satisfies the
governance rules. Qwen or other non-target models cannot populate it.
