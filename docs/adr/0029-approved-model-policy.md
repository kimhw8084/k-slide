# ADR 0029 — Require approved effective model identity

## Decision

Production quality evaluation requires both requested and effective model IDs to
match an exact approved ID or an explicitly configured private alias. Model
name substrings are not sufficient evidence of Gemma identity or capability.

## Consequences

Local Qwen runs remain protocol smoke only. Private deployment aliases can be
approved without committing confidential provider names to the repository.
