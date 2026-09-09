# ADR 0022 — Source-local semantic scoring

## Decision

Numeric facts, table values, modality, Hangul, visual relations, and executive
claims are scored against their source region/cell/object rather than by
deck-wide string presence.

## Consequence

A number or correct modality label copied into the wrong row or region fails,
which reflects the business risk of misplaced facts.
