# ADR 0027 — Score every persisted work unit

## Decision

The evaluator loads all translation, EvidenceIR, and SlideIR artifacts keyed by
`work_unit_id`. Unit metrics are scored locally and then aggregated into deck,
category, format, and run summaries.

## Consequences

A multi-slide run cannot pass because only its first patch was scored. Missing
or duplicate unit artifacts remain visible as end-to-end failures.
