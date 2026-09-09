# ADR 0020 — Stratified evaluation splits

## Decision

The 100-spec public corpus uses a deterministic per-category 60/20/20 split,
recorded in generated `splits.json` manifests with dataset version `1.0`.

## Reason

Category-ordered assignment made held-out results structurally unrepresentative.
Every category with enough cases now appears in development, validation, and
held-out, including protected financial, numeric, modality, chart, and visual
categories.

## Consequence

Held-out membership is immutable for corpus version `1.0`; changing it requires
a dataset version bump and a documented reason.
