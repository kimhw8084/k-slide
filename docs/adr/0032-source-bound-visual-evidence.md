# ADR 0032 — Bind visual interpretations to engine evidence IDs

## Decision

Model visual relations may reference only source IDs defined by EvidenceIR.
Evaluation gold describes semantic roles and binds them deterministically to
regions, table cells, charts, or visual elements. Ambiguous or missing bindings
are infrastructure failures and are never guessed.

## Consequences

Process and chart scores cannot pass because a model invented matching labels.
Native chart objects receive engine-owned visual IDs while text-bearing shapes
remain addressable through their engine-owned regions.
