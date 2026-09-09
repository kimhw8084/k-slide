# ADR 0026 — Bind media compliance to each work unit

## Decision

Context-image and required-crop reads are traced between that work unit’s
`kslide_evidence` and `kslide_submit` events. Reads from another slide or a
path mentioned in text do not satisfy the requirement.

## Consequences

Multi-slide certification can identify the exact unit with missing visual
evidence and cannot accidentally pass because a different slide read an image.
