# ADR 0025 — Separate measurement from certification

## Decision

Model evaluation records use explicit states for capability blockage, protocol
smoke, authoritative measurement, certification failure, and later candidate or
certified status. `MEASURED` means the workflow and scorers ran; it does not
mean quality gates passed. Authoritative semantic failures become
`CERTIFICATION_FAIL`.

## Consequences

Exit status, model identity, OpenCode completion, and semantic quality are
reported separately. Non-target protocol runs can validate orchestration but can
never populate a production champion.
