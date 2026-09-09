# ADR 0008: Evidence revisions bind translation

## Decision

`EvidenceIR` receives a stable SHA-256 revision over canonical JSON. Every `TranslationPatch` must reference the current revision, and stale patches are rejected.

## Reason

A translation produced against old crops or extraction results must never overwrite a newer source interpretation.

## Consequences

Evidence regeneration intentionally invalidates pending model work. This is preferable to silent stale merges and also supports content-addressed reuse later.
