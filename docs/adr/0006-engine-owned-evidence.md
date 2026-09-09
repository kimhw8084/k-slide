# ADR 0006: Engine-owned evidence

## Decision

The engine, not the model, owns `EvidenceIR`: source geometry, literal candidates, numeric facts, tables, required IDs, crops, and evidence revisions. Gemma returns only a validated `TranslationPatch`, which the engine merges into `SlideIR`.

## Reason

If the model can author both the source inventory and its translation, internal coverage checks become circular and omissions can look valid.

## Consequences

Submission is stricter, but source completeness and provenance remain auditable. Future OCR/layout providers must emit engine evidence rather than model-authored structure.
