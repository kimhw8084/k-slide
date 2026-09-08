# ADR 0002: Versioned SlideIR

## Decision

Use a versioned `SlideIR` as the canonical source of truth for regions, tables, numeric facts, visual relations, coverage, unresolved evidence, and executive semantics.

## Alternatives

Keep independent Markdown, JSON, and model-output representations.

## Reason

Independent artifacts drift and make verification unreliable. A typed intermediate representation lets deterministic renderers and verifiers share one state.

## Consequences

Model-shaped payloads must be schema-validated and canonicalized before persistence. Renderers can evolve without changing the evidence contract.
