# ADR 0003: Deterministic Completion

## Decision

Only `finalize_run` may create `RUN_COMPLETE.md`, and it may do so only after deterministic verification passes with no critical or unaccounted items.

## Alternatives

Treat report presence or model self-attestation as completion.

## Reason

The model cannot reliably prove that it preserved every number, table cell, or commitment level. Completion is a safety boundary, not a prose claim.

## Consequences

Incomplete or damaged runs remain recoverable and visible as failure/review states. The verifier must grow as new integrity rules are added.
