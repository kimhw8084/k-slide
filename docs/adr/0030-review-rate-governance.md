# ADR 0030 — Govern safe uncertainty and usefulness together

## Decision

Unresolved output is safer than fabrication, but clean cases with unexpected
unresolved regions and large review-rate regressions fail candidate promotion.
Experiments report unresolved-region rate, NEEDS_REVIEW rate, and critical
failure frequency separately.

## Consequences

The model cannot game certification by marking every region unresolved, while
degraded artifacts can still surface honest review requests.
