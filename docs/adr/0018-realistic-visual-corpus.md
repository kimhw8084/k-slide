# ADR 0018 — Realistic visual corpus

## Decision

Keep 100 fixed semantic specifications, but render each requested format with
actual visual structures and fixed development/validation/held-out splits.

## Reason

A scenario label or a text card cannot prove table, chart, process, or visual
relationship handling. Independent format cases prevent PNG-only execution
from being reported as PDF/PPTX coverage.

## Consequences

Generation requires a verified Korean font. The public corpus remains synthetic;
confidential bilingual gold belongs in the private evaluation protocol.
