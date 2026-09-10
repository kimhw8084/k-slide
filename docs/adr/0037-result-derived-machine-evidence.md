# ADR 0037 — Result-derived machine certification evidence

## Status

Accepted for K-Slide 0.3.5 certification closure; schema/adapter 2.0.

## Decision

Machine evidence envelopes are generated only by type-specific adapters from
the actual runner result files.  Each envelope records unique source roles and
SHA-256 hashes.  Loading an envelope revalidates every source hash and
re-derives the payload before the release-state evaluator can use it.

Model-evaluation evidence must also prove the exact declared scenario ×
format × repeat matrix for its split. Deployment/behavior identity is separate
from experiment-plan identity: the former is assembled through the shared
deployment-factor allowlist and excludes sampling controls and certification
metadata; the latter records split, membership, formats, repetitions, filters,
limits, and evaluation settings. Validation, high-risk, and held-out evidence
therefore share one behavior hash without pretending that their sampling plans
are identical.

The stable evidence identity excludes packaging-only metadata such as the
envelope timestamp and path.  The physical envelope hash remains available for
tamper/audit checks, while the deterministic evidence identity participates in
the certification fingerprint.

Human, private, and organizational attestations remain source-free external
evidence and are still required for the states that depend on them.

## Consequences

Changing a result, source role/hash, adapter version, or derived payload makes
the evidence invalid.  Administrators cannot promote a release by editing
machine metrics or selecting a higher requested state.  Old development-only
machine metrics or selecting a higher requested state. Old development-only
machine envelopes without adapter provenance, complete matrix proof, or the 2.0
identity fields cannot satisfy certification.
