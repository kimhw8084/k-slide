# ADR 0037 — Result-derived machine certification evidence

## Status

Accepted for K-Slide 0.3.5 certification closure.

## Decision

Machine evidence envelopes are generated only by type-specific adapters from
the actual runner result files.  Each envelope records unique source roles and
SHA-256 hashes.  Loading an envelope revalidates every source hash and
re-derives the payload before the release-state evaluator can use it.

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
machine envelopes without adapter provenance cannot satisfy certification.
