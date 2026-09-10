# ADR 0036 — Evidence-bound release state

## Decision

Release state is derived by one certification layer from validated, source-free
evidence envelopes. Every evidence item is bound to the candidate Git SHA and
deployment fingerprint; machine evidence also binds to the hash of its actual
result file. A release manifest records those hashes and derives a separate
certification fingerprint. The production doctor recomputes both identities
and fails closed when they differ.

The development SBOM inventory is not certification evidence. Certified
releases require a real environment/image SBOM generated in the approved
release environment. Private bilingual, human-study, model-data, and pilot
evidence remains outside the public repository.

## Consequences

Changing code, model/runtime configuration, OCR assets, prompts, terminology,
or evidence makes prior certification stale. A requested release state is only
a maximum; missing or mismatched evidence blocks generation rather than
creating a misleading manifest.
