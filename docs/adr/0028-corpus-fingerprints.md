# ADR 0028 — Fingerprint corpus and frozen held-out data

## Decision

Every evaluation manifest records a deterministic corpus fingerprint and a
held-out fingerprint over scenario specs, split membership, gold, and generator
inputs. Expected fingerprints are checked for the current dataset version.

## Consequences

Changing held-out membership or expected answers is detectable and requires an
explicit dataset-version governance decision.
