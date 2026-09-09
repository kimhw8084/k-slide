# ADR 0023 — Reproducible heavy certification environment

## Decision

LibreOffice and PaddleOCR integration runs in an explicit heavyweight Docker
image with a self-test. The normal PR tier reports those capabilities
separately and does not silently treat missing dependencies as model failures.

## Consequence

Heavy results are reproducible only when the image self-test passes and exact
versions are recorded. Confidential evaluation remains outside public runners.
