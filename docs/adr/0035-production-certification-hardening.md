# ADR 0035 — Production certification hardening

## Decision

Keep K-Slide in `DEVELOPMENT` until external runtime, target-model, private
gold, human, security, reliability, governance, and pilot evidence exists.
Implement the local controls now, but make production mode fail closed when a
profile, attestation, OCR assets, target identity, or certification fingerprint
is absent. Diagnostic/support output is redacted and support bundles contain
operational metadata only. Run cleanup is administrator-facing and refuses
symlinks or paths outside the run root.

## Consequences

The repository can test production-control behavior without pretending that
Docker, LibreOffice, PaddleOCR, Gemma, internal artifacts, or human studies
are available. A managed deployment must provide tenant isolation, access
control for admin cleanup/support commands, approved model-data policy, and
the external certification evidence before changing the release state.
