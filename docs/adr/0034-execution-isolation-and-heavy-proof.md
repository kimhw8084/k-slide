# ADR 0034 — Isolated diagnostics and required heavy proof

## Decision

OpenCode diagnostics run provider checks in a clean workspace and install
K-Slide only in a separate project workspace. Heavy runtime verification runs
in a required container mode with local OCR assets, disabled runtime network,
host-mounted output, and explicit failure on missing LibreOffice/Paddle
capabilities.

## Alternatives

One workspace and container-private output were rejected because project
configuration could contaminate provider diagnostics and successful evaluation
artifacts could disappear when the container exited.

## Consequences

The diagnostic result identifies the first failing layer, timeout cleanup is
testable, and heavy results survive the container. Local development may still
report capability blocks until the managed heavy environment is available.
