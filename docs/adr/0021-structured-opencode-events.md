# ADR 0021 — Structured OpenCode event normalization

## Decision

Certification parses structured OpenCode JSON events into normalized tool,
message, error, and media-read records. Prompt/log substring scanning is not a
tool-use signal.

## Consequence

Forbidden-tool and required-image assertions are more precise and can be
versioned as OpenCode event shapes evolve. Raw and normalized event logs remain
available in evaluation workspaces.
