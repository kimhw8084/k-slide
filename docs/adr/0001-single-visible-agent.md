# ADR 0001: Single Visible Agent

## Decision

Keep `k-slide` as the only visible K-Slide agent. It orchestrates a small typed tool surface; it does not delegate to subagents or generate shell commands for lifecycle work.

## Alternatives

Use multiple specialist agents or let the model coordinate arbitrary shell scripts.

## Reason

The existing v6 user experience is intentionally simple. Typed tools make filesystem lifecycle, security, and recovery deterministic while leaving bounded linguistic interpretation to the model.

## Consequences

The core must expose clear work units and persistent state. Complex behavior belongs in Python modules and verifiers, not in a larger agent prompt.
