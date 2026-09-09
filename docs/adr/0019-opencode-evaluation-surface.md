# ADR 0019 — OpenCode is the certification surface

## Decision

Model quality evaluation must exercise the actual OpenCode `k-slide` command
and typed tools. Direct model calls may be added only as diagnostic ablations.

## Reason

Users run K-Slide through OpenCode, including command discovery, permissions,
media reads, retries, reports, and finalization. A direct API score cannot prove
that workflow.

## Consequences

The local runner captures JSON events and labels a non-Gemma model as protocol
smoke only. Target-model quality remains blocked until the approved Gemma 4
31B-it endpoint and internal gold set are available.
