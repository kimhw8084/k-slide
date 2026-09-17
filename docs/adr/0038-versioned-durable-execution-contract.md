# ADR 0038 — Versioned durable execution contract

## Status

Accepted for the KSA-06 execution-contract boundary.

## Decision

K-Slide uses one versioned, source-free `ExecutionJob` record per run.  The
record carries stable run/job/execution identities, an opaque run-store
reference, operational lifecycle, cancellation intent, bounded operational
retry state, resume eligibility, terminal outcome, and the last committed
`RunCheckpoint`.  A checkpoint binds the contract version and identities to
an engine phase, bounded progress, the engine `RunState` revision, and the
`WorkQueue` revision.  Result commits use source-free operation markers.

All mutable record updates use an expected revision.  A store accepts exactly
the next checkpoint revision, rejects stale writers explicitly, and treats an
identical replay of an accepted checkpoint or result marker as idempotent.
The workspace adapter retains atomic replacement and the existing short-lived
run lock.  The durable-profile reference adapter uses the same CAS contract
over an isolated filesystem root; it is a deterministic test adapter, not a
PaaS backend.

Workspace-local and durable PaaS execution use the same host-neutral engine
step boundary.  The KSA-08 controller/worker layer binds the durable profile
without introducing another engine. `RunState`, `WorkQueue`, EvidenceIR, TranslationPatch,
verification, repair, and finalization remain engine-owned; the execution
record coordinates when those operations run and where their control state is
stored.  Operational `CANCELED` and `PROCESSING_FAILED` never become semantic
`NEEDS_REVIEW`.

## Consequences

An adapter/controller can be recreated and recover the last valid checkpoint
without changing run identity.  Corrupt, incompatible, or hash-inconsistent
control state fails closed.  Cancellation persists until a safe boundary
acknowledges it, and retry attempts cannot become an unbounded regeneration
loop.  Production persistence, queueing, tenancy/isolation, runtime binding,
and worker/controller infrastructure are layered by KSA-08/KSA-09 without
changing this KSA-06 CAS contract. KSA-09's live company-storage
qualification and later storage/retention work remain outside this ADR.
