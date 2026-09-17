# ADR 0041 — User/workspace-scoped durable admission

## Status

Implemented as the KSA-09 repository-side reference contract. Live company
storage/job-service integration and production qualification remain external
gates.

## Decision

K-Slide keeps the KSA-08 `PaaSController` → `PaaSJobService` → `PaaSWorker`/
`RunStore` boundary and adds an explicit deployment-supplied
`AuthorizedScopeContext`. A scoped operation must match the user, workspace,
and opaque `scope_ref` in that context. A job ID, run ID, or durable identity
alone is not authorization.

The reference adapter stores each scoped control state, FIFO admission record,
job record, KSA-06 run store, and opaque run/result/evidence references below a
scope-derived namespace. A scope lock serializes admission and promotion. The
default policy admits one heavy run per scope; subsequent jobs receive a
monotonic FIFO sequence. The admission record owns that sequence across a
crash before KSA-06 job creation, so recovery reserves record-only positions
until the exact source-free submission is reconciled. Contradictory
record/store state fails closed. Operationally `COMPLETED` jobs—including
semantic `NEEDS_REVIEW`—release the slot and promote at most one next eligible
entry. An explicit identity-bound `NEEDS_REVIEW` resume must reacquire the
scope slot through the same FIFO admission path and cannot overtake active or
queued work. KSA-06 compare-and-set and operation-marker idempotency remain
authoritative for checkpoint and result commits. A bound `ScopedPaaSRunStore`
exposes only the authorized job's store view to a worker.

The persisted control records are source-free. They contain only opaque scope,
identity, runtime, admission, and run/result/evidence references. `AccessKey`
is process-only and is neither accepted as durable control material nor placed
in queue records, artifacts, prompts, or diagnostics.

## Consequences

- Independent scopes use independent locks and namespaces and can progress
  concurrently.
- Recreated reference services recover queue order from every durable admission
  sequence, including record-only crash reservations; they do not scan one
  globally shared active queue.
- Queue visibility, inspect, cancellation, claim, store resolution, and
  result/evidence reference resolution all require the authorized scope in
  scoped mode and fail closed for another scope.
- The platform-neutral `ScopedPaaSJobService` protocol is the production
  adapter boundary. K-Slide does not define LDAP/login, company persistence,
  or company job-service APIs.
- The local `ReferencePaaSJobService` scoped filesystem backend is deterministic
  qualification evidence, not live company-storage certification.

## Out of scope

Exact model/OCR/termbase resume compatibility, the three-class storage model,
retention-policy split, deletion/legal hold, company transport, release, live
company-runtime qualification, and production certification remain KSA-10
through KSA-14 work or external deployment gates.
