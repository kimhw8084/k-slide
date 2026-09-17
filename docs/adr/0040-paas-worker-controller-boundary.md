# ADR 0040 — Durable PaaS worker/controller boundary

## Status

Implemented for the KSA-08 source contract; live company-PaaS qualification is
unproven.

## Decision

K-Slide exposes a small platform-neutral `PaaSJobService` protocol. A
controller submits the existing KSA-06 `ExecutionJob` with an exact opaque
runtime/model/OCR/termbase identity binding and receives a durable
`DurableJobIdentity` immediately. Status, progress, cancellation, and
reconnect use source-free views of that same record.

`PaaSWorker` claims through the service and delegates step execution to the
existing `ExecutionController` and `EngineStep` boundary. Checkpoint and
result mutations therefore retain KSA-06 compare-and-set, monotonic revision,
and operation-id idempotency semantics. The worker acknowledges cancellation
only at a safe boundary, resumes from the last committed checkpoint, and
classifies retryable, non-retryable, and semantic failures without changing
engine semantic ownership. Operational `CANCELED` and `PROCESSING_FAILED`
remain separate from semantic `DONE` and `NEEDS_REVIEW`.

`ReferencePaaSJobService` and `ReferencePaaSRunStore` are deterministic local
integration adapters. The latter delegates state changes to the existing
`DurableTestRunStore` and is not a production persistence, queue, tenancy, or
company transport implementation. `python -m k_slide.worker` (also installed
as `k-slide-worker`) proves the separate worker process path with a
deterministic reference engine. A managed deployment must supply the
approved job-service adapter and the same pinned K-Slide runtime/engine
binding. The worker entrypoint accepts an approved `module:factory` engine
binding for that deployment; no proprietary company API is assumed here.

## Out of scope

KSA-09 production persistence/concurrency policy/backend, KSA-10 full
end-to-end resume binding, KSA-14 company transport, release and company
runtime qualification, and production certification remain later work. This
ADR provides only the stable interfaces needed to connect those layers.
