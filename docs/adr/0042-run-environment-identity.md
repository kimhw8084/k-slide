# ADR 0042 — Immutable run-environment identity

## Status

Implemented for CHG-16 KSA-10. External company runtime, storage, transport,
release, and production qualification remain outside this ADR.

## Decision

Each newly created execution binds one versioned `RunEnvironmentIdentity` in
the existing KSA-06 `ExecutionJob`. The binding is source-free operational
metadata and is persisted with the existing RunStore CAS record. Its
authoritative subjects are the exact K-Slide revision/candidate/version,
KSA-07 runtime artifact/image/build/manifest/SBOM identities, effective model
and model/semantic configuration identities, OCR asset/configuration
identities, termbase identity/version, and the execution and schema contract
versions. Mutable branch names, tags, deployment nicknames, and labels are
not compatibility proof.

The checkpoint carries the binding digest. Durable PaaS admission/service
records, worker claims, status metadata, and workspace-local execution
metadata carry the same identity. Resume compatibility is exact equality. A
worker or execution controller compares the persisted binding with the
current effective binding before an engine step or result commit; failures
return only the source-free mismatch code and field names and do not rewrite
the run identity or mutate queue/admission state.

Rolling upgrades therefore affect new runs only. A newer worker may reattach
to an older run only when it supplies the exact compatible identity. Existing
KSA-06 CAS, idempotency, controller/worker, and KSA-09 scoped authorization
contracts remain authoritative; no second engine, queue, runtime authority,
or evidence authority is introduced.

The repository reference fixtures retain a deterministic identity derived from
the pre-KSA-10 opaque `RuntimeIdentity` API so the earlier KSA-06–09 contract
tests remain reconnectable. Production adapters should provide the explicit
KSA-07-backed identity. Live company qualification and explicit restart/
rederive lineage are not implemented here.
