# ADR 0043: Versioned three-plane storage contract

Status: Accepted for CHG-16 / KSA-11

## Decision

K-Slide uses one host-neutral storage contract, version `1.0`, with exactly
three semantic planes:

1. `ephemeral_processing_scratch` contains recreateable conversion staging,
   transient render workspaces, transient OCR workspaces, and coordination
   locks. It is never an authority for run admission, checkpoints, results,
   environment binding, evidence identity, or content needed to resume.
2. `durable_user_workspace_run_data` contains authorized user/workspace run
   data: immutable input snapshots and manifests, normalized renders and
   native extraction, crops/OCR/EvidenceIR, translation patches, canonical
   IR/reports/verification, run state, `WORK_QUEUE.json`, KSA-06 execution
   records/checkpoints/result markers, KSA-09 admission state, environment
   binding, failure/completion markers, metrics, and recovery/session metadata.
3. `central_non_content_operational_telemetry` contains only the explicit
   allowlisted telemetry event schema: opaque deployment/runtime/model/run or
   worker references, lifecycle and error codes, stage timings, bounded
   counts/resource use, and retry information. It is not a content or resume
   authority.

`StorageReference` carries the version, plane, artifact class, relative path,
and the existing scope/run context. `StorageLayout` is the shared resolver and
write boundary used by workspace-local and reference durable adapters. It
rejects traversal, symlink/alias escape, wrong-plane resolution, and scope
mismatch. A durable reference cannot be resolved with only a guessed run ID or
store reference.

## Reference deployment proof

The deterministic filesystem adapters preserve compatible historical durable
paths while making the roots unambiguous:

| Adapter | Durable | Scratch | Central telemetry |
| --- | --- | --- | --- |
| Workspace | `.k-slide-runs/<run-id>/` | `.k-slide-scratch/<run-id>/` | `.k-slide-telemetry/` |
| Scoped reference PaaS | `job-service/scopes/<scope-key>/` | `scratch/<scope-key>/<job-id>/` | `telemetry/` |

The legacy unscoped reference PaaS paths contain only the existing source-free
KSA-08/KSA-06 control compatibility records; scoped user/workspace persistence
remains the KSA-09 authority. No company endpoint or live PaaS qualification is
defined here.

Scratch cleanup removes only the run's scratch root. Recreating the layout and
adapter resolves the durable run/control/evidence state and allows processing
intermediates to be regenerated. Telemetry write loss returns a non-fatal
failure and cannot affect durable resume. Malformed, unknown, nested,
content-shaped, path-shaped, binary, credential, `Authorization`, token, or
`AccessKey` telemetry is rejected before persistence; it is not sanitized into
an admin content channel.

Retention/deletion policy remains outside this decision. KSA-12 owns content
versus operational-metadata retention configuration and KSA-13 owns deletion,
expiry, and legal hold semantics.
