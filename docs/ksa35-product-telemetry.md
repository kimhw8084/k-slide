# KSA-35 product telemetry and employee reports

KSA-35 extends the existing `TelemetryEvent`, `TelemetryWriter`, execution-job identity, run authorization, and retention paths. It adds no authentication system or network service. The central writer is inactive unless the trusted host process sets `KSLIDE_OPERATIONAL_SERVICE_ROOT`; storage and delivery failures do not change normal K-Slide work.

## Product telemetry

Events use the closed schema at `schemas/operational-telemetry-event.schema.json`. The host, artifact class, semantic outcome, review category, lifecycle, error code, stage, bounded latency/count/resource values, retry attempt, and typed opaque deployment/runtime/model/candidate/run/scope references are scalar allowlisted fields. Lifecycle and stage events are generated after existing engine operations. Semantic `DONE` is recorded only when the exact final marker and current deterministic verification both pass. `NEEDS_REVIEW` comes from persisted engine state and queue/conflict artifacts. Telemetry does not accept a model-supplied semantic state.

The event stream is bounded and append-replaced atomically. Event IDs derive from typed run identity and engine/job revisions; concurrent or restarted writes of the same event are idempotent, and a reused ID with different event data is rejected. Operational-metadata cleanup continues to require an explicit retention policy and authoritative legal-hold provider. Unknown or held metadata is retained.

## Employee issue reporting

Issue reporting is an explicit employee action. Host tools accept only the selected run, one closed category, and a canonical UUIDv4 submission ID:

- `meaning_error`
- `number_error`
- `omission`
- `false_done`
- `unnecessary_review`

OpenCode exposes `report_issue` and `issue_status` through the existing `.opencode/tools/kslide.ts` tool path. The existing Cloud VS Code `kslide_*` host path can call the same core operations with its current session and run binding, setting `--host-adapter cloud_vscode`. The CLI contract is:

```text
k-slide report-issue --run RUN_ID --session-id HOST_SESSION --category omission --submission-id UUID --host-adapter cloud_vscode --json
k-slide issue-status --run RUN_ID --session-id HOST_SESSION --report-id OPAQUE_REPORT_ID --json
```

The host supplies the session from its current authenticated session context. A report includes only its closed allegation category, host/artifact classes, engine-derived semantic snapshot, lifecycle, retry attempt, and opaque references. It has status `ALLEGATION`; it is not a semantic finding and cannot modify EvidenceIR, translations, run completion, or certification. The report ID is opaque and lookup is limited to one report in the authorized current session/run. No report narrative, source material, filenames, paths, screenshots, OCR, prompts, or translations are accepted.

If the operational destination is absent or fails, submission returns `NOT_DELIVERED`, a closed reason code, and a concrete next action. A report is confirmed as recorded only after the writer reports a persisted or idempotently recovered event. Content-bearing diagnostics remain under the existing separately authorized, scoped, audited, and expiring support flow.

## Verification boundary

Repository verification for this change covers typed event/schema validation, hostile-field rejection, credential-canary rejection, authorization, duplicate and concurrent submissions, restart lookup, write/sink failures, retention/legal holds, the Cloud VS Code core host contract, and the OpenCode typed tool definitions. It does not enable a live external telemetry service, run a pilot, or qualify a production deployment.
