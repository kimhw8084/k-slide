# KSA-34 candidate-bound rollout controls

KSA-34 adds deployment admission controls at the shared `prepare_run` engine
boundary. The CLI and OpenCode `/k-slide` invocation both pass through this
boundary. Host arguments, prompt text, file paths, filenames, and source bytes
do not select a rollout policy, candidate, or cohort.

## Candidate and policy identity

The source-free candidate binding contains the exact KSA-10 source revision,
KSA-33 deployment fingerprint, and full KSA-10 run-environment identity hash:

```json
{
  "subject_git_sha": "<40 lowercase hex characters>",
  "deployment_fingerprint": "<64 lowercase hex characters>",
  "run_environment_identity_sha256": "<64 lowercase hex characters>"
}
```

The complete run-environment identity already binds the runtime, model, OCR,
termbase, inference route, and semantic configuration. A rollout policy is
separately identified by SHA-256 over its canonical signed payload and carries
contract/policy version `1.0`, an increasing policy revision, and finite
`issued_at`/`expires_at` bounds. State must name the exact policy identity and
candidate binding. Missing, malformed, stale, unauthorized, contradictory,
replayed, or mismatched values reject new admissions.

Policy/state signatures are HMAC-SHA-256 over canonical JSON. The key is
provided by the deployment authority and is never stored in rollout files,
run records, tool arguments, prompts, or source-derived artifacts. The
repository `ReferenceFileRolloutControl` stores source-free policy, state, a
signed monotonic head, and revision-indexed transition history under
`.k-slide-config/`. History records only signed actor/cohort/stage IDs,
transition IDs, timestamps, and candidate/policy hashes. It exists for
deterministic local qualification and tests. It is not production IAM or PaaS
persistence.
Production adapters must implement `RolloutAdmissionProvider`, resolve cohort
membership from the deployment's authenticated identity authority, and use a
durable compare-and-swap revision anchor plus append-only transition history
that cannot be rolled back with the application workspace.
`KSLIDE_ROLLOUT_CONTROL_FACTORY=package.module:factory`
selects that process-level deployment adapter. The factory receives no
workspace path, source content, tool arguments, or prompt text. Its `admit`
method receives only the source-free candidate binding.

Candidate-bound environments fail closed when no deployment authority is
configured. Explicit local reference environments retain their existing
development behavior when no rollout adapter is configured. Once an adapter
is configured, its policy is enforced for either environment type.

## Stages and explicit changes

Every policy names the exact cohorts admitted at each stage. The `NAMED_COHORT`
stage contains one named cohort; `PILOT`, `CANARY`, `PHASED`, and `FULL` each
contain a strict superset of the previous stage. There are no traffic
percentages, engagement triggers, or model-selected cohorts. The deployment
authority assigns a caller to a cohort; K-Slide compares that opaque cohort
name with the state-approved set.

Signed transition commands use the current policy identity and expected state
revision. They are compare-and-swap operations with an explicit actor and
unique transition ID:

- `SET_STAGE` deliberately expands or contracts to one policy-defined stage.
- `DISABLE` immediately blocks all new admissions.
- `ROLLBACK` selects the policy's exact previously authorized candidate and
  disables new admissions while the deployment restores that runtime.
- `RESTORE_CANDIDATE` selects the policy's primary candidate and also leaves
  admissions disabled until a separate `SET_STAGE` command.

Each successful transition advances the signed monotonic head and records its
signed actor, time, and transition ID in the source-free revision history. An
old state, stale command, duplicate revision, wrong policy identity, incomplete
history, or wrong rollback target fails closed. Deployment administrators can use the transition helpers
in `k_slide.rollout`; no semantic-code change is needed to disable, expand,
contract, roll back, or restore an authorized candidate.

## In-flight runs and evidence boundary

The versioned rule `BOUND_RUNS_COMPLETE_OR_STOP_ON_IDENTITY_MISMATCH_V1`
allows an admitted run to complete while its exact bound candidate/model/config
remains available. If a deployment changes that identity before the run
finishes, existing KSA-10 environment checks stop the next resumable mutation;
K-Slide never silently moves an active run to another candidate. The
source-free `admission/ROLLOUT_ADMISSION.json` receipt records that rule,
candidate, policy identity, state revision, stage, and named cohort. Disable
and rollback affect new admissions immediately; identity-changing rollback
stops an in-flight run at the next existing safe operation boundary.

Rollout controls only gate deployment admission. They do not generate or infer
`PILOT_APPROVED`, `PRODUCTION_CERTIFIED`, champion promotion, release evidence,
security approval, governance approval, employee-study results, or any other
certification state. KSA-31 promotion/change-impact, KSA-32 governance, and
KSA-33 candidate/security identities remain under their existing authorities.
No live company setting, employee pilot, canary, release, or certification is
changed or claimed by this repository implementation.
