# ADR 0045 — Candidate-bound rollout controls

## Status

Implemented as the KSA-34 repository contract. The reference filesystem
adapter is a deterministic test adapter; live deployment control-plane,
identity, and persistence qualification remain external.

## Decision

The shared engine admission boundary loads deployment-owned rollout policy and
state before inspecting input paths or source bytes. Both the CLI and OpenCode
host adapter call the same `prepare_run` boundary. A process-configured
`RolloutAdmissionProvider` resolves the authenticated caller's named cohort
from the deployment identity authority. No host-specific rollout semantics,
prompt inputs, or arbitrary tool arguments are added.

Policy and state bind the KSA-10 source revision, KSA-33 deployment fingerprint,
and full run-environment identity hash. Their versioned canonical identity,
HMAC authorization, expiry, exact candidate match, signed state revision, and
monotonic head are checked on every new admission. Cohorts are named explicitly
at each closed rollout stage. Operators use signed expected-revision
transitions to set a stage, disable admission, select the previously authorized
candidate for rollback, or restore the primary candidate.

The in-flight rule is `BOUND_RUNS_COMPLETE_OR_STOP_ON_IDENTITY_MISMATCH_V1`:
existing runs may finish only while their stored candidate/model/config
identity remains available. Existing environment compatibility checks stop a
resumable operation if that identity changes. New admissions stop immediately
after disable or rollback.

Durable admission receipts contain only candidate/config hashes, policy and
state identities, named stage/cohort, and a closed decision code. This control
does not participate in release derivation. KSA-31 champion/change-impact,
KSA-32 governance, KSA-33 security, and all evidence-derived certification
states remain unchanged.

## Consequences

- Missing, malformed, stale, unauthorized, contradictory, replayed, or
  candidate-mismatched rollout data blocks new managed admissions.
- Expansion and contraction require explicit, auditable signed transitions;
  traffic and engagement cannot advance the stage.
- The reference file adapter proves the deterministic state-machine contract.
  Production adapters must keep the revision anchor in deployment-owned
  persistence that cannot be rolled back with the application workspace.
- Existing local reference-mode runs retain behavior when no rollout provider
  is configured.
- No live PaaS or feature flag, employee pilot/canary, release, or certification
  is changed or claimed.
