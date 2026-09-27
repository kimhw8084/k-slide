# KSA-37 candidate revocation and material drift

KSA-37 adds a source-free, candidate-bound revocation ledger in
`src/k_slide/candidate_revocation.py`. Its strict durable contract is
`schemas/candidate-revocation.schema.json` version 1.0. Events carry only the
exact KSA-34 candidate binding, actor and authority references, event and
revision identities, a timestamp, one closed reason category, and a typed
evidence identity. There is no free-form diagnostic or source-content field.

The candidate binding reuses `RolloutCandidateBinding`:

- `subject_git_sha`
- `deployment_fingerprint`
- `run_environment_identity_sha256`

The KSA-34 signed rollout policy and state remain version 1.0, preserving
their existing identities. The admission receipt has its own version 1.1 and
includes the exact revocation state identity, revision, and status.

The signed local reference adapter stores immutable event history, a revisioned
state, and a signed head under `.k-slide-config/candidate-revocations/`. It is
for tests and local qualification only. Production deployments must provide
`KSLIDE_CANDIDATE_REVOCATION_CONTROL_FACTORY` implementing the typed `status`
and `apply_event` contract. Runtime rollout adapters configured through
`KSLIDE_ROLLOUT_CONTROL_FACTORY` are wrapped with this provider; missing,
unreadable, stale, mismatched, or invalid status blocks admission.

The reference event path records revocation before applying the existing
signed KSA-34 `ROLLBACK` or `DISABLE` transition. It selects only the rollback
candidate already named in the signed rollout policy, and it never changes an
in-flight run's candidate or stored admission. Signed stage changes to a
revoked candidate are rejected. Requalification is a separate authorized
`RECOVER` event with a `REQUALIFICATION_ATTESTATION` identity. When the
candidate was rolled back, recovery uses `RESTORE_CANDIDATE` into `DISABLED`;
it does not re-enable any cohort.

Production readiness checks require the profile's exact
`run_environment_identity_sha256`. Release requests for `PILOT_APPROVED` or
`PRODUCTION_CERTIFIED` require
`--candidate-run-environment-identity-sha256` plus a healthy typed provider.
When the live provider or exact environment identity is unavailable, the
release path blocks promotion. The repository reference provider does not
qualify company control-plane enforcement.

Revocation status is a current admission/readiness condition. It is not added
to the deployment fingerprint or used to rewrite prior certification or
evidence.
