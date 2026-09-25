# KSA-33 candidate-bound security release evidence

KSA-33 extends the existing `security` machine-evidence type. It adds no
release state and changes no promotion behavior. The contract is
`k-slide.candidate-security-release-evidence` version `1.0`, enforced by
machine adapter `2.9` and pinned by
[`security/release-security-policy.json`](../security/release-security-policy.json).
The source-derived payload schema is
[`schemas/security-release-evidence.schema.json`](../schemas/security-release-evidence.schema.json).
The closed candidate-bound disposition input is specified in
[`schemas/vulnerability-dispositions.schema.json`](../schemas/vulnerability-dispositions.schema.json).

## Candidate binding and required proof

Each qualifying result binds the exact full Git SHA, Git tree object ID,
candidate deployment fingerprint, and canonical candidate-specification
identity. Its 64-character `candidate_tree_sha256` is a domain-separated
SHA-256 derived from that exact 40-character Git tree object ID. It
also records the workflow run and attempt, pinned runner image identity,
runtime artifact/manifest/SBOM/dependency-lock hashes, runtime image digest,
base-image digest, platform, and candidate egress-policy identity. Scanner
reports must be fresh, complete, successful, version-pinned, and bound to the
production dependency lock, candidate source tree, or exact built image as
appropriate.

The four scanner subjects are pip-audit for the production dependency
environment, Gitleaks and Semgrep for the candidate source tree, and Trivy for
the locally built runtime image. Trivy is installed from its versioned release
archive after SHA-256 verification. The runtime is built and verified through
the existing runtime-artifact builder, which checks the pinned Python base
image and supported platform. Its source-file hash is independently matched
against the exact Git archive scanned by Gitleaks and Semgrep. Trivy scans the immutable local image ID,
includes the full package inventories, and its report image ID must match the
runtime artifact identity. Gitleaks and Semgrep scan an archive of the exact
candidate Git tree, without relying on the surrounding runner workspace. The
egress proof reuses the candidate's existing default-deny policy and rejects
the reference adapter.

Security control results reuse the accepted KSA-15 AccessKey non-leakage,
KSA-17 run-scoped authorization/tenant-isolation, KSA-18 default-deny egress,
KSA-21 adversarial-security, and KSA-32 release-governance test suites. Their
test-source hashes, counts, workflow run, and attempt are bound into the
result. The KSA-33 adversarial tests cover candidate replay, stale/missing/
failed/malformed scanner results, wrong runtime or image identity, secret
leakage, policy mismatch, cross-run results, and vulnerability-disposition
bypass.

Every dependency or image vulnerability must have one explicit disposition
record. The finding identity, allowed disposition/reason, supporting evidence
hash, named policy owner, expiry, and candidate SHA/tree/deployment fingerprint
are checked as a complete one-to-one set. Accepted-risk exceptions are limited
to LOW or MEDIUM severity and expire within the policy window. Omitted,
duplicated, stale, unrelated, or replayed dispositions fail closed.

Raw scanner reports and logs stay in runner-temporary storage. Only minimized
projections, hashes, bounded counts, control results, and policy/configuration
identities are included in the durable evidence artifact. Gitleaks, Semgrep,
and Trivy report paths, snippets, descriptions, secret values, and raw payloads
are discarded during projection. Source-document content and AccessKey values
are never written to durable security evidence.

## Qualification boundary

The workflow can create candidate-bound repository evidence when run against a
complete candidate and its authorized runtime inputs. The local Fabric run
does not have a Docker daemon, so it cannot produce real image-scan or pinned
runtime execution results. Repository tests exercise the derivation contract
with synthetic scanner/control fixtures; those fixtures are not scanner
certification. Live company IAM, network egress, and deployed runtime identity
remain `UNQUALIFIED`. This work does not claim live company approval, target
Gemma certification, release, pilot/canary, `BUILD COMPLETE`, or production
certification.
