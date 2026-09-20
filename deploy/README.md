# Managed production profile

## KSA-07 runtime artifact

The canonical heavy/runtime subject is built only through
`scripts/build_runtime_artifact.py` and `deploy/runtime/Dockerfile`. It is a
digest-qualified `linux/amd64` image with an exact Debian snapshot package
manifest, the committed or approved exact Python lock/inventory, an installed
K-Slide wheel, and a portable verified OCR asset tree. The build emits a
source-free runtime manifest and CycloneDX SBOM identity and independently
records a local Docker image ID or a real registry digest.

Use the same image for the product command (`k-slide`) and heavy verification
(`python -m evals.heavy.doctor`). The build refuses to call an unverified
dynamic OCR prefetch a candidate artifact; the explicit development prefetch
mode is marked `DEVELOPMENT_ONLY`.

The source contract also installs the separately executable `k-slide-worker`
path. A managed deployment must bind that worker to its approved PaaS job
service and the same pinned runtime; the repository's deterministic reference
adapter does not qualify live company transport or production persistence.
The worker accepts an approved `module:factory` engine binding so the managed
path can invoke the existing K-Slide engine/checkpoint/evidence boundary.

Certification inputs live in the public-safe `evals/production-candidate.yaml`
or an ignored `.k-slide-config/production-candidate.json`. Certification-quality
commands accept that object with `--candidate-profile`; its deployment factors
exclude release outputs and ambient scanner/runner runtime. The release command
materializes `.k-slide-config/production-profile.json` only after deriving the
requested state, so the source candidate does not need to claim certification.

Copy `production-profile.example.json` to the deployment’s ignored
`.k-slide-config/production-profile.json` and replace every `UNSET` value only
after the corresponding certification evidence exists. The profile is checked
by `k-slide doctor --production`; a missing profile, non-certified release
state, wrong model, missing or unresolved content/operational-metadata
retention policy, unsafe run permissions, missing offline OCR assets, or
missing heavy runtime fails closed. Retention values are centrally supplied
deployment inputs; this repository does not define a duration default.

Production requires one isolated workspace/container per user or session. Do
not share a writable `.k-slide-runs/` directory between employees.

OpenCode production starts only through the managed pre-start bootstrap. Copy
`opencode-bootstrap.example.json` into the deployment manifest, materialize a
read-only isolated `.opencode` directory containing the shipped local
`k-slide-host.ts`, its shipped access-key helper, and pinned `opencode.json`,
whose provider surface must contain exactly `enabled_providers: ["google"]`
and `provider.google.whitelist: ["gemma-4-31b-it"]`, with no
`disabled_providers` entry that includes `google`. The deployment-owned model
catalog must resolve that exact Google/Gemma model,
`GOOGLE_GENERATIVE_AI_API_KEY`, `@ai-sdk/google`, and the approved
Generative Language endpoint before its hash is recorded. Record exact hashes
for that config, plugin, helper, verified prebundled `rg`, and local or
verified bundled model catalog. Precreate the isolated
OpenCode XDG config/data/cache/state
directories; the global config directory must be empty and read-only, and the
managed data directory must not contain OpenCode or MCP auth state. Launch with
`python -m k_slide.opencode_bootstrap --manifest .k-slide-config/opencode-bootstrap.json -- opencode web`
(or the repository `scripts/launch_opencode_k_slide.py` seam). The launcher sets
the OpenCode egress controls and puts the verified `rg` directory first in
`PATH`, starts OpenCode in a managed process group, forwards termination and
control signals, and waits for and reaps the child with bounded escalation when
needed. It rejects `OPENCODE_MODELS_URL` and ambient config/plugin overrides,
and requires the provider credential through its existing environment seam. A
doctor result after startup is evidence only; it does not replace this launcher
contract.

For durable heavy jobs, the deployment adapter must supply an authorized
user/workspace scope to the KSA-09 `ScopedPaaSJobService` boundary. Its
company persistence must provide the equivalent per-scope control, FIFO
admission, locking, and run/result/evidence reference isolation. The local
scoped `ReferencePaaSJobService` is a deterministic qualification backend,
not live company-storage qualification; job/run IDs are never authorization.

The certified profile must bind `subject_git_sha`,
`deployment_fingerprint`, `certification_fingerprint`,
`release_manifest`, and `release_manifest_sha256` to an evidence-derived
release manifest. These values are release outputs, not hand-edited readiness
flags. Certifying evidence and that manifest must remain under the release
root with relative paths so a deployed doctor can re-open and re-derive every
machine envelope. Runtime-enforced limits are not stored as decorative profile fields;
measured SLOs remain in `production-slo.yaml` until the deployment wires them
to a managed timeout policy.
