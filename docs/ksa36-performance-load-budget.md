# KSA-36 performance, load, and resource budgets

## Product path and owners

| Surface or concern | Current owner | Qualification boundary |
|---|---|---|
| CLI intake | `k_slide.cli.main` → `prepare_run` → `security.validate_input` / `host_adapter.validate_host_inputs` | Shared engine admission owner |
| OpenCode `/k-slide` | `.opencode/plugin/k-slide-host.ts` → `.opencode/tools/kslide.ts` → `k_slide.cli` | Shared CLI/core path; actual model calls remain inside OpenCode |
| Cloud VS Code | Documented host adapter contract calling the shared `k-slide` CLI operations | The external host adapter is not included in this repository |
| Normalization and extraction | `normalization.normalize_run` → `extraction.extract_run` | The local reference pipeline measured by the harness |
| Run state and work queue | `state.RunState`, `queue.WorkQueue`, `execution.WorkspaceRunStore` | Durable per-run state and work-unit ownership |
| Model/provider | OpenCode's pinned K-Slide agent and provider route; `k_slide.model` builds evidence packets | Python has no provider invocation or provider usage callback |
| Storage | `StorageLayout`, `StorageArtifact`, `storage_path`, and the run-store adapters | Existing storage-plane and run-store owners |
| Durable PaaS admission | `PaaSController` → `ScopedPaaSJobService`; reference implementation is `ReferencePaaSJobService` | Reference worker advances checkpoints only; company PaaS and slide engine are external |

The harness invokes `k_slide.cli.main prepare` for each shared-core topology.
That command runs the same `prepare_run`, `normalize_run`, and `extract_run`
owners and emits the normal source-free CLI telemetry when configured. It
measures that supported preparation operation through extraction; it does not
synthesize translations. Model invocation, returned patch, deterministic
verification, and finalization are explicitly marked `NOT_MEASURED`. The PaaS
result measures scoped controller admission only; it does not use
`ReferenceWorkerEngine` as a slide processor.

## Budget contract

`ResourceBudget` is the only resource-limit contract. Its versioned object is
stored as `resource_budget` in the managed `production-profile.json` and is
snapshotted with its SHA-256 into each run manifest. Existing admitted runs
continue to use their snapshot after a profile reload. `ResourceBudget.reference()`
provides deterministic test/reference values and is marked
`reference_non_production`.

Production candidate completeness and production readiness require an explicit
`production` budget; pre-contract legacy runs can use the reference ceiling
only in reference environments.

The contract covers per-file and total input bytes, input count, PDF pages,
PPTX slides, total work units, pixels per image, aggregate decoded pixels,
normalized bytes, evidence media per work unit, conservative model input and
output token estimates, total per-run model token estimates, per-scope active
and queued runs, and per-run concurrent work units. Duration-bearing media is
currently unsupported and must be explicitly `null`. Existing technical
security ceilings remain upper bounds; they are not company budget values.

The CLI and OpenCode adapters reach the same Python input validator. OpenCode
also checks the centrally supplied profile's per-file ceiling before decoding
data URL attachments, then carries a typed rejection into core admission. The
translation evidence packet reserves a bounded input estimate before it is
returned, and K-Slide rejects an over-budget TranslationPatch before storage.
Those token estimates use UTF-8 byte lengths, a fixed 512-byte host-response
metadata margin, and the configured image reserve; they are not provider
tokenizer usage. Production readiness therefore fails
until the host/provider exposes actual token accounting and an enforceable
provider output cap. Company PaaS readiness also remains blocked until its
admission adapter binds the same contract.

The existing scoped durable queue enforces its configured queue depth and the
one-active-run-per-scope rule. The workspace-local CLI, OpenCode, and Cloud
VS Code shared-CLI paths have no queue owner, so shared intake uses the run
state and admission-control lock to return typed `KSLIDE_CAPACITY_LIMIT`
results when it cannot admit another active run. It does not queue work.
Static screenshot/PDF/PPTX inputs have no duration budget; animated images are
rejected rather than reduced to a frame, and media count is enforced for the
exact required context image and crops without dropping any crop.

## Measurement artifact

Run from a clean candidate worktree after the candidate commit:

```sh
PYTHONPATH=src:. python -m evals.performance_load \
  --root . \
  --output /tmp/k-slide-performance-load.json \
  --warmups 1 \
  --repetitions 2
```

The harness creates a screenshot, 16- and 55-slide PDF presentations, and
16- and 55-slide PPTX presentations. It bounds warmups to one and repetitions
to five, deletes all synthetic inputs and run artifacts, and writes only
source-free timing and shape data to the report. Each result binds the exact
candidate commit/tree, branch, changed paths, Python/runtime identity, end-to-
end timing, p50/p95, concurrency, and capacity fields. PPTX results are marked
`NOT_MEASURED` when the product's Office converter is absent. These timings do
not establish a production SLO. The approved Gemma endpoint, production
OpenCode provider, live Cloud VS Code adapter, and company PaaS are not replaced
by alternate providers or runtimes when unavailable.
