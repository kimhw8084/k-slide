# K-Slide Implementation Status

## Current boundary

**K-Slide 0.3.5 — Phase 3.5 execution-isolation and heavy-runtime-proof boundary.**

The repository now has a coherent, tested boundary from validated immutable input through normalized document units, native evidence, configured OCR routing, deterministic crops, bounded multimodal packets, deterministic reports, and synthetic evaluation artifacts. It remains `DEVELOPMENT`: the local runtime is `ollama/qwen3:14b`, not the target `google/gemma-4-31b-it`, and no production translation gate has been certified.

The current production-certification hardening pass also adds explicit noninteractive permissions, centralized diagnostic redaction, restrictive artifact permissions, fail-closed retention cleanup, a source-free admin support bundle, a production profile/doctor gate, provisional production constraints/SLO metadata, and offline release-manifest/SBOM generation. These controls are implemented and unit-tested; they are not evidence that their external runtime, model, internal-data, human-study, or pilot gates have passed.

The certification-closure pass adds a single evidence envelope and fingerprint
implementation shared by release tooling and the production doctor. Release
states are derived from validated evidence bound to an explicit subject Git SHA
and deployment fingerprint; a requested state cannot promote itself. Machine
evidence must also hash-match its underlying result file. Production profiles
bind to the release manifest and both fingerprints, use the authoritative
ModelPolicy, and verify OCR asset content hashes. The lightweight SBOM remains
explicitly development-only; certified release generation requires a real
CycloneDX environment SBOM from the approved release environment.

The result-derived evidence closure adds type-specific adapters for runtime,
heavy, model, security, reliability, and governance results. Machine evidence
records unique source roles and hashes; loading it re-parses those source
files and compares a deterministic derived payload. Envelope timestamps and
packaging paths do not affect evidence identity; adapter version and
source-result hashes do. A machine PASS envelope cannot be authored through
the generic attestation writer.

## Implemented and tested

- Engine-owned, versioned `EvidenceIR` with deterministic SHA-256 revisions.
- Strict model-owned `TranslationPatch`; source geometry, native text, OCR candidates, numeric facts, required IDs, and coverage baselines cannot be supplied by the model.
- Engine-controlled `EvidenceIR + TranslationPatch → SlideIR` merge with explicit provenance.
- Evidence revision, work-unit identity, table/cell identity, required-region coverage, and source-field injection checks.
- Persisted multi-work-unit queue with sequential scheduling, repair states, optimistic revisions, run locking, and resumable `NEEDS_REVIEW`.
- Finalization that re-runs verification against current artifacts before creating `RUN_COMPLETE.md`.
- Central completion policy in `src/k_slide/policy.py`, used by manifests, verification, and finalization.
- Typed OpenCode `kslide_submit` payload schema; no model-facing JSON-in-a-string contract.
- JSON schema, Python parser, and OpenCode TypeScript TranslationPatch parity for rich semantic fields, including Hangul retention and source-bound visual relations.
- Narrow OpenCode permissions: normal K-Slide execution has no bash, edit, write, subagent, webfetch, or websearch access.
- Image normalization with decode, EXIF orientation, dimension, pixel-count, and decompression-safety limits.
- PDF page rendering and native text-span extraction through PyMuPDF.
- PPTX native shape/table extraction through python-pptx and capability-gated headless LibreOffice rendering.
- Deterministic render-region crops, model-ready non-generative resizing, numeric evidence extraction, and native/OCR evidence-fusion states.
- OCR provider protocol with `none` and optional PaddleOCR 3.x adapter.
- Managed OCR provider policy/factory wired into normal `/k-slide` extraction; requested/effective provider and version persist in EvidenceIR/run metrics. Explicit `paddle` fails closed when unavailable.
- Closed commitment/speech/claim/uncertainty enums, engine-owned numeric linkage, Korean scale and `%p` semantic checks, residual-Hangul and locked-term verification foundations.
- Deterministic final report, executive brief, and unresolved-item renderers generated from SlideIR.
- Explicit whole-unit context-image/risk-crop media plan and bounded model prompt contract.
- 100 fixed development/validation/held-out specifications with actual raster/PPTX tables, charts, process diagrams, screenshots, and compound executive compositions.
- Independent PNG/JPEG/WebP/PDF/PPTX artifact cases and qualified engine scores for normalization, EvidenceIR coverage, table/numeric/visual/media invariants.
- Verified Korean-font discovery that fails corpus generation instead of falling back to tofu/default glyphs.
- OpenCode protocol runner using the real `opencode run --format json` command surface; non-Gemma runs are protocol smoke only.
- Structured OpenCode event normalization that does not infer tool use from prompt/log substrings; actual forbidden-tool and media-read assertions, timeout diagnostics, and a complete-run success contract.
- Corpus-level `ModelEvaluationRunner` with split/category/format/repetition controls, persisted experiment manifests, TranslationPatch/SlideIR loading, source-local semantic scoring, and non-authoritative gating for non-target models.
- Stratified deterministic split manifest generation, held-out governance, five linked multi-slide deck scenarios, and stricter champion/challenger protected-category rules.
- Certification state semantics separate measurement from quality outcome (`NOT_MEASURED`, `CAPABILITY_BLOCKED`, `PROTOCOL_SMOKE_ONLY`, `MEASURED`, `CERTIFICATION_FAIL`, and candidate/certified states); `champion.json` remains intentionally `UNSET`.
- Approved-model policy requires exact requested/effective identity or an explicitly configured private alias; certification manifests persist corpus, held-out, configuration, and certification fingerprints.
- Per-work-unit media traces bind each `kslide_evidence`/read/`kslide_submit` sequence to its own work-unit ID, including context-image and crop recall.
- Per-attempt media history retains initial and repair attempts without overwriting prior compliance evidence.
- Source-bound visual gold binding rejects ambiguous process/chart role mappings instead of scoring invented model IDs.
- OpenCode diagnostic ladder separates provider, plain-run, explicit-model, agent, and real `/k-slide` failures with process-group timeout cleanup.
- OpenCode diagnostics isolate clean provider workspaces from separately installed K-Slide workspaces, persist per-level stdout/stderr/events, and classify the first failed layer.
- Shared process-group termination uses bounded SIGTERM/SIGKILL cleanup and reports whether timed-out evaluation processes were reaped.
- OCR policy configuration fails closed on malformed/unknown files; `auto` fallback preserves its original capability error and explicit certification policies remain reproducible.
- PaddleOCR configuration supports PP-OCRv5 Korean recognition, local `paddlex_config`/model paths, build-time asset prefetch, and an asset manifest for networkless managed images.
- Heavy doctor distinguishes local capability `BLOCKED` from required-image `FAIL`; the manual heavy workflow mounts host output, enforces `--network none`, and uploads diagnostics/evaluation results.
- Deck protocol PASS requires complete expected-unit artifacts, per-unit media compliance, K-Slide completion, and a deck consistency score.
- Model result collection loads every persisted work-unit TranslationPatch/EvidenceIR/SlideIR triple, aggregates unit/deck metrics, and computes repeated-run critical frequency, review rate, and category/format summaries.
- Source-local table-header, chart-trend, process-edge, modality, terminology, Hangul-retention, unresolved-usefulness, and executive-claim semantic gates are covered by automated tests.
- Semantic TranslationPatch scorers, private gold-set protocol, and zero-Korean comprehension-study protocol.
- Reproducible heavyweight Docker definition/self-test for LibreOffice, PaddleOCR 3.x, PyMuPDF, python-pptx, Pillow, and Korean fonts.
- Black-box CLI, installer regression, trust-model, queue/resume, concurrency, stale-evidence, stale-finalization, and normalization fixture tests.
- GitHub Actions workflow for Python 3.11/3.12, unit tests, compile checks, CLI/installer checks, and doctor.
- Explicit production permission denials for interactive/headless-dangerous operations, including question, external-directory, and doom-loop controls.
- Centralized redaction for credentials, home paths, source-content fields, and support/diagnostic output.
- Restrictive run/artifact permissions plus an admin-only retention cleanup command with symlink and outside-root refusal.
- Sanitized `support-bundle` command that excludes source snapshots, renders, crops, evidence, translations, reports, and raw transcripts.
- Fail-closed production profile checks for target model identity, OCR assets/provider initialization, OpenCode, retention, tenancy, egress, permissions, and certification fingerprint.
- Provisional pinned production constraints, SLO configuration, deployment profile template, and offline release manifest/SBOM generator.
- Evidence-bound release states, subject-SHA/deployment/certification fingerprints, validated machine/human evidence envelopes, champion binding, and stale-certification detection.
- Production doctor verification of release-manifest hashes, evidence hashes, authoritative model policy, exact dependency identities, and OCR asset content hashes.
- Pinned public security workflow for dependency, secret, and static scans; CODEOWNERS for production-sensitive paths.
- Production SBOM generation path using `cyclonedx-py`; the existing package inventory remains labeled as non-certified development metadata.
- Result-derived machine evidence adapters with source-role validation, payload re-derivation, deterministic evidence identities, and runtime/heavy/model/security/reliability/governance coverage.
- Spoof/tamper regressions covering contradictory metrics, result mutation, envelope mutation, critical model results, scanner findings, and non-authoritative governance input.
- Reliability adapters require explicit substantive proof for timeout recovery,
  resume, concurrency, 50-slide execution, and SLO compliance; missing proof
  cannot default to PASS.
- High-risk adapters evaluate every declared and observed scenario/format group
  under the repository protected-category policy rather than selecting a best
  format, and model validation/held-out adapters enforce locked terminology
  recall `>=0.995` plus zero unexpected unresolved rate.
- Security workflow scanner exit codes are captured in per-tool files and
  assembled structurally; missing scanner output is not synthesized as clean.
- Deployment/behavior identity uses one explicit factor allowlist shared by
  model evaluation, release, engine diagnostics, and production verification;
  experiment-plan identity separately records split, membership, formats,
  repetitions, filters, limits, and evaluation settings.
- Model validation and held-out adapters require the complete frozen
  scenario × format × repeat matrix. High-risk evidence uses the canonical
  `scenario_id + format` group key, exact declared groups, repeat numbers, and
  protected-category coverage; no best-format or partial-run selection is
  possible.

## Verification performed locally

```text
Base unit/integration suite: PASS (`python -m unittest discover -s tests -q`; latest local execution: 148 tests passed, 2 optional dependency skips)
Dependency-backed unit/integration suite: PASS (`/tmp/k-slide-phase32-venv/bin/python -m unittest discover -s tests -q`; latest local execution: 148 tests passed, no optional dependency skips)
Dependency-backed compile/import checks: PASS
TranslationPatch JSON schema parse: PASS
Stratified split manifest: PASS (100 specs; 60/20/20; protected categories in held-out)
Corpus fingerprint: `698b471fa9dffe9f79af40a61c3546d6455889b90063a02bc2e270b90402f7ac`
Held-out fingerprint: `c2dee1ba1b03fead1a6641cfa8c7ceea27eb51b0ed80c0879c07bc3ee29bcc4e`
Corpus/held-out fingerprint governance tests: PASS
Full lightweight engine suite: EXECUTED (500 cases; 100 each PNG/JPEG/WebP/PDF/PPTX, dependency-backed environment)
Artifact generation: 500/500 PASS
PNG/JPEG/WebP/PDF normalization + EvidenceIR: 320/400 PASS; 80 CAPABILITY_BLOCKED because image-only financial-table cases require OCR when explicitly pinned to `none`
PPTX visual normalization: 100 CAPABILITY_BLOCKED (LibreOffice unavailable)
Lightweight engine algorithmic failures: 0; all 180 findings were capability blocks in this run
OpenCode 1.3.9 isolated diagnostic ladder: pure and normal clean OpenCode TIMEOUT with zero structured events; explicit model TIMEOUT; Levels 3/4 intentionally not reached after the provider-level failure
Gemma quality evaluation: CAPABILITY_BLOCKED — target endpoint unavailable
```

Test totals are not a standing contract; the commands above and CI are authoritative as the suite evolves.

Runtime snapshot: OpenCode `1.3.9`; configured model `ollama/qwen3:14b`; model compatibility `different_model_warning`.

The dependency-backed temporary environment exercised Pillow, PyMuPDF, python-pptx, and verified Korean-font support. LibreOffice, PaddlePaddle, PaddleOCR, and the approved Gemma endpoint were unavailable locally. The OpenCode runner retained timeout diagnostics and did not treat the zero-event timeout as a protocol pass.

## Certification capability matrix

| Capability | Status | Evidence |
| --- | --- | --- |
| Unit/integration tests | PASS | Full unittest command passes; optional document/OCR tests are dependency-gated in the base interpreter |
| Artifact generation | PASS | 500/500 generated across five formats |
| Lightweight engine | PASS with capability-separated findings | 500 cases executed; 320 raster/PDF cases completed, 80 raster/PDF financial OCR cases and 100 PPTX cases capability-blocked |
| LibreOffice real roundtrip | BLOCKED | `soffice` unavailable; Docker daemon unavailable |
| PaddleOCR real Korean roundtrip | BLOCKED | PaddlePaddle/PaddleOCR unavailable |
| OpenCode protocol | BLOCKED | OpenCode 1.3.9 pure and normal clean Qwen smoke both timed out before events |
| Gemma development | BLOCKED | `google/gemma-4-31b-it` unavailable in effective runtime |
| Gemma validation | NOT RUN | Target endpoint unavailable |
| Held-out quality evaluation | NOT RUN | Champion remains `UNSET` |
| Internal bilingual evaluation | NOT RUN | Private dataset not present |
| Zero-Korean comprehension study | NOT RUN | Study has protocol only |
| Production certification | DEVELOPMENT | No target-model or human gates passed |
| Production doctor/profile | BLOCKED as expected | No certified profile; target model, Paddle/LibreOffice, retention attestation, and fingerprint are not proven locally |
| Support bundle/redaction/retention controls | PASS (unit-tested) | Metadata-only support bundle and fail-closed cleanup are implemented; deployment enforcement remains required |
| Release manifest/SBOM tooling | PASS (offline smoke) | Generates DEVELOPMENT metadata with deployment fingerprint; certified release state is evidence-derived and blocked without complete evidence; production SBOM generator requires `cyclonedx-py` |

## Certification closure verification

The latest local closure run executed:

```text
PYTHONPATH=src:. python -m unittest discover -s tests -q
148 tests passed, 2 optional dependency skips
148 tests passed, no optional dependency skips
python -m compileall -q src evals tests: PASS
git diff --check: PASS
DEVELOPMENT release generation: PASS
PRODUCTION_CERTIFIED request with incomplete evidence: BLOCKED (expected)
```

No runtime/heavy/Gemma/private/human/pilot evidence was fabricated or
materialized by these tests.

## Phase 3.5 execution matrix

| Capability | State | Evidence |
| --- | --- | --- |
| TranslationPatch JSON/Python/OpenCode parity | PASS | Rich fixture validated by Python and JSON schema when available; TypeScript field parity assertions pass |
| TranslationPatch optional/null parity | PASS | Optional fields are omitted; JSON, Python, and TypeScript reject explicit nulls |
| OCR production routing | PASS | `none` and explicit unavailable `paddle` paths exercised; metadata records requested/effective provider |
| OCR malformed-config handling | PASS | Malformed JSON/YAML and unknown providers return `KSLIDE_CONFIG_INVALID`; auto fallback retains cause |
| Raster/PDF engine with pinned `none` OCR | PASS | Dependency-backed one-case engine run completed |
| PPTX heavy roundtrip | BLOCKED | LibreOffice unavailable locally; Docker daemon unavailable |
| Paddle real Korean OCR | BLOCKED | PaddlePaddle/PaddleOCR unavailable locally |
| Heavy engine subset with `paddle` | BLOCKED | Correctly classified as `CAPABILITY_BLOCK` locally |
| Timeout process cleanup | PASS | Process-group helper tests SIGTERM/SIGKILL fallback and reaping |
| Host-persisted heavy output | PASS (workflow) | Runner-temp mount and `if: always()` artifact upload are tested statically |
| OpenCode Level 0 provider | BLOCKED | Ollama executable unavailable |
| OpenCode clean workspace isolation | PASS (harness) | Clean checks precede project installation; project workspace is separate |
| OpenCode Level 1 pure/normal runs | BLOCKED | OpenCode 1.3.9 timed out with zero structured events in both modes |
| OpenCode Level 2 explicit model | BLOCKED | Qwen run timed out with zero structured events |
| OpenCode Level 3 k-slide agent | NOT REACHED | Clean provider Level 1 failed first; installation was intentionally skipped |
| OpenCode Level 4 `/k-slide` | NOT REACHED | Clean provider Level 1 failed first; no K-Slide process was started |
| Gemma target | BLOCKED | `google/gemma-4-31b-it` unavailable; effective runtime is Qwen |
| 3-slide protocol deck | BLOCKED | Real OpenCode path attempted; provider timed out before run creation |
| 5-slide protocol deck | BLOCKED | Real OpenCode path attempted; provider timed out before run creation |
| Champion | UNSET | No authoritative target-Gemma validation result |
| Release | DEVELOPMENT | `GEMMA_EVAL_READY` not reached |

## Known limitations

- Full target Gemma translation, repair quality, and zero-Korean comprehension evaluation are not yet measured.
- The base local interpreter does not have all optional document/OCR runtimes; doctor reports proven capabilities rather than pretending they pass.
- LibreOffice-rendered PPTX and PaddleOCR 3 integration are not exercised in this workspace; `evals/heavy/Dockerfile` is reproducible but its build could not start because the local Docker daemon is unavailable. Use it and `python -m evals.heavy.doctor` in an approved environment.
- The model-facing OpenCode flow is contract-ready, but the isolated clean-workspace Qwen protocol smoke timed out before emitting structured events. Levels 3/4 were intentionally not run after that provider-level failure. No Gemma accuracy or comprehension result is reported; this remains a provider/runtime blocker to resolve in an environment where the configured model responds.
- Numeric/modality/terminology verifiers are deterministic foundations, not a substitute for bilingual gold review.
- Current-message attachment materialization is not advertised because OpenCode 1.3.9 does not expose a proven safe bridge in this repository.
- The local OpenCode server `/doc` surface exposed only global routes during inspection; the runner therefore uses the supported CLI JSON-event path for protocol execution and records structured server API work as a separate capability.
- Locally generated visual corpus cases are available with the verified macOS system Korean font. LibreOffice and PaddleOCR are still unavailable locally, so PPTX visual normalization and real OCR remain heavy-tier capability blocks.
- The PaddleOCR adapter follows the current 3.x API shape but is not installed or benchmarked in this workspace.
- Production mode is intentionally fail-closed until an approved profile contains a real certification fingerprint, approved model-data attestation, local OCR assets, and proven heavy/runtime capabilities.
- The support-bundle path is source-free by construction, but administrative access control for invoking it must be supplied by the managed deployment.

## Next phase

1. Run the heavy container/doctor with a working Docker daemon or approved heavy runner; resolve any real OCR/layout failures before model scoring.
2. Resolve the provider-level OpenCode timeout and prove a complete one-slide run.
3. Connect the approved Gemma 4 31B-it endpoint through the bounded OpenCode workflow.
4. Run development, validation, ablation, repeated high-risk, and finally frozen held-out evaluations.
5. Complete private bilingual, zero-Korean comprehension, security/reliability, governance, and canary evidence.
6. Promote a configuration only when hard critical-error gates and protected-category regression rules pass; do not create 1.0.0 before every required gate is evidenced.

## Architecture decisions

- [ADR 0001 — Single visible agent](docs/adr/0001-single-visible-agent.md)
- [ADR 0002 — Versioned SlideIR](docs/adr/0002-slide-ir.md)
- [ADR 0003 — Deterministic completion](docs/adr/0003-deterministic-completion.md)
- [ADR 0004 — Local-first privacy](docs/adr/0004-local-first-privacy.md)
- [ADR 0005 — OpenCode compatibility](docs/adr/0005-opencode-compatibility.md)
- [ADR 0006 — Engine-owned evidence](docs/adr/0006-engine-owned-evidence.md)
- [ADR 0007 — Multi-work-unit state](docs/adr/0007-multi-work-unit-state.md)
- [ADR 0008 — Evidence revisions](docs/adr/0008-evidence-revision.md)
- [ADR 0009 — Document normalization](docs/adr/0009-document-normalization.md)
- [ADR 0010 — OCR provider abstraction](docs/adr/0010-ocr-provider-abstraction.md)
- [ADR 0011 — Globally unique work units](docs/adr/0011-globally-unique-work-units.md)
- [ADR 0012 — Deterministic renderers](docs/adr/0012-deterministic-renderers.md)
- [ADR 0013 — Model media plan](docs/adr/0013-model-media-plan.md)
- [ADR 0014 — Verification scoping](docs/adr/0014-verification-scoping.md)
- [ADR 0015 — Evaluation corpus](docs/adr/0015-evaluation-corpus.md)
- [ADR 0016 — Modality enums](docs/adr/0016-modality-enums.md)
- [ADR 0017 — Bounded repair](docs/adr/0017-bounded-repair.md)
- [ADR 0018 — Realistic visual corpus](docs/adr/0018-realistic-visual-corpus.md)
- [ADR 0019 — OpenCode evaluation surface](docs/adr/0019-opencode-evaluation-surface.md)
- [ADR 0020 — Stratified evaluation splits](docs/adr/0020-stratified-evaluation-splits.md)
- [ADR 0021 — Structured OpenCode events](docs/adr/0021-structured-opencode-events.md)
- [ADR 0022 — Source-local semantic scoring](docs/adr/0022-source-local-semantic-scoring.md)
- [ADR 0023 — Heavy certification environment](docs/adr/0023-heavy-certification-environment.md)
- [ADR 0024 — Held-out governance](docs/adr/0024-held-out-governance.md)
- [ADR 0025 — Certification state semantics](docs/adr/0025-certification-state-semantics.md)
- [ADR 0026 — Per-work-unit media compliance](docs/adr/0026-per-work-unit-media-compliance.md)
- [ADR 0027 — Multi-unit model scoring](docs/adr/0027-multi-unit-model-scoring.md)
- [ADR 0028 — Corpus fingerprints](docs/adr/0028-corpus-fingerprints.md)
- [ADR 0029 — Approved model policy](docs/adr/0029-approved-model-policy.md)
- [ADR 0030 — Review-rate governance](docs/adr/0030-review-rate-governance.md)
- [ADR 0031 — OCR provider activation](docs/adr/0031-ocr-provider-activation.md)
- [ADR 0032 — Source-bound visual evidence](docs/adr/0032-source-bound-visual-evidence.md)
- [ADR 0033 — OpenCode diagnostic ladder](docs/adr/0033-opencode-diagnostic-ladder.md)
- [ADR 0034 — Execution isolation and heavy proof](docs/adr/0034-execution-isolation-and-heavy-proof.md)
- [ADR 0036 — Evidence-bound release state](docs/adr/0036-evidence-bound-release-state.md)
- [ADR 0037 — Result-derived machine evidence](docs/adr/0037-result-derived-machine-evidence.md)
