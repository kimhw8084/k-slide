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
- Versioned source-free execution/job and run-store contract with workspace-local and deterministic durable-profile reference adapters, monotonic checkpoint CAS, durable cancellation, bounded operational retry, restart/replay tests, and host-visible execution metadata. This is the KSA-06 implementation boundary; it is not a production PaaS worker, runtime binding, tenancy system, or production readiness claim.
- KSA-08 source contract for durable PaaS controller submission, reconnectable source-free inspection/cancellation, independent worker claims, exact pinned runtime identity binding, bounded retry, checkpoint resume, and process-boundary integration. The local `ReferencePaaSJobService`/`ReferencePaaSRunStore` and `k-slide-worker` entrypoint are deterministic qualification adapters; live company-PaaS transport, full engine resume binding, and production certification remain unproven and out of scope.
- KSA-09 user/workspace-scoped durable reference admission: deployment-supplied `AuthorizedScopeContext`, per-scope control/queue/job/run-store namespaces, one-active-heavy-run FIFO admission, independent-scope concurrency, durable scope locking and promotion, least-privilege scoped store views, source-free run/result/evidence references, and fail-closed scoped authorization. The platform-neutral `ScopedPaaSJobService` is the production adapter boundary; live company storage/job-service qualification and production certification remain external gates.
- KSA-14 process-only company authentication boundary: the exact `AccessKey` environment variable is the only credential source; its raw value is retrieved at the authenticated call edge, passed to a deployment-injected approved-service transport as a dedicated ephemeral argument, and is not inserted by K-Slide into serializable requests, model packets, execution state, environment identity, telemetry, or files. The response boundary requires JSON serializability; broad content-surface leakage remains a KSA-15 concern. Host-neutral and durable/PaaS callers share the boundary; endpoint/protocol qualification and live company authentication remain external gates.
- KSA-16 authoritative classification admission: trusted host/platform classification travels independently with every host-neutral input, defaults only missing labels to `company_confidential`, and is evaluated exactly against a deployment-controlled route/data-use policy before source validation, immutable snapshots, normalization, rendering, crops, or EvidenceIR. Denied, unknown, malformed, unresolved, route-mismatched, or policy-drifted inputs fail as source-free operational admission failures; trusted adapter labels are preserved, while OpenCode v1.3.9 `FilePart` has no supported authoritative classification channel and therefore receives the documented `company_confidential` default. OpenCode tool/model values cannot override host metadata; a stronger OpenCode label requires a future supported trusted metadata/resolver integration outside model, tool, and user control. Route and exact policy identities bind candidate fingerprints and resumable run environments. The reference policy is a deterministic test adapter only; company policy approval, model-data attestation, target-Gemma qualification, and production certification remain external gates. See [ADR 0044](docs/adr/0044-classification-admission.md).
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
- Canonical KSA-07 runtime artifact contract with a digest-qualified Python base, Debian snapshot package manifest, exact production dependency lock/inventory, non-root product entrypoint, source-free runtime manifest, OS-inclusive CycloneDX SBOM, OCR asset identity, and an independent build/verify script. The image is explicitly `CANDIDATE` only with a verified certifying OCR bundle; development-prefetched OCR remains `DEVELOPMENT_ONLY`.
- Black-box CLI, installer regression, trust-model, queue/resume, concurrency, stale-evidence, stale-finalization, and normalization fixture tests.
- GitHub Actions workflow for Python 3.11/3.12, unit tests, compile checks, CLI/installer checks, and doctor.
- Explicit production permission denials for interactive/headless-dangerous operations, including question, external-directory, and doom-loop controls.
- Centralized redaction for credentials, home paths, source-content fields, and support/diagnostic output.
- Restrictive run/artifact permissions plus an admin-only retention cleanup command with symlink and outside-root refusal.
- Sanitized `support-bundle` command that excludes source snapshots, renders, crops, evidence, translations, reports, and raw transcripts.
- Separate KSA-20 controlled content-support boundary with typed exact-run artifact selections, deployment-supplied live decision re-checks, finite expiry, durable support-content copies, source-free support-access audit, and KSA-12/KSA-13 cleanup/deletion integration. The reference authorization provider is test-only; company IAM, support-role/approval authority, and any content transfer mechanism remain external gates. The ordinary `support-bundle` CLI remains source-free.
- Fail-closed production profile checks for target model identity, OCR assets/provider initialization, OpenCode, retention, tenancy, egress, permissions, and certification fingerprint.
- Provisional pinned production constraints, SLO configuration, deployment profile template, and offline release manifest/SBOM generator.
- Evidence-bound release states, subject-SHA/deployment/certification fingerprints, validated machine/human evidence envelopes, champion binding, and stale-certification detection.
- Production doctor verification of release-manifest hashes, evidence hashes, authoritative model policy, exact dependency identities, and OCR asset content hashes.
- Pinned public security workflow for dependency, secret, and static scans; CODEOWNERS for production-sensitive paths.
- Production dependency identity is derived from an exact isolated-environment inventory; the release path emits a deterministic complete CycloneDX SBOM from that inventory, while the development package inventory remains non-certified.
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
Base unit/integration suite: PASS (`PYTHONPATH=src:. python -m unittest discover -s tests -q`; latest local execution: 239 tests passed, 2 optional dependency skips)
Dependency-backed unit/integration suite: PASS (`/tmp/k-slide-phase32-venv/bin/python -m unittest discover -s tests -q`; latest local execution: 161 tests passed, no optional dependency skips)
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

KSA-07 repository-side verification: `PYTHONPATH=src:. python -m unittest tests.test_runtime_artifact -q` PASS (6 tests); `PYTHONPATH=src:. python -m unittest discover -s tests -q` PASS (222 tests, 2 optional skips); `python -m compileall -q src evals tests` PASS; `git diff --check` PASS before final documentation edits. The canonical builder was exercised with `scripts/build_runtime_artifact.py build --allow-development-ocr-prefetch ...` against the pinned `linux/amd64` image. Docker completed the base and exact Debian package layers but the Fabric host's emulated Paddle installation produced no progress and was stopped after the capability wait window; no image/doctor/networkless pass is claimed from that attempt. A certifying OCR bundle was not available in the public worktree, so no `CANDIDATE` runtime artifact was materialized.

KSA-08 repository-side verification: `PYTHONPATH=src:. python -m unittest tests.test_chg16_paas_worker -q` PASS (9 tests); the tests exercise independent worker subprocess submission/claim, controller reconstruction, cancellation acknowledgement, interruption/restart, duplicate-marker prevention, bounded retry, semantic classification, exact runtime binding, secret/source hygiene, and recreated-store CAS/idempotency. Live company-PaaS transport, production persistence/concurrency policy, and company-runtime qualification remain explicitly unproven.

KSA-09 repository-side verification: `PYTHONPATH=src:. python -m unittest tests.test_chg16_scoped_admission -q` PASS (10 tests); the tests exercise multi-process scoped admission/claims, one-active-heavy-run FIFO overflow, independent scopes, restart recovery, record-only admission sequence recovery, terminal/NEEDS_REVIEW/cancellation promotion and explicit FIFO resume, recreated-store CAS/idempotency, wrong-scope/guessed-ID denial, and source-free isolated namespaces. Live company storage/job-service qualification remains an external gate.

KSA-14 repository-side verification: `PYTHONPATH=src:. python -m unittest tests.test_chg16_authentication_transport -q` PASS; the tests cover exact process-environment sourcing, opaque credential values, missing/empty/non-string fail-closed behavior before transport invocation, dedicated secret-argument separation, host/PaaS reuse, request destination rejection, response/error non-leakage, execution/storage/file absence, and source-free production readiness reporting. This is not live company endpoint, LDAP, network-policy, runtime, release, or production-certification evidence.

KSA-16 repository-side verification: `PYTHONPATH=src:. python3 -m unittest tests.test_chg16_classification_admission -q` PASS (7 tests); focused KSA-14/15, host, environment, foundation, and certification regressions PASS; full repository suite PASS (334 tests, 3 optional skips) under Python 3.11; Python 3.11 and 3.12 compile checks PASS. FIX01 verifies exact OpenCode v1.3.9-shaped `FilePart` inputs default to `company_confidential`, file parts are removed before model exposure, model/tool classification and route/policy spoof values are stripped, and trusted engine-level labels remain separately tested. OpenCode v1.3.9 loader compatibility PASS; esbuild parsing PASS; the full TypeScript fixture reaches these FIX01 assertions but remains blocked at the pre-existing CLI-success fixture's missing KSA-10 candidate/runtime subjects; standalone `tsc` is environment-blocked by missing Node/Bun/OpenCode ambient type packages. Python 3.12 focused execution is dependency-blocked because Pillow is unavailable for the existing image-normalization test. No company policy approval, Gemma inference, model-data attestation, target-Gemma certification, BUILD COMPLETE, release, or production certification is claimed.

KSA-18 bounded BUILD repository-side verification: exact base `ad89e3ef608d423d90bfe4cd182406e846a3e36e`, branch `codex/k-slide-chg16-default-deny-egress-01`; versioned source-free default-deny egress policy, candidate/RunEnvironmentIdentity binding, pre-transport capability admission, strict `google/gemma-4-31b-it` OpenCode model pin, and trusted `chat.params` guard implemented. Full Python suite PASS (346 tests, 3 optional skips); KSA-18 egress/authentication/environment/candidate tests PASS (7 egress tests); Python 3.11/3.12 compile checks PASS; Python 3.12 focused egress/authentication/environment tests PASS (31 tests); OpenCode 1.3.9 agent/config inspection, plugin-loader compatibility, and trusted pre-request guard PASS. The complete TypeScript fixture remains blocked by the pre-existing KSA-10 CLI-success fixture with no candidate/runtime subjects; standalone `tsc` remains environment-blocked by absent Node ambient types. Production doctor reports live deployment network enforcement as an external WARN gate; repository code does not prove company firewall, service-mesh, DNS, or network-layer enforcement. No live egress enforcement, company endpoint, Gemma inference, BUILD COMPLETE, release, or production certification is claimed.

KSA-19 bounded BUILD repository-side verification: exact base `08d55a66e23d9c2f76fd15ff9dee0e9332836e16`, branch `codex/k-slide-chg16-governed-termbase-01`; governed core plus explicitly injected BU/team overlays, deterministic hierarchy, source-free authority/version/content identity, fail-closed authorization/materialization/drift checks, candidate/runtime/resume binding, and exact isolated-evaluation reproduction implemented. Full Python suite and focused KSA-19/candidate/runtime/certification tests pass; Python compile and diff checks pass. The repository exposes an adapter/contract for deployment-owned company authorization and does not claim a live company termbase or membership backend. No BUILD COMPLETE, release, or production certification is claimed.

The dependency-backed temporary environment exercised Pillow, PyMuPDF, python-pptx, and verified Korean-font support. LibreOffice, PaddlePaddle, PaddleOCR, and the approved Gemma endpoint were unavailable locally. The OpenCode runner retained timeout diagnostics and did not treat the zero-event timeout as a protocol pass.

## Certification capability matrix

| Capability | Status | Evidence |
| --- | --- | --- |
| Unit/integration tests | PASS | Full unittest command passes; optional document/OCR tests are dependency-gated in the base interpreter |
| Artifact generation | PASS | 500/500 generated across five formats |
| Lightweight engine | PASS with capability-separated findings | 500 cases executed; 320 raster/PDF cases completed, 80 raster/PDF financial OCR cases and 100 PPTX cases capability-blocked |
| LibreOffice real roundtrip | VERIFY/BLOCKED | The canonical image contract includes exact LibreOffice `4:25.2.3-2+deb13u6`; the clean cross-architecture build reached the package layer, but did not complete the emulated Python/Paddle layer in the available wait window |
| PaddleOCR real Korean roundtrip | VERIFY/BLOCKED | Runtime lock/inventory and offline OCR verification are implemented; no certifying OCR bundle was available and the development-prefetch build did not complete |
| OpenCode protocol | BLOCKED | OpenCode 1.3.9 pure and normal clean Qwen smoke both timed out before events |
| Gemma development | BLOCKED | `google/gemma-4-31b-it` unavailable in effective runtime |
| Gemma validation | NOT RUN | Target endpoint unavailable |
| Held-out quality evaluation | NOT RUN | Champion remains `UNSET` |
| Internal bilingual evaluation | NOT RUN | Private dataset not present |
| Zero-Korean comprehension study | NOT RUN | Study has protocol only |
| Production certification | DEVELOPMENT | No target-model or human gates passed |
| Production doctor/profile | BLOCKED as expected | No certified profile; target model, Paddle/LibreOffice, retention attestation, and fingerprint are not proven locally |
| Support bundle/redaction/retention controls | PASS (unit-tested) | Metadata-only support bundle and fail-closed cleanup are implemented; deployment enforcement remains required |
| Release manifest/SBOM tooling | PASS (offline smoke) | Generates DEVELOPMENT metadata with deployment fingerprint; certified release state is evidence-derived and blocked without complete evidence; production SBOM generation requires the exact resolved dependency inventory |

## Certification closure verification

The latest local closure run executed:

```text
PYTHONPATH=src:. python -m unittest discover -s tests -q
161 tests passed, 2 optional dependency skips
161 tests passed, no optional dependency skips
python -m compileall -q src evals tests: PASS
git diff --check: PASS
DEVELOPMENT release generation: PASS
PRODUCTION_CERTIFIED request with incomplete evidence: BLOCKED (expected)
Complete synthetic release → certified profile → full production doctor: PASS
Candidate-bound multimodal proof and production dependency/ruleset binding: PASS
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
| PPTX heavy roundtrip | VERIFY/BLOCKED | Canonical runtime pins LibreOffice; the clean cross-architecture build reached the system package layer but the emulated Python/Paddle layer did not complete in the wait window |
| Paddle real Korean OCR | VERIFY/BLOCKED | Runtime lock/inventory and offline OCR checks are implemented; no certifying OCR overlay was available and no completed image was produced |
| Heavy engine subset with `paddle` | VERIFY/BLOCKED | The same-image workflow is wired; actual image execution remains unverified in this host |
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
- LibreOffice-rendered PPTX and PaddleOCR 3 integration are not completed in this workspace. Use the canonical `deploy/runtime/Dockerfile` and `python -m evals.heavy.doctor` in an approved environment; `evals/heavy` is a verification wrapper, not a second image authority.
- The model-facing OpenCode flow is contract-ready, but the isolated clean-workspace Qwen protocol smoke timed out before emitting structured events. Levels 3/4 were intentionally not run after that provider-level failure. No Gemma accuracy or comprehension result is reported; this remains a provider/runtime blocker to resolve in an environment where the configured model responds.
- Numeric/modality/terminology verifiers are deterministic foundations, not a substitute for bilingual gold review.
- Current-message attachment materialization is implemented at the trusted OpenCode host boundary for the installed 1.3.9 FilePart contract: supported local/data inputs are reduced to private transient local references before the host-neutral adapter, while the full provider/model protocol remains separately blocked above.
- The local OpenCode server `/doc` surface exposed only global routes during inspection; the runner therefore uses the supported CLI JSON-event path for protocol execution and records structured server API work as a separate capability.
- Locally generated visual corpus cases are available with the verified macOS system Korean font. LibreOffice and PaddleOCR are still unavailable locally, so PPTX visual normalization and real OCR remain heavy-tier capability blocks.
- The PaddleOCR adapter follows the current 3.x API shape but is not installed or benchmarked in this workspace.
- Production mode is intentionally fail-closed until an approved profile contains a real certification fingerprint, approved model-data attestation, local OCR assets, and proven heavy/runtime capabilities.
- The support-bundle path is source-free by construction, but administrative access control for invoking it must be supplied by the managed deployment.

## KSA-26 initial governance evidence (historical checkpoint)

Bounded repository change from exact integrated main `847c8e760b13b3eb6aeff22106d54ada324a9c1b`, on branch `codex/k-slide-chg16-corpus-governance-01`. Final worktree `HEAD` remains that same base commit; changes are uncommitted, with no merge or history rewrite.

Implemented a source-free, canonical four-role corpus governance contract and bound its identities into candidate deployment fingerprints, model evidence, certification loading, and release manifests. The public synthetic 100-case corpus retains dataset version `1.0`, its current corpus and public held-out fingerprints, all scenario IDs, gold, and split assignments. Its `held_out` split is explicitly `public_synthetic_regression`, not `sealed_held_out`. Candidate and evidence boundaries validate role/purpose, lifecycle, immutable version transitions, predecessor/replacement lineage, canonical membership hashes, cross-set content overlap, held-out contamination records, and exact candidate/evidence identity equality. The tracked production candidate remains on its legacy development-readable identity; the example template leaves private governed identities `UNSET`. Private data remains outside Git. No external IAM qualification is implied.

Changed repository files:

- `evals/README.md`
- `evals/corpus_governance.py` (new)
- `evals/model_eval.py`
- `evals/opencode_diagnostics.py`
- `evals/production-candidate.example.yaml`
- `evals/production-candidate.yaml`
- `evals/release.py`
- `evals/run_engine_eval.py`
- `evals/scenarios.py`
- `private-evals/README.md`
- `src/k_slide/certification.py`
- `src/k_slide/corpus_governance.py` (new)
- `src/k_slide/evidence_adapters.py`
- `src/k_slide/production.py`
- `tests/test_certification_closure.py`
- `tests/test_ksa26_corpus_governance.py` (new)

Validation commands and results:

```text
rtk env PYTHONPATH=src:. python -m unittest tests.test_ksa26_corpus_governance -q
PASS: 19 KSA-26 tests at the focused-test checkpoint.

rtk env PYTHONPATH=src:. python -m unittest tests.test_ksa26_corpus_governance tests.test_certification_closure tests.test_phase32 tests.test_phase33 tests.test_phase35 -q
PASS: 156 tests.

rtk env PYTHONPATH=src:. python3.11 -m unittest discover -s tests -q
PASS: 519 tests, 4 skipped.

rtk env PYTHONPATH=src:. python3.12 -m unittest discover -s tests -q
Initial diagnostic: failed because this interpreter lacked the declared Pillow dependency; nine image-dependent errors and one doctor expectation failure resulted.

rtk env python3.12 -m venv /tmp/k-slide-ksa26-py312
rtk env /tmp/k-slide-ksa26-py312/bin/python -m pip install 'Pillow>=10,<13'
rtk env PYTHONPATH=src:. /tmp/k-slide-ksa26-py312/bin/python -m unittest discover -s tests -q
PASS after installing Pillow 12.3.0 in that temporary environment: 519 tests, 9 skipped.

rtk env PYTHONPATH=src:. python -m unittest tests.test_ksa21_adversarial_security tests.test_ksa22_provenance tests.test_ksa23_conflicts tests.test_ksa24_modality_conformance tests.test_ksa24_f24_repairs tests.test_ksa24_f24_real_path tests.test_ksa25_recovery_law -q
PASS: 93 tests, 1 skipped.

rtk env PYTHONPATH=src:. python -m unittest tests.test_chg16_accesskey_nonleakage tests.test_chg16_authentication_transport tests.test_chg16_classification_admission tests.test_chg16_deletion tests.test_chg16_durable_execution tests.test_chg16_environment_binding tests.test_chg16_foundation tests.test_chg16_host_integration tests.test_chg16_paas_worker tests.test_chg16_retention_policy tests.test_chg16_scoped_admission tests.test_chg16_storage_planes tests.test_chg18_opencode_bootstrap tests.test_ksa19_employee_path tests.test_ksa19_governed_termbase tests.test_runtime_artifact -q
PASS: 177 tests, 1 skipped.

rtk npx --no-install tsx tests/test_chg16_opencode_plugin.ts
PASS: OpenCode host attachment regression tests.

rtk env PYTHONPATH=src:. python -m unittest tests.test_phase35.Phase35Tests.test_full_translation_contract_matches_schema_and_typescript -q
PASS: TranslationPatch Python/schema/TypeScript contract test.

rtk env PYTHONPATH=src:. python -c 'import json, pathlib, jsonschema; paths=sorted(pathlib.Path("schemas").glob("*.schema.json")); [jsonschema.Draft202012Validator.check_schema(json.loads(p.read_text(encoding="utf-8"))) for p in paths]; print(len(paths), "JSON schemas valid:", [p.name for p in paths])'
PASS: all 4 repository JSON schemas.

rtk env PYTHONPATH=src:. python3.11 -m compileall -q src evals tests
rtk env PYTHONPATH=src:. python3.12 -m compileall -q src evals tests
PASS: both supported interpreter compile checks.

rtk env PYTHONPATH=src:. python -m evals.generate_corpus --output /tmp/k-slide-ksa26-public-smoke --formats png --limit 1
PASS: public generation smoke; manifest retained DATASET_VERSION 1.0, corpus_fingerprint 698b471fa9dffe9f79af40a61c3546d6455889b90063a02bc2e270b90402f7ac, and public held_out_fingerprint c2dee1ba1b03fead1a6641cfa8c7ceea27eb51b0ed80c0879c07bc3ee29bcc4e.

rtk git diff --check
PASS.
```

Authoring diagnostics before final green runs: the first focused KSA-26 attempt exposed two test-helper issues, and the first certification-closure attempt exposed seven legacy fixture assumptions about corpus identity; the fixtures and compatibility path were corrected, after which the focused and full suites passed. An initial inline schema-check command had a quoting/syntax error and was replaced by the passing command above. The unmodified Python 3.12 interpreter run exposed the missing declared Pillow dependency; the isolated dependency-backed full run passed as recorded.

Scope exclusions: no KSA-27 or later policy, no hard quality thresholds/repetition/reviewer/study/champion logic, no live company or Gemma qualification, no private corpus bytes, no release or production certification. `evals/champion.json` remains `UNSET`; no candidate promotion or repository status flag was advanced. The passing synthetic closure fixtures exercise repository logic only and are not production evidence.

## CHG-16 / KSA-26 FIX01 and FIX02 continuation evidence

This continuation starts at exact integrated main `847c8e760b13b3eb6aeff22106d54ada324a9c1b`. It fast-forwarded to the exact predecessor BUILD candidate `28be285b08859bdcbb6e910e94af6f5c161d248a` before repair edits; that predecessor is a direct child of the requested base. Work branch: `codex/k-slide-chg16-corpus-governance-01-fix01`. Final implementation work head: `52732149b774c17eef16d75dad157a00044ff353`.

F26-01 adds a second, explicit source mode to the canonical `ModelEvaluationRunner` and `OpenCodeEvalRunner`. Governed external mode consumes canonical source-free manifests and an exact four-role candidate-bound bundle, validates local descriptors/artifact/gold bytes and role/purpose/history before execution, and retains the existing TranslationPatch/SlideIR scorers and evidence adapters. The adapter rederives exact active membership and result matrices from the persisted governed case identity without public scenario membership authority. A generated-public-byte digest scan is used only to exclude copied public artifacts; manifest membership remains the sole governed execution authority. Output metadata omits local paths and gold/source contents. Public synthetic mode retains its generation path, public manifest bundle, and fingerprints.

F26-02 keeps retired public membership permanently relevant to sealed held-out overlap checks. Historical active memberships and item-scoped exposure contexts remain contamination-relevant after retirement; unrelated retired private history is permitted. Source-only, gold-only, and source-plus-gold overlap are checked across current and historical manifests, while transition, predecessor, replacement, and version validation remain fail-closed.

Changed files for this continuation:

- `evals/README.md`
- `evals/governed_corpus.py` (new)
- `evals/model_eval.py`
- `evals/opencode_runner.py`
- `evals/run_model_eval.py`
- `private-evals/README.md`
- `src/k_slide/corpus_governance.py`
- `src/k_slide/evidence_adapters.py`
- `tests/test_certification_closure.py`
- `tests/test_ksa26_corpus_governance.py`
- `tests/test_ksa26_governed_runner.py` (new)
- `IMPLEMENTATION_STATUS.md`

Final validation commands and results for the final source tree, including the public-byte exclusion guard:

```text
PYTHONPATH=src:. rtk python3.11 -m unittest tests.test_ksa26_corpus_governance tests.test_ksa26_governed_runner -q
PASS: 36 focused KSA-26 governance, external-runner, and adapter tests. This includes a renamed public artifact copied without generator metadata and rejected by its exact generated-byte digest. The three role smokes use a deterministic OpenCode test double; they are not live model measurements.

PYTHONPATH=src:. rtk python3.11 -m unittest tests.test_certification_closure tests.test_phase32 tests.test_phase33 tests.test_phase35 -q
PASS: 138 certification closure and phase 3.2/3.3/3.5 tests.

PYTHONPATH=src:. rtk python3.11 -m unittest tests.test_ksa21_adversarial_security tests.test_ksa22_provenance tests.test_ksa23_conflicts tests.test_ksa24_modality_conformance tests.test_ksa24_f24_repairs tests.test_ksa24_f24_real_path tests.test_ksa25_recovery_law -q
PASS: 93 KSA-21–25 regression tests, 1 skipped.

PYTHONPATH=src:. rtk python3.11 -m unittest tests.test_chg16_accesskey_nonleakage tests.test_chg16_authentication_transport tests.test_chg16_classification_admission tests.test_chg16_deletion tests.test_chg16_durable_execution tests.test_chg16_environment_binding tests.test_chg16_foundation tests.test_chg16_host_integration tests.test_chg16_paas_worker tests.test_chg16_retention_policy tests.test_chg16_scoped_admission tests.test_chg16_storage_planes tests.test_chg17_run_scope_authorization tests.test_chg18_accesskey_handoff tests.test_chg18_default_deny_egress tests.test_chg18_opencode_bootstrap tests.test_ksa19_employee_path tests.test_ksa19_governed_termbase tests.test_ksa20_controlled_content_support tests.test_runtime_artifact -q
PASS: 222 KSA-15–20/security/host/runtime compatibility tests, 1 skipped.

rtk npx --no-install tsx tests/test_chg16_opencode_plugin.ts
PASS: OpenCode TypeScript host regression.

PYTHONPATH=src:. rtk python3.11 -c 'import json, pathlib, jsonschema; paths=sorted(pathlib.Path("schemas").glob("*.schema.json")); [jsonschema.Draft202012Validator.check_schema(json.loads(p.read_text(encoding="utf-8"))) for p in paths]; print(len(paths), "JSON schemas valid:", [p.name for p in paths])'
PASS: all 4 JSON schemas.

PYTHONPATH=src:. rtk python3.11 -m unittest tests.test_phase35.Phase35Tests.test_full_translation_contract_matches_schema_and_typescript -q
PASS: TranslationPatch Python/schema/TypeScript contract test.

PYTHONPATH=src:. rtk python3.11 -m unittest discover -s tests -q
PASS: 537 tests, 4 skipped, on Python 3.11.7.

PYTHONPATH=src:. rtk /tmp/k-slide-ksa26-py312/bin/python -m unittest discover -s tests -q
PASS: 537 tests, 9 skipped, on isolated Python 3.12.9 with Pillow 12.3.0.

PYTHONPATH=src:. rtk python3.11 -m compileall -q src evals tests
PYTHONPATH=src:. rtk /tmp/k-slide-ksa26-py312/bin/python -m compileall -q src evals tests
rtk git diff --check
PASS: both compile checks and whitespace validation.

PYTHONPATH=src:. rtk python3.11 -m evals.generate_corpus --output /tmp/k-slide-ksa26-public-smoke-final --formats png --limit 1
PYTHONPATH=src:. rtk python3.11 -c 'import json, pathlib; d=json.loads(pathlib.Path("/tmp/k-slide-ksa26-public-smoke-final/specs/MANIFEST.json").read_text()); print(d["dataset_version"], d["corpus_fingerprint"], d["held_out_fingerprint"])'
PASS: public generation smoke retained DATASET_VERSION 1.0, corpus fingerprint 698b471fa9dffe9f79af40a61c3546d6455889b90063a02bc2e270b90402f7ac, and public held-out fingerprint c2dee1ba1b03fead1a6641cfa8c7ceea27eb51b0ed80c0879c07bc3ee29bcc4e.
```

An intermediate closure-suite run exposed legacy test fixtures that reused public scenario IDs and public held-out fingerprints while presenting governed roles. Those fixtures were changed to opaque governed IDs and manifest-derived identities; the final closure and both final full-discovery runs are green. The public corpus smoke is generation-only.

Explicit exclusions: no KSA-27 or later; no live company corpus, private corpus contents, live Gemma execution or Gemma quality qualification; no release, candidate promotion, champion assignment, or production certification. Synthetic external-role smokes establish runner/adapter contract compatibility only.

## CHG-16 / KSA-27 predecessor hard-gate BUILD

This continuation starts from exact integrated main `fa03989e002864081609a25add1fb36b282d99a7` on branch `codex/k-slide-chg16-hard-gates-01`; the work head remains that base with uncommitted changes. No main merge was performed. It preserves KSA-26's four-set governed corpus, exact role/purpose/membership checks, external private/high-risk/sealed runner, and existing repetition/group policy.

The predecessor BUILD candidate used source-free policy schema `1.0`, policy `ksa-27.1`, registry `ksa-27-hard-gates-1`, SHA-256 `41736413cb8fdb0714b03b46c402ca8567c2d09903b17bb2886dc8313d2e739f`. Its hard-gate registry is closed; unknown codes map to a failing `UNKNOWN_HARD_GATE_CODE`. Its 0.99 field was incorrectly derived from the minimum of already-critical axes. F27-01 replaces that metric and advances the policy identity below.

Model evaluation, machine evidence adapters, internal bilingual evidence validation, and release output shared and rederived that predecessor identity. Deployment fingerprints remained separate. Per-case and per-work-unit hard-gate findings were rebuilt from scorer facts, structured OpenCode events, required-media traces, exact model identity, persisted verification/finalization state, recovery state, and KSA-23 conflict state. Hard-gate failure preceded floors; means remained descriptive. Table identity, cell membership, duplicate/extra/missing table members, and cardinality were checked by source IDs. Safe unnecessary review counted toward precision rather than as a critical error; engine-owned material false-DONE remained zero tolerance. Its evidence envelope schema was `2.4`. No KSA-29 reviewer workflow or KSA-28 repetition changes were introduced.

Changed implementation and test files:

- `evals/certification.py`, `evals/model_eval.py`, `evals/model_results.py`, `evals/model_scorers.py`, `evals/release.py`
- `src/k_slide/certification.py`, `src/k_slide/evidence_adapters.py`, `src/k_slide/quality_policy.py`
- `tests/test_certification_closure.py`, `tests/test_ksa26_governed_runner.py`, `tests/test_ksa27_quality_policy.py`, `tests/test_phase33.py`
- `.codex-fabric/audit.json`, `IMPLEMENTATION_STATUS.md`

Final validation:

```text
rtk proxy env PYTHONPATH=src:evals:. python3 -m unittest tests.test_ksa27_quality_policy tests.test_ksa26_corpus_governance tests.test_ksa26_governed_runner -q
PASS: 56 tests; KSA-27 hard-gate/floor/tamper cases plus KSA-26 governance and governed external-runner cases.

rtk proxy env PYTHONPATH=src:evals:. python3 -m unittest tests.test_certification_closure tests.test_phase32 tests.test_phase33 tests.test_phase35 -q
PASS: 139 tests; certification closure and phase 3.2/3.3/3.5 regression suites.

rtk proxy env PYTHONPATH=src:. python3 -m unittest -q tests.test_ksa21_adversarial_security tests.test_ksa22_provenance tests.test_ksa23_conflicts tests.test_ksa24_modality_conformance tests.test_ksa24_f24_repairs tests.test_ksa24_f24_real_path tests.test_ksa25_recovery_law
PASS: 93 tests, 1 skipped; KSA-21–25 preservation.

rtk proxy env PYTHONPATH=src:. python3 -m unittest -q tests.test_chg16_foundation tests.test_chg16_storage_planes tests.test_chg16_durable_execution tests.test_chg16_accesskey_nonleakage tests.test_chg16_deletion tests.test_chg16_host_integration tests.test_chg17_run_scope_authorization tests.test_chg18_accesskey_handoff tests.test_chg18_default_deny_egress tests.test_chg18_opencode_bootstrap tests.test_ksa19_employee_path tests.test_ksa19_governed_termbase tests.test_ksa20_controlled_content_support tests.test_chg16_environment_binding tests.test_chg16_classification_admission tests.test_chg16_retention_policy tests.test_chg16_scoped_admission tests.test_chg16_paas_worker tests.test_chg16_authentication_transport
PASS: 216 tests, 1 skipped; KSA-15–20/security/host/runtime compatibility.

rtk proxy npx --yes tsx tests/test_chg16_opencode_plugin.ts
PASS: OpenCode host attachment regression.

rtk proxy env PYTHONPATH=src:. python3 -c 'import json,pathlib; from jsonschema import Draft202012Validator; files=sorted(pathlib.Path("schemas").glob("*.json")); [Draft202012Validator.check_schema(json.loads(p.read_text())) for p in files]; print(f"{len(files)} schemas: Draft 2020-12 valid")'
PASS: all 4 repository JSON schemas.

rtk proxy env PYTHONPATH=src:. python3 -m unittest -q tests.test_phase35.Phase35Tests.test_full_translation_contract_matches_schema_and_typescript
PASS: TranslationPatch Python/schema/TypeScript contract.

rtk proxy env PYTHONPATH=src:. python3 -m unittest discover -s tests -p 'test_*.py' -q
PASS: 558 tests, 4 skipped on Python 3.11.7.

rtk proxy env PYTHONPATH=src:. /tmp/k-slide-py312-fix05/bin/python -m unittest discover -s tests -p 'test_*.py' -q
PASS: 558 tests on isolated Python 3.12.9.

rtk proxy env PYTHONPATH=src:. python3 -m compileall -q src evals tests
rtk proxy env PYTHONPATH=src:. /tmp/k-slide-py312-fix05/bin/python -m compileall -q src evals tests
rtk git diff --check
PASS: both compile checks and whitespace validation.
```

An intermediate deployment-identity test initially passed the certification policy hash as a candidate-profile field, correctly rejected by the deployment allowlist; its fixture now keeps certification metadata outside deployment factors. Initial full discovery also exposed a legacy scorer test double without `recovery_status`; the scorer now reads that engine-owned field optionally, while current EvidenceIR recovery state remains the material-recall source. Both final full-discovery runs passed. Temporary synthetic release fixtures print example release states; these are test output only.

`evals/champion.json` remained `UNSET` for the predecessor candidate. No KSA-28+, live company/Gemma qualification, private-human/security approval, release, candidate promotion, or production certification was performed by that predecessor.

## CHG-16 / KSA-27 F27-01 non-critical semantic-equivalence repair

F27-01 began from exact integrated main `fa03989e002864081609a25add1fb36b282d99a7` on branch `codex/k-slide-chg16-hard-gates-01-fix01`. The branch was fast-forwarded to predecessor BUILD candidate `b2ca101733ee450e123bf8b630ceca6eda9cc20a`; that candidate's exact parent is the requested main base. Repair edits are on top of that predecessor commit, preserving its ancestry. No main merge was performed. The repair remains a working-tree change on top of work head `b2ca101733ee450e123bf8b630ceca6eda9cc20a`.

The current machine metric uses explicit approved non-critical meaning assertions. Each output surface must equal a complete approved phrase after NFKC normalization, case folding, and deterministic tokenization; unapproved additions or contradictions cannot pass by containing an approved substring. Public assertions are held in a policy-bound sidecar keyed to stable scenario IDs and exact EvidenceIR source anchors, preserving KSA-26 dataset version `1.0` and both public corpus fingerprints. Governed external assertions are loaded only from the exact gold wrapper whose bytes match the manifest's `gold_sha256`. The scorer records opaque assertion IDs, source-object identities, outcomes, counts, and rates; governed result rows, machine evidence, release metadata, and logs omit assertion text and acceptable phrases. The adapter validates assertion membership, source-anchor digests, observations, counts, and rates again from persisted scorer facts.

Quality policy is now schema `1.0`, policy `ksa-27.2`, registry `ksa-27-hard-gates-1`, identity SHA-256 `4656283f7ce7506695e42e54008eea190bfcaab9a971b737280af27405801fd1`. The existing 0.99 floor now applies to `noncritical_semantic_equivalence = correct / required`, with a no-positive rate of `1.0`; exactly `0.99` passes and lower values fail. Evidence schema advanced from `2.4` to `2.5`, so predecessor evidence cannot qualify under the repaired policy. Internal-bilingual `overall_noncritical_semantic_fidelity` retains the same 0.99 threshold and is bound to the same conceptual policy dimension. The hard-gate registry version remains unchanged.

Focused coverage uses the actual public assertion gold and persisted scorer observations: two public source-bound assertions with one non-critical miss and no hard-gate finding; harmless approved paraphrase; fluent incorrect meaning; wrong-region text; 99/100 pass; 989/1000 fail with no hard-gate finding; allowed unresolved exemption; material unresolved miss; summary/observation/ID tampering; hash-bound governed private assertions; stale-policy rejection; and exact bilingual/unresolved floors. Existing hard-gate, governance, release, and champion tests remain included in the regression runs below.

Final validation for F27-01:

```text
KSA-27 focused + KSA-26 governance/runner: 63 tests passed.
Certification closure / phase32 / phase33 / phase35: 139 tests passed.
KSA-21–25 regression: 93 tests passed, 1 skipped.
KSA-15–20 security/host/runtime regression: 216 tests passed, 1 skipped.
OpenCode TypeScript host attachment regression: passed.
All 4 repository JSON schemas: Draft 2020-12 validation passed.
TranslationPatch Python/schema/TypeScript contract: passed.
Full Python 3.11.7 discovery: 565 tests passed, 4 skipped.
Isolated Python 3.12.9 discovery: 565 tests passed.
Compileall on Python 3.11.7 and 3.12.9: passed.
git diff --check: passed.
```

Diagnostic runs: an initial `rtk pytest` invocation collected no tests, and an initial unittest invocation without `PYTHONPATH=src` could not import `k_slide`; verification then used the repository's unittest discovery with the correct source path. The first closure run also exposed two phase33 synthetic rows without empty assertion-observation fields; those fixtures were updated and the complete closure suite passed afterward.

Explicit exclusions: no KSA-28+, no merge to main, no live company/Gemma/private-human qualification, no champion assignment, no release, no BUILD COMPLETE claim, and no production certification claim. `evals/champion.json` remains `UNSET`. Synthetic governed fixtures verify code paths only and are not private-corpus or Gemma quality evidence.


## Next phase

KSA-28 and later work requires a separate scoped change. Existing production-candidate prerequisites remain listed above, but none were run for this KSA-27 implementation.

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
- [ADR 0038 — Versioned durable execution contract](docs/adr/0038-versioned-durable-execution-contract.md)
- [ADR 0044 — Classification admission for the configured inference route](docs/adr/0044-classification-admission.md)
