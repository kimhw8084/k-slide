# K-Slide

K-Slide turns Korean or mixed Korean-English business artifacts into evidence-backed English comprehension for readers who do not know Korean. It is designed for slides, screenshots, PDFs, PPTX files, tables, charts, diagrams, and dense business-review visuals.

The current implementation is K-Slide `0.3.5`, a Phase 3.5 execution-isolation and heavy-runtime-proof build. It provides immutable engine-owned source evidence, a narrow structured TranslationPatch, globally unique multi-document work units, deterministic reports, source-local semantic scorers, stratified frozen splits with fingerprints, per-attempt OpenCode media assertions, isolated OpenCode diagnostics, fail-closed OCR configuration, and a host-persisted LibreOffice/PaddleOCR evaluation workflow. Full Gemma translation certification is not claimed until the target model and evaluation gates are exercised.

## Quick start

From this project:

```bash
./scripts/install_project.sh /path/to/your/project
./scripts/verify_install.sh /path/to/your/project
```

Then launch OpenCode in the target project. Put source files in:

```text
.k-slide-input/
```

Run:

```text
/k-slide
```

Or pass an explicit file or directory:

```text
/k-slide slides/weekly-review.pptx
/k-slide slides/
```

Results are written under:

```text
.k-slide-runs/<run-id>/
```

Use `/k-slide-status` for the current session and `/k-slide-doctor` for diagnostics. Users do not need to remember a run ID for normal operation.

## Supported source types

The engine validates file content, not only suffixes, and currently accepts `.png`, `.jpg`, `.jpeg`, `.webp`, `.pdf`, and `.pptx`. Inputs are copied into an immutable run snapshot and recorded with SHA-256 hashes. Office archives are inspected for unsafe paths, excessive expansion, symlinks, and macros.

Image normalization requires Pillow. PDF normalization requires PyMuPDF, PPTX native extraction requires python-pptx, and PPTX rendering requires a headless LibreOffice/soffice plus PyMuPDF. OCR is selected through managed `none`, `paddle`, or `auto` policy. Certification runs pin the provider; normal deployments may use `auto`. The local PaddleOCR adapter targets the current PaddleOCR 3.x/PaddlePaddle 3.x family but is not installed by default. `/k-slide-doctor` reports the requested and effective provider instead of assuming it. The default privacy posture is local-first; source content is not sent to external OCR or web services.

The source pipeline is deliberately separated:

```text
engine EvidenceIR → Gemma TranslationPatch → engine-controlled SlideIR → deterministic verification
```

The model cannot author source geometry, native text, numeric facts, required-region inventories, or coverage baselines. Each patch is bound to the immutable EvidenceIR revision for its work unit.

`kslide_evidence` also returns a model media plan with one required whole-unit context image and risk-routed crops. The agent must read those images before submitting a patch. Reports are rendered deterministically from the merged SlideIR; `NEEDS_REVIEW` and incomplete work units block `DONE`.

## OpenCode integration

The project installs:

- `/k-slide`, `/k-slide-strict`, `/k-slide-safe`, `/k-slide-continue`, `/k-slide-status`, `/k-slide-doctor`, `/k-slide-audit`, and `/k-slide-help`;
- one visible `k-slide` agent;
- typed custom tools: `kslide_prepare`, `kslide_next`, `kslide_evidence`, `kslide_submit`, `kslide_verify`, `kslide_finalize`, `kslide_status`, and `kslide_doctor`.

The installed agent does not use model-generated shell commands for K-Slide lifecycle operations. OpenCode compatibility is detected at runtime; the repository was validated against OpenCode `1.3.9` during this implementation pass.

The current local environment reports `ollama/qwen3:14b`, not the target `google/gemma-4-31b-it`. K-Slide records that mismatch as a warning and does not certify the runtime as production-compatible. The target model is the instruction-tuned Gemma 4 31B model documented by [Google](https://ai.google.dev/gemma/docs/core/model_card_4).

### Certification candidate resolution

Certification-quality commands take an explicit candidate profile. Release
tooling resolves repository-owned immutable hashes (including prompts,
termbase, constraints, schema, policy, corpus, and OCR manifest inputs) without
changing a declared value. To persist that resolved source-free object for
subsequent evidence producers, use an explicitly private output path:

```bash
PYTHONPATH=src:. python -m evals.release \
  --root . \
  --output .k-slide-config/release-manifest.json \
  --candidate-profile .k-slide-config/production-candidate.json \
  --resolved-candidate-output .k-slide-config/resolved-candidate.json
```

An unresolved value remains `UNSET` and blocks any release state that requires
it. `NOT_EXPOSED` and `NOT_APPLICABLE` are reserved for provider metadata that
the provider genuinely cannot expose; they never resolve an ordinary required
production field. Certification evidence and the final production manifest
must be staged beneath the release root so the production doctor can reopen
their relative paths; outside-root evidence is rejected. The tracked
`evals/production-candidate.yaml` intentionally remains an incomplete
DEVELOPMENT template. Accordingly, the public security workflow publishes
scanner reports but marks its result `NOT_CERTIFYING` until a complete private
candidate is supplied.

The approved deployment environment must first persist one exact package
subject: `.k-slide-config/production-requirements.lock` and its canonical
`.k-slide-config/production-dependency-inventory.json`. The shared
`evals.freeze_production_dependencies` command derives both from the active
production interpreter and, for a private certifying run, verifies them
against an already-approved lock. The public repository never stores the
private bundle as its own Actions artifact. Hosted certification requires
protected environment configuration (`KSLIDE_PRIVATE_CERTIFICATION_REPOSITORY`,
approved preparation workflow ID and path, and
`KSLIDE_PRIVATE_CERTIFICATION_TOKEN`) plus a run ID, artifact name, and
externally supplied archive digest. The workflow verifies authoritative
private run/artifact metadata before downloading; there is no public-repository
fallback. `evals.build_certification_bundle` provides the local/private
producer contract and includes only explicitly named candidate, lock, termbase,
and OCR files. Without an approved private source, local/self-hosted
preparation is required; public scans still enforce scanner findings but a
clean result is explicitly `NOT_CERTIFYING`. The heavy Docker image installs
the same lock and fails if its installed inventory differs. The production SBOM is
then generated from that inventory with
`--production-dependency-inventory` and `--generate-production-sbom`.

## Development checks

```bash
rtk env PYTHONPATH=src python3 -m unittest discover -s tests -v
rtk env PYTHONPATH=src python3 -m k_slide.cli doctor --root . --json
rtk opencode debug config
rtk env PYTHONPATH=src python3 -m evals.run_engine_eval --output /tmp/k-slide-eval --limit 5
```

The public evaluation laboratory generates 100 synthetic scenario specifications and independent PNG/JPEG/WebP/PDF/PPTX cases. Run `PYTHONPATH=src python -m evals.generate_corpus --output /tmp/k-slide-corpus --formats png jpg webp pdf pptx` for the 500-case default corpus, then use `evals.run_engine_eval` to score each format through the real engine. This remains an engine/evidence tier, not a Gemma quality benchmark. Target-model results must be produced through the OpenCode runner in an approved environment and recorded with the exact model, provider, prompt, OCR, and preprocessing configuration.

The implementation status, known limitations, and next concrete tasks are tracked in [`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md). Historical source-pack lineage remains in [`SOURCE_PROVENANCE.md`](SOURCE_PROVENANCE.md). The exact completion artifact contract is code-owned by `src/k_slide/policy.py`.

Administrators can run `k-slide doctor --production` against a managed deployment profile. It fails closed until the approved model, OCR assets/provider, OpenCode runtime, retention policy, tenant isolation, egress policy, and certification fingerprint are proven. The non-model-facing `k-slide retention-cleanup` and `k-slide support-bundle` commands are intended for an administrator or deployment wrapper; support bundles contain operational metadata only and exclude source content.

The corpus runner is available for approved OpenCode environments:

```bash
PYTHONPATH=src python -m evals.run_model_eval \
  --output /tmp/k-slide-model-eval \
  --model ollama/qwen3:14b \
  --mode protocol --split development --formats png --limit 1
```

Non-target models are protocol smoke only. Quality is authoritative only when
the approved Gemma endpoint, actual `/k-slide` workflow, required structured
media reads, complete K-Slide artifacts, TranslationPatch, SlideIR, and
semantic gold scorers all pass.
