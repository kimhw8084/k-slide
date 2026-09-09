# K-Slide

K-Slide turns Korean or mixed Korean-English business artifacts into evidence-backed English comprehension for readers who do not know Korean. It is designed for slides, screenshots, PDFs, PPTX files, tables, charts, diagrams, and dense business-review visuals.

The current implementation is K-Slide `0.2.0`, a Phase 1.1 plus Phase 2 evidence-boundary build. It provides immutable engine-owned source evidence, a narrow structured translation patch, multi-work-unit state, deterministic completion, image/PDF/PPTX normalization, native extraction, deterministic crops, and an OCR-provider boundary. Full Gemma translation certification is not claimed until the target model and evaluation gates are exercised.

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

Image normalization requires Pillow. PDF normalization requires PyMuPDF, PPTX native extraction requires python-pptx, and PPTX rendering requires a headless LibreOffice/soffice plus PyMuPDF. OCR is optional; the local PaddleOCR adapter targets the current PaddleOCR 3.x/PaddlePaddle 3.x family but is not installed by default. `/k-slide-doctor` reports proven capabilities and warnings instead of assuming them. The default privacy posture is local-first; source content is not sent to external OCR or web services.

The source pipeline is deliberately separated:

```text
engine EvidenceIR → Gemma TranslationPatch → engine-controlled SlideIR → deterministic verification
```

The model cannot author source geometry, native text, numeric facts, required-region inventories, or coverage baselines. Each patch is bound to the immutable EvidenceIR revision for its work unit.

## OpenCode integration

The project installs:

- `/k-slide`, `/k-slide-strict`, `/k-slide-safe`, `/k-slide-continue`, `/k-slide-status`, `/k-slide-doctor`, `/k-slide-audit`, and `/k-slide-help`;
- one visible `k-slide` agent;
- typed custom tools: `kslide_prepare`, `kslide_next`, `kslide_evidence`, `kslide_submit`, `kslide_verify`, `kslide_finalize`, `kslide_status`, and `kslide_doctor`.

The installed agent does not use model-generated shell commands for K-Slide lifecycle operations. OpenCode compatibility is detected at runtime; the repository was validated against OpenCode `1.3.9` during this implementation pass.

The current local environment reports `ollama/qwen3:14b`, not the target `google/gemma-4-31b-it`. K-Slide records that mismatch as a warning and does not certify the runtime as production-compatible. The target model is the instruction-tuned Gemma 4 31B model documented by [Google](https://ai.google.dev/gemma/docs/core/model_card_4).

## Development checks

```bash
rtk env PYTHONPATH=src python3 -m unittest discover -s tests -v
rtk env PYTHONPATH=src python3 -m k_slide.cli doctor --root . --json
rtk opencode debug config
```

The implementation status, known limitations, and next concrete tasks are tracked in [`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md). Historical source-pack lineage remains in [`SOURCE_PROVENANCE.md`](SOURCE_PROVENANCE.md). The exact completion artifact contract is code-owned by `src/k_slide/policy.py`.
