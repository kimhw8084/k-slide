# K-Slide Implementation Status

## Current boundary

**K-Slide 0.2.0 — Phase 1.1 trust-model hardening and Phase 2 evidence boundary.**

The repository now has a coherent, tested boundary from validated immutable input through normalized document units, native evidence, deterministic crops, and bounded evidence packets. It does not claim production translation certification: the local runtime is `ollama/qwen3:14b`, not the target `google/gemma-4-31b-it`, and the release gates have not been measured on a gold corpus.

## Implemented and tested

- Engine-owned, versioned `EvidenceIR` with deterministic SHA-256 revisions.
- Strict model-owned `TranslationPatch`; source geometry, native text, OCR candidates, numeric facts, required IDs, and coverage baselines cannot be supplied by the model.
- Engine-controlled `EvidenceIR + TranslationPatch → SlideIR` merge with explicit provenance.
- Evidence revision, work-unit identity, table/cell identity, required-region coverage, and source-field injection checks.
- Persisted multi-work-unit queue with sequential scheduling, repair states, optimistic revisions, run locking, and resumable `NEEDS_REVIEW`.
- Finalization that re-runs verification against current artifacts before creating `RUN_COMPLETE.md`.
- Central completion policy in `src/k_slide/policy.py`, used by manifests, verification, and finalization.
- Typed OpenCode `kslide_submit` payload schema; no model-facing JSON-in-a-string contract.
- Narrow OpenCode permissions: normal K-Slide execution has no bash, edit, write, subagent, webfetch, or websearch access.
- Image normalization with decode, EXIF orientation, dimension, pixel-count, and decompression-safety limits.
- PDF page rendering and native text-span extraction through PyMuPDF.
- PPTX native shape/table extraction through python-pptx and capability-gated headless LibreOffice rendering.
- Deterministic render-region crops, model-ready non-generative resizing, numeric evidence extraction, and native/OCR evidence-fusion states.
- OCR provider protocol with `none` and optional PaddleOCR 3.x adapter.
- Black-box CLI, installer regression, trust-model, queue/resume, concurrency, stale-evidence, stale-finalization, and normalization fixture tests.
- GitHub Actions workflow for Python 3.11/3.12, unit tests, compile checks, CLI/installer checks, and doctor.

## Verification performed locally

```text
PYTHONPATH=src python3 -m unittest discover -s tests -v: PASS (26 tests, 3 optional skips)
PYTHONPATH=src /tmp/k-slide-verify/bin/python -m unittest discover -s tests -v: PASS (26 tests, optional image/PDF/PPTX fixtures exercised)
OpenCode: 1.3.9
Configured model: ollama/qwen3:14b
Model compatibility: different_model_warning
```

The three skipped tests require optional local Pillow, PyMuPDF, and python-pptx availability in the base interpreter. The temporary verification environment exercised those fixtures successfully. The CI workflow installs the project development extras, while PPTX rendering and PaddleOCR remain capability-gated integration paths. No target-model session or Gemma production evaluation was available locally.

## Known limitations

- Full target Gemma translation, repair quality, and zero-Korean comprehension evaluation are not yet measured.
- The current local interpreter does not have Pillow, PyMuPDF, python-pptx, LibreOffice, or PaddleOCR installed; doctor reports those capabilities rather than pretending they pass.
- PDF/PPTX normalization code is implemented but needs runtime fixture execution in an environment with those dependencies.
- Numeric extraction is an evidence foundation, not yet the complete semantic equivalence verifier for Korean scale units, dates, direction, `%` versus `%p`, or currency conversion.
- Modality, terminology, residual Hangul, visual-relation, and executive-claim verifiers remain to be expanded for the translation phase.
- Deterministic final report/executive-brief content generation is currently a completion-contract boundary; richer renderers are next.
- Current-message attachment materialization is not advertised because OpenCode 1.3.9 does not expose a proven safe bridge in this repository.
- The PaddleOCR adapter follows the current 3.x API shape but is not installed or benchmarked in this workspace.

## Next phase

1. Install/execute the optional normalization stack in CI or a managed cloud image and add rendered PDF/PPTX fixture coverage.
2. Complete deck context, terminology, modality, and numeric semantic models.
3. Add the Gemma bounded work-packet prompts and deterministic repair loop.
4. Expand numeric, table, residual-Korean, modality, evidence-linkage, and executive-claim verification.
5. Run v6 baseline, ablations, target-model configuration experiments, bilingual review, and zero-Korean comprehension evaluation.

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
