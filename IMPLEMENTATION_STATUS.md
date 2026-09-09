# K-Slide Implementation Status

## Current boundary

**K-Slide 0.3.0 — Phase 2.1 translation-ready evidence boundary and Phase 3 development infrastructure.**

The repository now has a coherent, tested boundary from validated immutable input through normalized document units, native evidence, deterministic crops, bounded multimodal packets, deterministic reports, and synthetic evaluation artifacts. It remains `DEVELOPMENT`: the local runtime is `ollama/qwen3:14b`, not the target `google/gemma-4-31b-it`, and no production translation gate has been certified.

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
- Closed commitment/speech/claim/uncertainty enums, engine-owned numeric linkage, Korean scale and `%p` semantic checks, residual-Hangul and locked-term verification foundations.
- Deterministic final report, executive brief, and unresolved-item renderers generated from SlideIR.
- Explicit whole-unit context-image/risk-crop media plan and bounded model prompt contract.
- 100 synthetic scenario specifications and a real-image artifact smoke runner; no model-quality claim is made from this tier.
- Black-box CLI, installer regression, trust-model, queue/resume, concurrency, stale-evidence, stale-finalization, and normalization fixture tests.
- GitHub Actions workflow for Python 3.11/3.12, unit tests, compile checks, CLI/installer checks, and doctor.

## Verification performed locally

```text
PYTHONPATH=src python3 -m unittest discover -s tests -v: PASS (33 tests, 5 optional skips in the base interpreter)
PYTHONPATH=src /tmp/k-slide-verify/bin/python -m unittest discover -s tests -v: PASS (33 tests; image/PDF/PPTX fixtures and multi-input evidence exercised)
PYTHONPATH=src /tmp/k-slide-verify/bin/python -m evals.run_engine_eval --output /tmp/k-slide-eval --limit 5 --formats png jpg webp pdf pptx: PASS (100 specs available; 5 cases generated in all five formats; normalization + EvidenceIR extraction passed; artifact hard-pass rate 1.0)
OpenCode: 1.3.9
Configured model: ollama/qwen3:14b
Model compatibility: different_model_warning
```

The optional skips require image/PDF/PPTX packages in the base interpreter; the temporary verification environment exercised them. The CI workflow installs the development/document extras, while LibreOffice and PaddleOCR remain capability-gated integration paths. No target-model session or Gemma production evaluation was available locally.

## Known limitations

- Full target Gemma translation, repair quality, and zero-Korean comprehension evaluation are not yet measured.
- The base local interpreter does not have all optional document/OCR runtimes; doctor reports proven capabilities rather than pretending they pass.
- LibreOffice-rendered PPTX and PaddleOCR 3 integration are not exercised in this workspace.
- The model-facing OpenCode flow is contract-ready, but no Gemma endpoint is available locally; no Gemma accuracy or comprehension result is reported.
- Numeric/modality/terminology verifiers are deterministic foundations, not a substitute for bilingual gold review.
- Current-message attachment materialization is not advertised because OpenCode 1.3.9 does not expose a proven safe bridge in this repository.
- The PaddleOCR adapter follows the current 3.x API shape but is not installed or benchmarked in this workspace.

## Next phase

1. Execute LibreOffice/PaddleOCR integration in a managed environment.
2. Connect the approved Gemma 4 31B-it endpoint through the bounded OpenCode workflow.
3. Run v6 baseline, ablations, repeated target-model tests, bilingual review, and zero-Korean comprehension evaluation.
4. Promote a configuration only when hard critical-error gates and regression rules pass.

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
