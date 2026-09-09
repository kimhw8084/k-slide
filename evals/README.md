# K-Slide evaluation laboratory

The public corpus is synthetic and contains no confidential Samsung material.
It has 100 fixed semantic specifications in dataset version `1.0`, split by a
deterministic per-category 60/20/20 stratification into development (60),
validation (20), and held-out (20). `write_specs` emits an auditable
`splits.json` manifest; held-out membership must not change without a dataset
version bump. The specifications describe actual visual structures rather than
labels: raster/PPTX tables, charts, process diagrams, and compound executive
compositions.

## Artifact corpus

Generate 100 specifications × five supported formats (500 independent
artifact cases):

```bash
PYTHONPATH=src python -m evals.generate_corpus \
  --output /tmp/k-slide-corpus \
  --formats png jpg webp pdf pptx
```

Add the deterministic resolution/degradation matrix with `--all-variants`.
Generation requires a verified Korean-capable font and fails rather than
falling back to tofu/default glyphs.

## Engine evidence tier

Every selected scenario/format runs through its own immutable K-Slide run:

```bash
PYTHONPATH=src python -m evals.run_engine_eval \
  --output /tmp/k-slide-engine \
  --split development \
  --formats png pdf
```

The report separates:

```text
artifact_generation_pass_rate
engine_normalization_pass_rate
evidence_generation_pass_rate
```

and scores EvidenceIR work-unit, region, table, numeric, visual, and media-plan
invariants. It does not score translation quality. PPTX cases require a real
headless LibreOffice capability; a missing capability is reported as blocked,
not as a pass.

## OpenCode protocol and model tiers

The primary production surface is OpenCode, not a direct model call. The
runner executes the real `/k-slide` command through `opencode run --format
json`, normalizes structured events, detects forbidden tools only from actual
tool invocations, proves required image reads before submit, records timeout
diagnostics, and requires a complete K-Slide run before success. A non-Gemma
run is labelled `PROTOCOL_SMOKE_ONLY`:

```bash
PYTHONPATH=src python -m evals.run_model_eval \
  --output /tmp/k-slide-opencode \
  --model ollama/qwen3:14b \
  --mode protocol
```

Quality mode refuses to certify or tune any model other than the approved
`google/gemma-4-31b-it` target. If that endpoint is unavailable, the result
must say `GEMMA QUALITY EVALUATION BLOCKED — TARGET ENDPOINT UNAVAILABLE`.

The corpus-level runner supports split/category filters, formats, repetitions,
configuration manifests, and semantic TranslationPatch/SlideIR scoring. Quality
metrics remain non-authoritative unless every case satisfies the target-model,
OpenCode, media, artifact, and semantic scoring contract.

Heavy LibreOffice/PaddleOCR setup and the secure internal bilingual gold
protocol are documented in `evals/heavy/README.md` and
`private-evals/README.md`. No public CI job sends source material to a model.
