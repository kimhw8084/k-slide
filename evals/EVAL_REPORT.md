# K-Slide Phase 3.2 evaluation report

Status: `DEVELOPMENT`

Dataset version `1.0` contains 100 deterministic semantic specifications with
stratified development/validation/held-out splits (60/20/20). The generated
corpus contains actual visual tables, charts, process diagrams, screenshots,
compound executive layouts, and real PPTX structures. It is not a semantic
translation result until an approved model produces a TranslationPatch.

## Artifact generation

Measured in `/tmp/k-slide-phase32-corpus` with the document-capable test
environment:

```text
PNG:   100/100
JPEG:  100/100
WebP:  100/100
PDF:   100/100
PPTX:  100/100
Total: 500/500
```

The verified Korean font was `Apple SD Gothic Neo` (version `21.0d1e6`). The
generator fails instead of falling back to tofu/default glyphs.

## Engine evidence tier

The full 500-case run independently processed each scenario/format through the
K-Slide ingestion and EvidenceIR path:

```text
Artifact generation pass rate: 500/500 (1.000)
Normalization pass rate:        400/500 (0.800)
Evidence generation pass rate:  400/500 (0.800)
PPTX capability blocks:         100/100 (LibreOffice unavailable locally)
Critical failure findings:      300
Failure classes:                CAPABILITY_BLOCK 100; NORMALIZATION_FAILURE 100; TABLE_EXTRACTION_FAILURE 100
```

PNG, JPEG, WebP, and PDF each normalized and generated evidence for 100/100
cases in this environment. The PPTX files were generated successfully, but
visual normalization was correctly classified as
`KSLIDE_PPTX_RENDER_UNAVAILABLE`; a native PPTX-only test is not being claimed
as full visual PPTX coverage.

Engine metrics are qualified evidence metrics, not translation accuracy:

```text
Mean work-unit count: 0.800
Mean region coverage: 0.183
Mean table structure: 0.800
Mean numeric-fact recall: 0.556
Mean visual context: 0.800
Mean context media plan: 0.800
Unique-ID integrity: 1.000
```

The low region/numeric means reflect the current `none` OCR path for raster and
image-only content. They are an evidence-engine improvement target, not a
Gemma failure.

## OpenCode protocol tier

OpenCode `1.3.9` was exercised through the real JSON-event CLI path with the
configured `ollama/qwen3:14b` on one development PNG case. It timed out after
30 seconds before producing a K-Slide run, with zero structured events and no
artifacts. Timeout diagnostics were retained in the case workspace. This is
`PROTOCOL_SMOKE_ONLY`, not a linguistic result.

The event harness now detects forbidden tools and required media reads only
from structured tool events. Prompt text and path strings alone do not count.
Model identity is also non-authoritative unless effective structured/configured
identity is proven.

## Target Gemma status

`google/gemma-4-31b-it` was attempted through the same OpenCode workflow. The
configured runtime is `ollama/qwen3:14b`, and OpenCode returned one structured
error for the requested Gemma model. No TranslationPatch, SlideIR, complete
run, media-read sequence, or semantic model score was produced.

Result:

```text
GEMMA CERTIFICATION BLOCKED — TARGET ENDPOINT UNAVAILABLE
```

No Gemma accuracy, ablation, champion, production-candidate, or comprehension
claim is made.

## Heavy environment status

The reproducible definition is `evals/heavy/Dockerfile`. The local Python
environment self-test passed Pillow, PyMuPDF, python-pptx, and Korean-font
checks, but reported:

```text
LibreOffice: unavailable
PaddlePaddle: unavailable
PaddleOCR: unavailable
Paddle load: blocked
```

The Docker daemon was unavailable in this workspace, so actual LibreOffice and
PaddleOCR integration was not executed locally. The heavy job remains an
explicit manual/workflow-dispatch tier rather than a silently skipped claim.
