# K-Slide evaluation report

Status: `DEVELOPMENT`

The public corpus contains 100 deterministic semantic specifications with
fixed development/validation/held-out splits and actual visual generators for
tables, charts, process diagrams, screenshots, and compound executive slides.
The corpus generator can produce 500 independent default artifact cases across
PNG, JPEG, WebP, PDF, and PPTX. The engine runner evaluates each requested
scenario/format independently and records EvidenceIR extraction metrics.

Current local capability boundary:

```text
Pillow: available in the verification environment
PyMuPDF: available in the verification environment
python-pptx: available in the verification environment
LibreOffice: unavailable locally, so PPTX visual normalization is blocked
PaddleOCR: unavailable locally
Gemma 4 31B-it endpoint: unavailable
```

Latest measured public runs:

```text
Default corpus generation: 500/500 artifact cases
Held-out degradation matrix smoke: 100/100 PNG cases
Engine all-split run: 300 cases (100 PNG, 100 PDF, 100 PPTX)
Artifact generation pass rate: 1.000
Engine normalization pass rate: 0.667
Evidence generation pass rate: 0.667
Engine critical failures: 260
JPEG/WebP all-split engine run: 200 cases (100 JPEG, 100 WebP)
JPEG/WebP artifact, normalization, and evidence pass rates: 1.000 / 1.000 / 1.000
JPEG/WebP critical failures: 40
```

Mean engine evidence scores in that run were:

```text
work-unit count: 1.000 on normalized cases
region coverage: 0.152
table structure: 0.800
numeric-fact recall: 0.560
visual context: 0.667
context media plan: 0.667
unique IDs: 1.000
```

The 0.667 normalization/evidence rates are expected capability findings in
this machine: PPTX rendering requires LibreOffice, and image/PDF text-region
recall requires OCR/layout support. These figures must not be presented as
translation accuracy.

OpenCode `1.3.9` protocol smoke used the configured `ollama/qwen3:14b` and
timed out before producing a valid K-Slide session result. It is not used for
linguistic tuning. An explicit target-model attempt returned `Model not found:
google/gemma-4-31b-it`, so the result is:
`GEMMA QUALITY EVALUATION BLOCKED — TARGET ENDPOINT UNAVAILABLE`.

No semantic translation accuracy, ablation result, zero-Korean comprehension
score, or production-certification claim is made until the actual Gemma
OpenCode workflow and approved internal gold set are exercised. The local
Qwen runtime may be used only for protocol smoke and cannot tune production
linguistic defaults.
