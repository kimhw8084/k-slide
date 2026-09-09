# K-Slide Production Certification Report

This is an evidence report for the current local certification boundary. It
does not certify K-Slide for production.

## Identity

| Field | Value |
| --- | --- |
| Git SHA | `1539b28` |
| K-Slide version | `0.3.5` |
| Release state | `DEVELOPMENT` |
| OpenCode | `1.3.9` |
| Configured model | `ollama/qwen3:14b` |
| Target model | `google/gemma-4-31b-it` |
| Champion | `UNSET` |
| Public corpus | v1; fingerprints unchanged |

## Executed evidence

### Tests and static checks

- Base interpreter: **105 tests passed, 2 optional dependency skips**.
- Dependency-backed interpreter (`/tmp/k-slide-phase32-venv`): **105 tests passed**.
- `compileall`: **PASS**.
- `git diff --check`: **PASS**.
- Production hardening tests cover redaction, restrictive permissions,
  retention expiry/symlink refusal, support-bundle source exclusion,
  process-group cleanup, production-profile fail-closed behavior, release
  manifest gating, and explicit headless OpenCode permissions.

### OpenCode runtime

- Executable: **PASS** (`1.3.9`).
- Effective config discovery: **PASS**.
- Model inventory: **PASS**; configured Qwen model is visible.
- Provider-specific Ollama CLI check: **NOT AVAILABLE**; OpenCode remains the
  authoritative transport check.
- Pure clean OpenCode inference: **TIMEOUT**, zero structured events.
- Normal clean OpenCode inference: **TIMEOUT**, zero structured events.
- Explicit `ollama/qwen3:14b`: **TIMEOUT**, zero structured events.
- Timeout cleanup: **PASS**; SIGTERM/reap path exercised, with SIGKILL fallback
  tested by unit fixture.
- K-Slide agent and `/k-slide` levels: **NOT REACHED**, correctly skipped after
  the provider-level failure.

Classification: `OPENCODE_PROVIDER_RUNTIME_BLOCKED`.

### Engine corpus

The dependency-backed lightweight run executed **500 cases**:

| Format | Cases | Artifact generation | Evidence/normalization result |
| --- | ---: | ---: | --- |
| PNG | 100 | 100/100 | 80 pass; 20 OCR capability blocks |
| JPEG | 100 | 100/100 | 80 pass; 20 OCR capability blocks |
| WebP | 100 | 100/100 | 80 pass; 20 OCR capability blocks |
| PDF | 100 | 100/100 | 80 pass; 20 OCR capability blocks |
| PPTX | 100 | 100/100 | 100 LibreOffice capability blocks |

Aggregate: **500/500 artifacts generated**, **320/400 raster/PDF cases
completed**, **0 algorithmic failures**, **180 capability blocks**. The 80
image-only financial-table blocks occurred with OCR explicitly pinned to
`none`; the 100 PPTX blocks occurred because LibreOffice is unavailable.

The representative 15-case heavy subset was also attempted with OCR pinned to
`paddle`; all 15 were capability-blocked because PaddleOCR and/or LibreOffice
are unavailable locally. No result was promoted to a heavy-runtime pass.

### Heavy runtime

- Local Docker client: **PRESENT**.
- Docker daemon/build: **BLOCKED**; the configured OrbStack socket does not
  exist.
- Required heavy doctor: **FAIL** locally because LibreOffice, PaddlePaddle,
  PaddleOCR, and base-interpreter PyMuPDF are unavailable.
- Normal doctor: reports those capabilities as **BLOCKED**, not passed.
- Networkless OCR and LibreOffice round trips: **NOT EXECUTED**.
- Full 500-case heavy suite: **NOT EXECUTED**.
- Offline OCR asset manifest: **NOT AVAILABLE**.

### Model quality and production gates

- Gemma identity/vision proof: **NOT RUN**; target endpoint unavailable.
- Gemma development/validation/repeated high-risk/held-out: **NOT RUN**.
- Internal bilingual gold: **NOT RUN**; private corpus and attestations are not
  present.
- Zero-Korean comprehension study: **NOT RUN**.
- Security dependency/secret scans: **NOT RUN**; `pip-audit`, `gitleaks`, and
  `semgrep` are not installed in this workspace.
- Offline SBOM/release-manifest smoke: **PASS** for DEVELOPMENT metadata.
  Certified-state generation correctly returns **BLOCKED** when target model,
  OCR assets, validation/held-out hashes, and attestations are absent.
- Tenant isolation, model-data approval, canary, and production governance:
  **NOT PROVEN**.

## Certification decision

`PRODUCTION_CERTIFIED` and `1.0.0` are **not allowed**. The strongest truthful
state is:

```text
Release: DEVELOPMENT
Dominant blocker: OPENCODE_PROVIDER_RUNTIME_BLOCKED
Secondary blockers: HEAVY_RUNTIME_BLOCKED, GEMMA_ENDPOINT_BLOCKED,
INTERNAL_EVAL_REQUIRED, HUMAN_VALIDATION_REQUIRED, PILOT_REQUIRED
```

## Exact next action

Provision a responding approved OpenCode provider/model in a clean workspace,
start Docker or use the approved heavy runner, execute the required
networkless Paddle/LibreOffice proof, and only then begin the five-case Gemma
harness. No Qwen result may select production configuration or become a
champion.
