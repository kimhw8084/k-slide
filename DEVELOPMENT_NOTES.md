# Development notes

This project is the active foundation for a Korean-to-English slide comprehension skill. The intended reader cannot read Korean and should be able to understand the slide's content, structure, numbers, and visual meaning from the English output alone.

## Current foundation

The v6 package already provides:

- `/k-slide` as the main OpenCode command.
- A single-agent orchestrator designed for Gemma 4 31B.
- English-native reconstruction before explanation or summary.
- Mandatory Markdown table reconstruction with row and column preservation.
- Visible-item cardinality checks for bullets, process boxes, chart labels, and callouts.
- Verification and recovery artifacts, including an explicit completion sentinel.
- Smart, strict, safe, continue, status, audit, doctor, and help commands.

The current `0.3.5` implementation extends that foundation through the Phase 3.5 execution-isolation and heavy-runtime-proof boundary. The engine owns input validation, immutable snapshots, globally unique work units, state transitions, session resolution, typed OpenCode tools, collision-safe installation, runtime/model discovery, deterministic reports/completion, document normalization, native evidence, configured OCR selection, region crops, numeric evidence, semantic enums, termbase loading, and source-bound visual evidence. The evaluation lab now uses isolated clean/project OpenCode workspaces, shared process-group cleanup, fail-closed OCR configuration, host-persisted heavy outputs, required heavy-mode gates, local PaddleOCR asset prefetch configuration, and stricter multi-unit deck completion contracts. Gemma receives only bounded EvidenceIR packets and returns a strict TranslationPatch; it does not author source evidence. See [`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md) for the tested boundary and next task.

## Acceptance focus for future iterations

Every change should be evaluated against these reader outcomes:

| Content type | Reader must receive |
| --- | --- |
| Simple text slide | Natural English reconstruction and clear takeaway |
| Dense table | Same visible rows and columns, translated cells, preserved numbers, units, dates, and symbols |
| Chart or graphic | Titles, axes, legends, labels, trends, comparisons, and the meaning of the visual relationship |
| Image or diagram | What is shown, why it matters, labels or embedded text, and any uncertainty |
| Mixed Korean/English slide | Consistent terminology and explanations of important Korean business terms |
| Unreadable or ambiguous region | Explicit `[unreadable]` or unresolved notation instead of invented content |

The package is a prepared development baseline, not a claim that every visual case has already been benchmarked. The public corpus has 100 deterministic synthetic specifications and an artifact smoke runner. Target Gemma evaluation, internal bilingual review, and production certification remain future work.

## Production-certification hardening boundary

The 0.3.5 hardening pass keeps the release in `DEVELOPMENT`. It adds explicit
headless-dangerous permission denials, redacted diagnostics, restrictive run
artifact modes, fail-closed retention cleanup, a source-free support bundle,
production profile/doctor checks, provisional SLO/constraints metadata, and a
manual release-evidence workflow. These controls do not substitute for the
unavailable local OpenCode provider, LibreOffice/Paddle heavy runtime, target
Gemma endpoint, private bilingual gold, human comprehension study, tenant
isolation attestation, or canary evidence.

Current dominant blocker: `OPENCODE_PROVIDER_RUNTIME_BLOCKED`. OpenCode 1.3.9
passes executable/config/model-inventory discovery but pure and normal clean
Qwen runs time out with zero structured events. Docker is also unavailable in
the local environment, so heavy runtime results remain unexecuted rather than
being inferred from the Dockerfile.

The final repository-side certification micro-closure requires reliability
evidence to contain explicit timeout-recovery, resume, concurrency, 50-slide,
and SLO proof fields. High-risk model evidence now evaluates every declared
and observed scenario/format repeated group under the protected-category
policy, without best-format selection. Validation and held-out evidence
require locked terminology recall of at least 0.995 and zero unexpected
unresolved rate. Security scanner exit codes are captured structurally by the
workflow; failed scanners or missing reports cannot be normalized into clean
evidence. Base and dependency-backed suites both executed with 134 passing
tests during this closure; external OpenCode, heavy, Gemma, private, human,
governance, and pilot gates remain unexecuted or blocked.
