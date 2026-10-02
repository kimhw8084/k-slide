# Approved production implementation

All 78 items in `approved-plan.json` were approved by the user on 2026-10-01.
`status.json` retains the exact approval and tracks each item independently.
Approval is permission to implement; it is not production certification.

Base: `9089cd8415d16402efe5ac561e936540a22a6c19`.
Branch: `codex/k-slide-production-implementation`.
The original checkout was preserved. Existing VS Code / Decision View work
from `8409d5ece97cfdb450a6fa29a3ebb9113896fbb5` was reviewed and reused in
`59d64b8`; it is not claimed as new work or independent acceptance.

## Implemented changes

| Approved IDs | Change | Evidence |
|---|---|---|
| CORE-01 | Durable approval and per-item execution record | This directory |
| RUN-01, QA-01 | Managed workers reject implicit reference engines and reference job services. A COMPLETE checkpoint cannot establish DONE without locked finalization of the authorized run. Replayed DONE rechecks artifacts. Production verification requires current retained patches. | `tests/test_production_worker.py` |
| EVD-02, EVD-03, EVD-05, QA-01 | Ruled PNG/PDF tables are reconstructed from engine-owned pixels. Blank cells, rectangular merges, and cell evidence references survive extraction. Ink without a trustworthy literal becomes an explicit review obligation. PDF spans preserve cell boundaries; OCR can supplement uncovered native regions. | `tests/test_raster_tables.py` |
| UX-01–04, UX-08–09, HOST-01–03, OPT-01 | Shared deterministic Decision View, escaped HTML, native VS Code presentation, faithful table grid, evidence disclosures, review warnings, responsive themes and print CSS. | `tests/test_decision_view.py`, `tests/test_result_html.py`, VS Code compile/tests |
| HOST-05, RUN-06, SEC-08 | Both host subprocess boundaries drain concurrent pipes, bound output, time out, propagate cancellation, terminate process groups, and suppress raw diagnostics. Source-bearing JSON uses stdin. | VS Code `process.test.ts`, OpenCode host regression suite, Python security/contract tests |
| HOST-04, REL-02 | Pinned VS Code package build and clean package verification; inherited collision-safe installation and CI host gate | `scripts/verify_vscode_extension.sh`, installer tests |

## Employee use

Use the existing `/k-slide` command in OpenCode. The same single visible agent
continues to use only typed `kslide_*` tools. After translation or a review
stop, `/k-slide-view` returns the shared result descriptor. Open the descriptor's
`html_path` when the host supports HTML; Markdown and JSON remain available.

In a trusted VS Code workspace, use **K-Slide: Run on Current File** or select
files through **K-Slide: Run on Selected Files**. Preparation is cancellable.
**K-Slide: Open Decision View** presents the engine-generated HTML in a
script-disabled webview. Source files remain confined to the selected run.
Preparation alone does not translate a document or certify completion.
The company's translation-agent bridge and managed execution binding still
need deployment integration.

The HTML file can also be opened locally without a server. Keep it with its
run directory so relative evidence images remain available. Browser Print
provides the printable layout. Treat exports under company classification and
retention policy; export does not create a new approval or certification.

## Managed worker contract

Production startup requires `--engine-factory module:factory` and
`--service-factory module:factory`, the immutable environment identity, and
authorized user/workspace references. Factories are deployment-owned startup
configuration, never document/model inputs. The service factory receives
`scope_context` and `runtime_identity`; it must implement the existing scoped
job-service protocol and derive authorization from the company platform.

The engine factory returns an existing `WorkerEngine` binding plus
`run_directory(job) -> Path`. This resolver must open only the claimed run's
authorized durable artifact directory. It must never derive a path from source
document instructions. The worker checks run identity and invokes
`finalize_run(..., require_patches=True)` before returning DONE.

Reference execution requires `--reference-mode --service-root PATH` and cannot
be combined with a company scope or service factory. Reference checkpoints and
reference service tests do not prove managed translation, transport, or storage.

Cancellation of a host invocation terminates its local process group. This is
separate from canceling a previously dispatched durable company job; the latter
still requires the deployed job-service cancellation path and qualification.

## Compatibility

Completion policy 2.1 includes `05_decision_view.html`. The presentation v1
schema adds optional `html_path` and `decision_view_html` hash fields. Current
rendering emits them; old consumers can continue using `path` (Markdown).
Old retained presentations need re-rendering and verification before this
candidate will accept them as current. No historical evidence is rewritten as
part of installation. No input, EvidenceIR, or TranslationPatch schema changes
were introduced by the table detector.

## Remaining boundaries

- Ruled-grid detection is conservative, not a complete table-layout engine.
  Borderless, rotated, very low-contrast and ambiguous tables still need an
  approved layout provider and representative corpus qualification. Unknown
  detected geometry blocks completion; universal whole-page recall is not proven.
- Production OCR, exact Gemma inference, durable job transport, authorization,
  data-use approval, retention and legal hold, egress, telemetry, recovery,
  human studies, pilot and release gates require real company bindings/evidence.
  These are not replaced with test fixtures or a public substitute service.
- Full host journeys, accessibility evaluation with assistive technologies,
  and dense print/page-break inspection remain open. Mac browser controls were
  unavailable during this implementation session; automated structure/security
  checks do not substitute for visual inspection.
- Main is now protected with five required checks (Python and security), one code-owner PR
  approval, stale-review dismissal, last-push approval, resolved conversations,
  administrator enforcement, and no force pushes/deletions. GitHub currently
  lists only `kimhw8084`; a legitimate independent reviewer must be assigned
  before a compliant merge. No reviewer identity is fabricated. No production-ready status,
  champion promotion, or deployment is claimed.
- Caching (OPT-03) and an administrator view (OPT-04) retain their approved
  measurement/pilot prerequisites. Approval does not remove those conditions.

The [Notion production contract](https://www.notion.so/3d9c564c8d04818a9251f1724340b1fb),
refreshed in this session (last edited 2026-09-29), still distinguishes
repository build acceptance from exact company production qualification.
