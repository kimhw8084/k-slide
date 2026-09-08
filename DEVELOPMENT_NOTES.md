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

The current `0.1.0` implementation is the first hardened engine boundary built on that v6 behavior. Phase 1 now owns input validation, immutable snapshots, state transitions, session resolution, typed OpenCode tools, collision-safe installation, runtime/model discovery, and deterministic completion. See [`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md) for the explicit boundary and next task.

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

The package is a prepared development baseline, not a claim that every visual case has already been benchmarked. Phase 2 must add real PDF/PPTX normalization, native evidence, rendering, region crops, OCR adapters, and scored acceptance fixtures before calling a future iteration production-ready.
