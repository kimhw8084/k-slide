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

The current package is a prepared development baseline, not a claim that every visual case has already been benchmarked. Add representative fixtures and scored acceptance checks before calling a future iteration production-ready.
