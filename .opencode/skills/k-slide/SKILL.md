---
name: k-slide
description: Understand Korean/Korean+English slide images and generate English-native reports with faithful table reconstruction, item-count preservation, verification, and recovery behavior.
---

# Korean Slide Comprehension Skill v6

## Mission
Make a zero-Korean English reader fully understand a Korean or Korean+English slide image as if the slide were originally written in English.

The product is not a loose summary. It is a faithful English reconstruction plus explanation.

## Default behavior
Default `/k-slide` is single-agent. Do not use Task/subagents in the default workflow.

## Output priority
1. English-native slide reconstruction.
2. Recreated tables and visual structures.
3. Plain-English explanation.
4. Coverage/unresolved summary.
5. Verification result.

## Table Reconstruction Law
If a slide contains a table, the final report must attempt to recreate the same visible table as an English Markdown table. A paragraph summary is not a substitute.

Rules:
- Preserve all visible rows and columns.
- Translate headers and cells into natural English.
- Preserve numbers, dates, units, symbols, percentages exactly.
- If a cell is unreadable, write `[unreadable]`.
- If structure is partially unclear, still make a best-effort table and add a note.

## Cardinality Law
If the source slide has N visible bullets, numbered items, table rows, process boxes, chart labels, or callouts, the output must preserve N or explicitly mark missing/unreadable items. Never silently turn 3 source items into 2 output items.

## Korean business translation law
Use natural business English, not word-for-word awkward English.

Examples:
- `추진` = drive / execute / implement, not usually “promote.”
- `고도화` = enhance / mature / upgrade / capability improvement.
- `전사` = company-wide, not “warrior.”
- `검토 필요` = requires review before decision.
- `대응 방안` = response strategy / mitigation plan.

## `01_slide_understanding.json` contract
Must include status, slides, visible item counts, tables, visual elements, unresolved/unreadable, and confidence.

## `05_final_report.md` contract
Must include:
- Status and confidence
- Input files
- English-native slide reconstruction
- Recreated tables
- Visual/process reconstruction
- Plain-English explanation for a zero-Korean reader
- Important Korean business terms explained
- Coverage summary
- Unresolved/unreadable items

If no table exists, write `No visible table detected.` Do not invent tables.

## `06_verification.md` contract
Must include final status, table reconstruction check, cardinality check, number/date/unit preservation check, unresolved item check, and next action.

Verification must fail if a table is summarized instead of reconstructed, item counts mismatch, rows/columns are dropped without `[unreadable]`, numbers are missing, unresolved text is hidden, or report is summary-only.

## Recovery law
Every unexpected stop must end with a friendly guide:

```text
FAILED or NEEDS REVIEW
Run folder: <RUN_DIR>
Next:
/k-slide-status <RUN_DIR>
/k-slide-continue <RUN_DIR>
If repeated:
/k-slide-doctor
```

Do not display raw tool-call blocks as the final response.
