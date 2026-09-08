# K-Slide v6 — Korean Slide Comprehension for OpenCode + Gemma 4 31B

v6 is the **single-agent stable core** release.

## Quick start

```bash
cd k-slide
./scripts/install_project.sh /path/to/your/project
./scripts/verify_install.sh /path/to/your/project
cd /path/to/your/project
opencode
```

Put images in:

```text
.k-slide-input/
```

Run:

```text
/k-slide
```

Or pass a file directly:

```text
/k-slide imgs/slide-001.png
```

Open:

```text
.k-slide-runs/<run-id>/05_final_report.md
```

## Commands

```text
/k-slide                 main smart single-agent workflow
/k-slide-strict          stricter table/item/audit workflow
/k-slide-safe            fallback for fragile tool-call environments
/k-slide-continue        resume a run
/k-slide-status          show run status and next command
/k-slide-doctor          install and file-tool diagnostics
/k-slide-audit           generate detailed audit artifacts
/k-slide-help            quick help
```

## Complete run

A complete normal run must have:

```text
RUN_COMPLETE.md
01_slide_understanding.json
05_final_report.md
06_verification.md
```

If `RUN_COMPLETE.md` is missing, the run is not complete.

## Important v6 behavior

- Default `/k-slide` denies Task/subagent delegation.
- Tables must be recreated as Markdown tables, not summarized.
- Visible item counts must match; 3 source items cannot become 2 output items.
- If `/k-slide` does not create a run folder, approve the bash setup command or run manually:

```bash
.opencode/skills/k-slide/bin/prepare_run.sh smart imgs/slide.png
```

Then:

```text
/k-slide-continue .k-slide-runs/<printed-run-id>
```

## Troubleshooting

If the skill folder exists but OpenCode says skill is missing, check that `SKILL.md` starts with:

```text
---
name: k-slide
description: ...
---
```

If raw `<|tool_call|>` or `call:task` appears, run:

```text
/k-slide-status .k-slide-runs/<run-id>
/k-slide-doctor
/k-slide-safe path/to/image.png
```

For OpenCode debug logs:

```bash
opencode --log-level DEBUG
```

Common log location:

```text
~/.local/share/opencode/log/
```
