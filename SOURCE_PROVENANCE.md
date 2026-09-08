# Source provenance

## Active baseline

- Project: K-Slide Korean Slide Comprehension
- Pack: v6 single-agent stable core
- Model target: Gemma 4 31B through OpenCode
- Source archive (workspace-relative): `ai/cli-tools/kor-eng/korean_slide_gemma_opencode_pack_v6.zip`
- SHA-256: `bc7ff0bd0a76fdf781f38bf19c82f545ae58a0db226baf31af554556f93fac00`
- Workspace location: `projects/agent-skills/k-slide`
- Extracted on: 2026-09-08

## Engine evolution

- K-Slide engine: `0.1.0` Phase 1 platform-hardening implementation
- Implementation date: 2026-09-08
- Runtime inspected: OpenCode `1.3.9`; local configured model `ollama/qwen3:14b`
- Target model: `google/gemma-4-31b-it`; local runtime is recorded as a compatibility warning and is not certified
- Compatibility: v6 commands and single-agent behavior retained; lifecycle internals now use typed tools, immutable snapshots, a validated state machine, and deterministic completion
- No confidential slide content was added to the repository

## Why v6 is the active baseline

v6 is the latest pack and explicitly identifies itself as the Gemma 4 31B single-agent stable core. Its acceptance laws directly match this project's objective: reconstruct visible tables, preserve visible item counts, explain visual relationships, verify numbers and unresolved regions, and never claim completion without `RUN_COMPLETE.md`.

## Related earlier packs

The earlier source packs remain in the original archive location as historical references and are not mixed into the active implementation:

| Pack | SHA-256 | Role |
| --- | --- | --- |
| v4 | `9594e88ae7f399b583c1724928feb7be303644c930898e587c22197d3b09e8ca` | Earlier multi-agent and visual-extraction design |
| v5 | `2a1d89cf3772153a84963fbe16bd328bffac6d96a0290b4bee696b543f223474` | Earlier richer smart/strict/recovery workflow |
| v6 | `bc7ff0bd0a76fdf781f38bf19c82f545ae58a0db226baf31af554556f93fac00` | Active single-agent stable core |
