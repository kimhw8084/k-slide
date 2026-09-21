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

- K-Slide engine: `0.3.5` Phase 3.5 execution-isolation and heavy-runtime-proof boundary; translation certification remains unclaimed
- Implementation date: 2026-09-09
- Runtime inspected: OpenCode `1.3.9`; local configured model `ollama/qwen3:14b`
- Target model: `google/gemma-4-31b-it`; local runtime is recorded as a compatibility warning and is not certified
- Compatibility: v6 commands and single-agent behavior retained; lifecycle internals now use typed tools, immutable snapshots, a validated multi-work-unit state machine, engine-owned EvidenceIR, structured TranslationPatch submission, document normalization, and deterministic completion
- Evidence boundary: image/PDF/PPTX normalization, native extraction, globally unique work units, deterministic region crops, numeric evidence, semantic enums, deterministic report rendering, source-local semantic scoring, stratified split governance with corpus/held-out fingerprints, per-work-unit structured OpenCode event/media assertions, multi-slide deck scenarios, a reproducible heavy environment definition, and an optional OCR provider abstraction are implemented; full target-model translation certification is not claimed
- No confidential slide content was added to the repository
- Production hardening metadata is evidence-only. `constraints-production.txt` is a candidate lock for the heavy CPU image, not a claim that the listed OCR/LibreOffice/OpenCode versions passed certification in this workspace. OCR model assets are not bundled in the public repository; a managed heavy build must generate and hash its local asset manifest before production use.
- Certification closure uses source-free evidence envelopes bound to a subject Git SHA and deployment fingerprint. The public development SBOM is intentionally incomplete metadata; a certified release must generate a real CycloneDX environment/image SBOM with the approved `cyclonedx-py` tool in a private release environment. No private attestation content or source artifacts belong in this repository.

## Semantic provenance states (KSA-22)

User-facing semantic items use one closed vocabulary: `source_fact`,
`supported_interpretation`, or `unresolved`. The first state is accepted only
when the item cites its engine-owned source ID; interpretations and executive
claims cite current EvidenceIR IDs; unresolved items require a reason and stay
on the unresolved report surface. Geometry, numeric facts, source inventories,
and other engine-owned primitives do not carry model-authored provenance.

Existing 1.0 TranslationPatch and SlideIR artifacts remain readable. Missing
provenance is deterministically adapted to `supported_interpretation`, except
for existing unresolved flags/items, which adapt to `unresolved`; nothing
ambiguous is promoted to `source_fact`. Current EvidenceIR revision and source
ID validation still apply on resume and re-verification.

## Conflict and supersession provenance (KSA-23)

Run-level `CONFLICT_REGISTRY.json` is an optional durable artifact. Its absence
keeps legacy runs readable and is explicitly rendered as “conflict coverage not
assessed”; it is never interpreted as proof that no conflict exists. Each
conflict retains at least two stable assertion references to current canonical
SlideIR and EvidenceIR objects, including document/work-unit/source location,
provenance, exact evidence IDs, source-language context, and rendered English
context. The engine rebuilds those references during verification, so model or
operator-authored replacement text, fabricated evidence, locations, and stale
references are rejected without changing either competing claim.

The only resolving state is an evidence-backed or deterministically configured
authoritative supersession. Unknown authority remains `unresolved`; all
participants remain visible in final and executive reports. Supersession is
metadata about authority, never deletion, normalization, or repair of the
superseded source claim.

## Why v6 is the active baseline

v6 is the latest pack and explicitly identifies itself as the Gemma 4 31B single-agent stable core. Its acceptance laws directly match this project's objective: reconstruct visible tables, preserve visible item counts, explain visual relationships, verify numbers and unresolved regions, and never claim completion without `RUN_COMPLETE.md`.

## Related earlier packs

The earlier source packs remain in the original archive location as historical references and are not mixed into the active implementation:

| Pack | SHA-256 | Role |
| --- | --- | --- |
| v4 | `9594e88ae7f399b583c1724928feb7be303644c930898e587c22197d3b09e8ca` | Earlier multi-agent and visual-extraction design |
| v5 | `2a1d89cf3772153a84963fbe16bd328bffac6d96a0290b4bee696b543f223474` | Earlier richer smart/strict/recovery workflow |
| v6 | `bc7ff0bd0a76fdf781f38bf19c82f545ae58a0db226baf31af554556f93fac00` | Active single-agent stable core |
