# K-Slide Output Contract

The current code-owned completion policy requires these artifacts before `DONE`:

- `05_executive_brief.md`
- `05_final_report.md`
- `06_verification.md`
- `07_unresolved_items.md`
- `RUN_COMPLETE.md`

The authoritative list is implemented in `src/k_slide/policy.py` and is copied into each run's `ARTIFACT_MANIFEST.json`. This reference is user-facing guidance, not an independent completion authority. Compatibility artifacts such as `RUN_STATE.json`, `RUN_MANIFEST.json`, and `RUN_RECOVERY_GUIDE.md` remain useful diagnostics but are not a second completion contract.
