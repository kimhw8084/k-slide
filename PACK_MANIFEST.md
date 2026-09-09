# Historical V6 Source Pack Manifest

This file describes the imported v6 source pack. It is historical provenance, not the current K-Slide runtime contract. Current behavior is defined by the Python engine, typed OpenCode tools, `AGENTS.md`, and `IMPLEMENTATION_STATUS.md`.

Version: v6 single-agent stable core

Changes from v5:
- `/k-slide` remains the main command.
- Default workflow uses only the `k-slide` agent.
- Task/subagent delegation is denied by default.
- The historical pack allowed a shell setup fallback; the current runtime owns setup through typed tools and does not require model shell execution.
- Valid skill frontmatter included.
- Table reconstruction mandatory.
- Item-count preservation mandatory.
- Final report reconstruction before summary.
- Full audit files are lazy/optional.
