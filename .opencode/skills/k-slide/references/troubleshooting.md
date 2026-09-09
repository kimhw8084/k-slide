# K-Slide Troubleshooting

Run folder not created: run `/k-slide-doctor`, then retry `/k-slide`. Normal users should not run setup scripts manually.
Skill says missing: check `SKILL.md` frontmatter.
Raw tool-call text appears: run `/k-slide-doctor`, then `/k-slide-safe`.
Table summarized: run `/k-slide-strict`; this is a verification failure.
Items missing: run `/k-slide-status <run-dir>` and `/k-slide-continue <run-dir>`.
