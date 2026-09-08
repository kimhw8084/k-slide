# K-Slide v6 Troubleshooting

Run folder not created: approve bash setup or manually run `prepare_run.sh smart <image>`.
Skill says missing: check `SKILL.md` frontmatter.
Raw tool-call text appears: run `/k-slide-doctor`, then `/k-slide-safe`.
Table summarized: run `/k-slide-strict`; this is a verification failure.
Items missing: run `/k-slide-status <run-dir>` and `/k-slide-continue <run-dir>`.
