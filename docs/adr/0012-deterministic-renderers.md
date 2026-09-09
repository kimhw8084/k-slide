# ADR 0012: Deterministic report renderers

Status: accepted

Reports are rendered from canonical SlideIR by engine code. Gemma supplies bounded translations and evidence-backed claims, but it does not rewrite the final report. This keeps report structure reproducible and makes stale-artifact verification meaningful.
