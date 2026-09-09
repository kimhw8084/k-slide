# Evaluation program

The public evaluation assets are synthetic and contain no confidential Samsung material. `scenarios.py` produces 100 deterministic scenario specifications spanning text, modality, financial tables, charts, processes, degradation, prompt-injection data, cross-slide consistency, and state recovery.

Run the fast artifact tier with:

```bash
PYTHONPATH=src python -m evals.run_engine_eval --output /tmp/k-slide-eval --limit 5
```

The runner generates real PNG artifacts and machine-readable gold files. It does not call Gemma, does not certify translation quality, and does not replace a bilingual internal gold set. PDF/PPTX and actual Gemma runs belong to heavyweight approved environments and must record the exact model/runtime/configuration.

Future model evaluation output must include hard metrics for numeric fidelity, modality, tables, coverage, residual Hangul, evidence linkage, and executive claims, plus repeated-run variance and regression comparison against a baseline.
