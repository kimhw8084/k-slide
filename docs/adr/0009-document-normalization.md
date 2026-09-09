# ADR 0009: Provider-independent document normalization

## Decision

Images, PDF pages, and PPTX slides are converted into a common `Document`/`DocumentUnit` model with immutable renders, hashes, dimensions, and native evidence paths. PPTX visual rendering uses a feature-detected headless Office converter; `python-pptx` is extraction-only.

## Reason

Gemma needs consistent visual context, while native evidence is format-specific. Keeping normalization in the engine prevents the model from becoming responsible for filesystem and rendering lifecycle.

## Consequences

Optional dependencies are capability-gated and doctor-visible. A missing renderer blocks visual certification instead of silently producing an incomplete deck.
