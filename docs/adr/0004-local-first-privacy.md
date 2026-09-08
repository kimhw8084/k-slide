# ADR 0004: Local-First Privacy

## Decision

K-Slide defaults to local processing and does not send source material to external OCR, search, or web services. External providers require explicit future policy and configuration work.

## Alternatives

Use hosted OCR or web lookup as an implicit fallback.

## Reason

Business slides may contain confidential company information. An instruction embedded in a slide must never cause exfiltration.

## Consequences

Managed deployments may need heavier local PDF/PPTX/OCR dependencies. Doctor must report capability gaps clearly instead of silently switching privacy posture.
