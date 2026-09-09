# ADR 0010: OCR provider abstraction

## Decision

OCR is represented by a narrow provider protocol returning text, boxes, confidence, provider identity, and optional layout metadata. `none` is always available; PaddleOCR is an optional local adapter.

## Reason

OCR versions and deployment footprints change faster than the evidence contract. Native text must remain higher-value evidence when trustworthy, while OCR provides candidates for rendered-only content.

## Consequences

Provider selection and thresholds can be benchmarked without changing `EvidenceIR`. The default privacy mode does not transmit source material to external OCR services.
