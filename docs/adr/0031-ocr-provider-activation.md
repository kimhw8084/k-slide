# ADR 0031 — Activate OCR through one managed provider policy

## Decision

Normal extraction resolves `none`, `paddle`, or `auto` through one provider
factory. Certification runs pin the requested policy and persist the effective
provider and version. `paddle` fails closed when its runtime is unavailable;
`auto` may safely record a `none` fallback for development deployments.

## Consequences

The benchmarked OCR backend is the same backend selected by `/k-slide`. OCR
availability is visible in run metadata and doctor output rather than inferred
from installed packages.
