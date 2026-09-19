# ADR 0044 — Classification admission for the configured inference route

Status: Implemented for CHG-16 / KSA-16 BUILD.  Company policy approval,
model-data attestation, target-Gemma certification, and production release
remain external gates.

K-Slide treats submitted artifacts and content-bearing derivatives as
`company_confidential` when the trusted host supplies no classification.  An
authoritative host/platform label is carried independently with each input;
it is never inferred from a filename, document bytes, model output, or tool
arguments.  OpenCode v1.3.9 `FilePart` has no classification field or
arbitrary metadata bag, and its supported plugin hooks expose no trusted
classification resolver.  Therefore the OpenCode adapter assigns
`company_confidential` to every document and removes model-supplied references,
labels, route, and policy arguments before `kslide_prepare`.  OpenCode cannot
preserve a stronger external label until the deployment supplies a real,
supported trusted metadata/resolver integration that is outside model, tool,
and user control and fails closed per document.

Before source validation, snapshot creation, normalization, extraction, or
EvidenceIR generation, the engine evaluates every document against a
deployment-controlled `InferenceDataUsePolicy`.  The policy binds one exact
inference-route identity, policy version, semantic hash, policy identity, and
exact classification rules.  Unknown, malformed, unresolved, denied, or
mismatched values fail as an operational `FAILED_INPUT` admission failure;
they are not semantic `NEEDS_REVIEW`.  There is no severity ordering and one
document cannot authorize another in a multi-file packet.

The route and policy identities are source-free durable run metadata and are
part of candidate deployment fingerprints and run-environment compatibility.
Policy drift therefore invalidates affected candidate identity and refuses
resume before checkpoint mutation.  A denied run persists only bounded,
source-free admission metadata; it has no immutable source snapshot, render,
crop, EvidenceIR, or model-visible media packet.

The public repository intentionally contains no company production approval.
`InferenceDataUsePolicy.reference()` is an explicit deterministic test
adapter only.  Candidate/runtime-derived production environments require the
deployment policy contract, while external model-data-policy attestation is
kept separate from this repository-side runtime admission check.
