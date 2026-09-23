# Governed evaluation corpus protocol

This directory is a documented shape only. Do not commit Samsung or other
confidential source material, bilingual gold, transcripts, screenshots, or
rendered output. Repository fixtures must remain synthetic.

`src/k_slide/corpus_governance.py` owns the closed corpus roles, canonical
manifest format, SHA-256 validation, lifecycle transitions, access purposes,
and contamination records. A manifest is canonical UTF-8 JSON followed by one
newline. Its `manifest_fingerprint` is SHA-256 over canonical JSON for every
manifest field except `manifest_fingerprint`; item records are ordered by
opaque `item_id`. Each item contains only `item_id`, `source_sha256`,
`gold_sha256`, lifecycle `state`, and optional `replacement_of` linkage. The
source and gold bytes remain in the approved environment.

The only roles and allowed uses are:

| Role | Lifecycle | Allowed purpose |
| --- | --- | --- |
| `public_synthetic_regression` | `active` / `retired` | `development`, `regression` |
| `private_representative` | `active` / `retired` | `private_evaluation` |
| `frozen_high_risk` | `frozen` / `retired` | `comparison` |
| `sealed_held_out` | `sealed` / `contaminated` / `retired` | `promotion` |

The public corpus's split named `held_out` stays part of
`public_synthetic_regression`; that split name grants no sealed-promotion
authority. A certification-capable candidate binds one source-free set
identity for every role. The identity contains schema version, set ID, role,
version, lifecycle state, manifest fingerprint, total/active item counts,
source-free authority record hash, and access class. It excludes paths, usernames,
timestamps, item text, and filenames.
The legacy `{version, corpus_fingerprint, held_out_fingerprint}` shape remains
readable for public development and regression. It is never expanded into
invented private identities and fails certification completeness until an
approved environment supplies all four validated identities.

An approved internal evaluation environment may keep manifests and evaluation
material outside Git, for example:

```text
private-evals/
  manifests/
  source/
  gold/
  results/
```

Gold review should capture critical facts, numbers, dates, units, commitment
state, table geometry, terminology, visual relationships, and comprehension
questions. Keep the held-out set access-controlled and separate from prompt,
rule, training, or threshold selection. The repository enforces evaluation
purpose and candidate identity; it does not replace company IAM.

Frozen high-risk or sealed held-out content changes require a new version with
an exact predecessor identity. Retirements preserve old item IDs and hashes.
Contamination records use opaque IDs, source/gold hashes, and closed reason
codes. Replacements link to the retired item and must have distinct source and
gold fingerprints. A retired or contaminated item cannot be reactivated.
