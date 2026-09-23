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

## Canonical external model-evaluation path

Use the existing `evals.run_model_eval` command with explicit external corpus
inputs. The evaluated manifest determines the role; the required purpose is a
separate explicit input. `--split validation` and `--split held_out` remain
matrix labels consumed by the evidence adapter and do not grant corpus authority.
The candidate profile must already bind the exact complete four-role governed
identity in its `corpus_identity` field. The supplied four-manifest bundle must
match every identity in that field, and `--governed-history` must include each
exact predecessor needed to verify transition lineage.

The approved `--artifact-root` is outside the repository and contains
`cases.json`, local artifacts, and local gold wrappers. A descriptor has this
source-free control shape (paths remain relative and private to the external
root):

```json
{
  "schema_version": "1.0",
  "corpus_set_identity": {"...": "exact evaluated manifest identity"},
  "cases": [
    {
      "item_id": "opaque-case-001",
      "category": "financial_table",
      "protected_group": null,
      "artifacts": {"png": "artifacts/case-001/source.png"},
      "gold_path": "gold/case-001.json"
    }
  ]
}
```

The gold file contains a wrapper with `schema_version`, `case`, and `gold`.
`case` binds `item_id`, role, set ID, version, category, and protected group;
`gold` contains the existing scorer contract (coverage metadata and any
modality, table, chart, process, terminology, prompt-injection, or unresolved
policy fields used by that category). `gold_sha256` hashes the exact wrapper
bytes. `source_sha256` hashes canonical JSON of the complete format-to-byte
hash map: `{"artifacts":{"png":"<sha256 of source.png>"}}`. The runner
checks every listed artifact and the exact gold bytes before it calls
OpenCode. Private paths and gold content are not copied into experiment,
summary, machine-evidence, or operational log records.

Example private representative evaluation:

```bash
PYTHONPATH=src python -m evals.run_model_eval \
  --output /approved/evaluation-runs/private-validation \
  --model google/gemma-4-31b-it \
  --mode quality \
  --split validation \
  --candidate-profile /approved/candidates/production-candidate.yaml \
  --corpus-source governed_external \
  --governed-manifest /approved/manifests/private-representative.json \
  --governed-manifest-bundle /approved/manifests/current-bundle.json \
  --governed-history /approved/manifests/history.json \
  --evaluation-purpose private_evaluation \
  --artifact-root /approved/private-corpus/run-2026-09 \
  --case-descriptor cases.json \
  --formats png pdf \
  --repeats 3
```

Use `--evaluation-purpose comparison` and a frozen high-risk manifest for the
repeated protected-group run. Use `--split held_out`, purpose `promotion`, and
an exact empty `--contamination-report` for sealed held-out. The runner executes
all active descriptor membership; validation and sealed promotion cannot be
reduced by scenario, category, or limit filters. High-risk membership must
cover every protected group and uses at least five repetitions. Set result
directories outside both the public repository and the approved input root.

Frozen high-risk or sealed held-out content changes require a new version with
an exact predecessor identity. Retirements preserve old item IDs and hashes.
Contamination records use opaque IDs, source/gold hashes, and closed reason
codes. Replacements link to the retired item and must have distinct source and
gold fingerprints. A retired or contaminated item cannot be reactivated.
