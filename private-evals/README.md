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

## Bilingual human review and adjudication

KSA-29 uses the existing `internal_bilingual` release evidence type. Its private
review contract is `1.0`; the evidence envelope is `2.6`. Evidence from envelope
`2.5` or earlier is stale and cannot qualify. The release option remains
`--internal-bilingual-attestation`.

The approved environment keeps source files, gold text, translations, comments,
and full reviewer worksheets outside the repository. It emits a source-free
review contract containing only opaque identifiers, hashes, counts, the exact
candidate and corpus bindings, closed outcome codes, and the policy identity.
Do not put reviewer names, source or gold text, output text, comments,
filenames, local paths, model suggestions, or other private content in the
contract or evidence envelope. Use 64-character lowercase SHA-256 values for
reviewer, record, artifact, work-unit, and truth-unit identities. Existing
governed `item_id` values are used unchanged.

The deterministic contract has these top-level fields:

| Field | Required contents |
| --- | --- |
| `schema_version` | `1.0` |
| `subject_git_sha`, `deployment_fingerprint` | Exact release candidate identity |
| `evaluation_purpose` | `private_evaluation` |
| `corpus_set_identity`, `corpus_manifest` | Exact active `private_representative` manifest already bound by the candidate; source and gold are hashes only |
| `policy_identity` | Exact current KSA-27 quality policy record |
| `work_units` | Sorted inventory of reviewed output artifact, governed item, work unit, and decision-critical truth-unit identities |
| `review_records` | Exactly two records for every work unit |
| `adjudication_records` | One record for each truth unit where reviewers disagree; otherwise none |
| `ai_assistance_records` | Optional suggestion provenance with `authority: non_authoritative_assistance` |
| `truth_unit_decisions` | Per-truth-unit agreement/disagreement, exact review references, adjudication reference, and resolved outcome |

Every work-unit inventory entry binds `item_id`, `source_sha256`,
`gold_sha256`, `work_unit_id`, `artifact_id`, `artifact_sha256`, and a sorted
list of `truth_units`. A truth unit has an opaque `truth_unit_id` and exactly
one closed metric code: `critical_business_meaning_errors`,
`critical_numeric_date_unit_errors`, `critical_modality_escalations`,
`critical_table_mapping_errors`, `critical_trend_reversals`,
`unsupported_critical_executive_claims`,
`overall_noncritical_semantic_fidelity`, `unresolved_precision`,
`material_unresolved_recall`, or `locked_terminology`.

Each review record binds the candidate subject and deployment fingerprint,
corpus-set identity hash, purpose, corpus item identity hash, KSA-27 policy
identity hash, output artifact, and work unit. It contains an opaque reviewer
identity, a distinct review-record identity and review-artifact identity,
their hashes, and one `correct` or `incorrect` outcome for every listed truth
unit. `reviewer_kind` is `independent_bilingual_human`,
`decision_authority` is `human_review`, and `decision_basis` is
`direct_source_gold_comparison`. Free-form role labels do not establish
independence. Review-record, reviewer-pair, and review-artifact identities
must be unique where the contract requires them; copied or replayed records
fail validation.

`review_record_sha256`, `adjudication_record_sha256`, and
`assistance_record_sha256` are the SHA-256 of canonical JSON for that record
with its own digest field omitted. Lists are sorted by their opaque identity;
all JSON is UTF-8 and uses sorted keys. The evidence builder derives the
attestation ID as the SHA-256 of the complete canonical review contract.

For a disagreement, the separate adjudication record binds the same candidate,
corpus item, policy, artifact, work unit, and truth unit. It cites the exact
two `review_record_id` and `review_record_sha256` pairs. Its closed
`resolution_outcome` is `correct` or `incorrect`, `adjudicator_kind` is
`human_bilingual_adjudicator`, and `decision_authority` is
`human_adjudication`. Missing, unresolved, extra, or unrelated adjudication
records block evidence. Summary metrics cannot override the per-unit ledger.

AI assistance may appear only as a separately hashed suggestion record with
`authority: non_authoritative_assistance` and one of
`translation_suggestion`, `terminology_suggestion`, or
`comparison_suggestion`. It references a human review record and carries no
outcome. AI-only review records and AI adjudication are not valid contract
records and cannot establish authoritative truth.

The private producer should construct the source-free contract after checking
the exact manifest membership and then use the shared deterministic builder
and the normal certification evidence writer:

```python
from k_slide.bilingual_adjudication import build_internal_bilingual_payload
from k_slide.certification import write_evidence

payload = build_internal_bilingual_payload(source_free_review_contract)
write_evidence(
    evidence_path,
    evidence_type="internal_bilingual",
    subject_git_sha=candidate["subject_git_sha"],
    deployment_fingerprint=deployment_fingerprint,
    payload=payload,
    generated_at=generated_at,
    candidate_spec=candidate,
)
```

The builder requires at least 50 distinct output artifact identities and 200
work units, two independent human reviews for each work unit, coverage of every
closed metric category, and adjudication of every disagreement. It derives all
existing bilingual counts and rates from resolved truth-unit outcomes, then
applies the unchanged KSA-27.2 thresholds and KSA-27 hard-gate registry.
Submit the resulting envelope through the existing release option; do not
replace it with aggregate-only fields.

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
