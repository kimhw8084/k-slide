# KSA-30 zero-Korean employee study protocol and analysis plan

**Protocol/analysis contract:** `1.0`

**Evidence type:** existing `zero_korean_comprehension`

**Shared evidence envelope:** `2.6`

**Execution status for this BUILD:** not executed; no human-study result is claimed.

This specification freezes the later approved-company study. The study measures
whether an English report lets an employee who cannot read Korean understand
the decision-relevant content. It does not measure translation accuracy. The
study may run only in the approved company environment, using cleared material
and the controls below.

## Conditions and eligible participants

The study has exactly two conditions in a randomized, balanced, parallel
design:

1. `kslide_output`: the exact English report produced by the candidate bound
   to the study, with its original Korean artifact withheld.
2. `expert_english_reference`: the human-authored expert-English reference for
   the same report and questions, approved as bilingual-reviewed gold, with
   the original Korean artifact withheld.

Each participant receives one condition only. Both conditions use the same
neutral presentation and do not identify which report is being shown. There is
no Korean-source, untreated, AI-answer, or other study condition. The reference
must be prepared or verified by a qualified human English-language expert and
must be the exact gold artifact in the KSA-29 bilingual review binding.

Recruit employees approved for the study who consent, confirm sufficient
English reading proficiency, confirm they cannot read Korean, and have not
previously accessed the bound report or participated in its preparation or
review. Screen eligibility and consent before randomization. The company
environment keeps screening answers and any participant contact information;
the evidence contains only opaque participant IDs.

An authorized coordinator uses a concealed computer-generated sequence with
permuted blocks of four and a fixed 1:1 allocation. If enrollment stops at the
minimum of 85 per arm, use one final balanced two-person block after 42 full
blocks. Each employee can be randomized once. Do not crossover participants
between conditions. Do not stratify after seeing outcomes or change allocation
after randomization.

## Frozen questions and scoring

Ask the same eight structured questions in the same order for each condition:

| Question identity | Category | Critical |
| --- | --- | --- |
| `q-decision-status-v1` | Decision status | Yes |
| `q-timing-v1` | Timing | Yes |
| `q-key-numbers-v1` | Key numbers | Yes |
| `q-risk-v1` | Risk | Yes |
| `q-dependency-v1` | Dependency | Yes |
| `q-trend-v1` | Trend | No |
| `q-owner-v1` | Owner | No |
| `q-next-step-v1` | Next step | No |

The approved company gold package contains the question wording, expert-English
reference, and human-approved answer key. Its SHA-256 is both the
`question_set_identity` and `expert_english_gold_identity` in source-free
evidence. The KSA-29 binding must also identify the exact candidate output
artifact and reviewed corpus item. Do not place question wording, gold text,
report text, participant answers, or reviewer comments in Git or the evidence
envelope.

Two independent human scorers, blinded to condition and participant identity,
compare each answer with the approved gold using only these outcome codes.
The source-free ledger binds both opaque scorer IDs, their separate record
hashes, authority/basis enums, and scores to the exact participant, question,
condition, candidate, and gold. If scores differ, a distinct human bilingual
adjudicator and exact review references are required; AI scorer or adjudicator
identities fail validation.

- `correct`: matches the approved gold for the question.
- `incorrect_noncritical`: wrong, incomplete, or unsupported, without meeting
  the serious-misleading rule.
- `serious_misleading`: meets rule `SMO-1` below.
- `unanswered`: blank, missing, or unavailable; score it as incorrect (zero).

**SMO-1:** A response is serious misleading if a reasonable employee could be
led to a materially unsafe, unlawful, financially material, operationally
irreversible, or materially wrong decision because it fabricates, reverses, or
materially misstates a source fact. For a critical question, a material error
about decision status, timing, key numbers, risk, or dependency is serious.
Resolve scorer disagreement through a qualified human bilingual adjudicator.
Any serious-misleading outcome in either condition fails the study, regardless
of averages, reference performance, confidence bound, or non-inferiority.
AI-generated answers, scoring, or adjudication cannot replace employees, the
expert-English reference, approved gold, or human adjudicators.

## Population, exclusions, and missing answers

The analysis population is every eligible randomized participant, analyzed in
the assigned condition (intention to treat). Participant is the independent
analysis and sample-size unit. Each participant contributes one score made
from the eight repeated question outcomes; do not count questions as
independent observations. Participants must be independent, each have one
opaque ID, and appear in one condition only. There is no site or group
clustering or cluster adjustment in this plan.

An analyzable participant has exactly one closed outcome code for each of the
eight frozen questions. An `unanswered` code is a valid recorded zero outcome,
not grounds to remove that randomized participant from the analysis.

Only consent decline, failed eligibility, duplicate identity/prior
randomization, prior exposure, or preparation/review involvement may exclude a
person before randomization. No post-randomization participant, answer, or
outlier exclusion is allowed. Emit an `unanswered` outcome for every missing
question and keep that participant in the assigned arm. Do not impute. If
approved consent and company policy do not allow retention of the opaque
assignment and unanswered outcomes after withdrawal, the study cannot qualify.

## Primary endpoint and power plan

For each participant, score each `correct` answer as 1 and every other outcome
as 0; divide the sum by eight. The primary endpoint is the participant-level
mean fraction correct. The comparative effect is
`mean(kslide_output) - mean(expert_english_reference)`.

The frozen absolute non-inferiority margin is **exactly 0.05**. Use a 1:1
allocation and the following power assumptions:

| Assumption | Frozen value |
| --- | ---: |
| One-sided alpha | 0.025 |
| Confidence convention | 97.5% one-sided lower bound (lower endpoint of a two-sided 95% interval) |
| Target power | 0.90 |
| Assumed K-Slide participant-score mean | 0.95 |
| Assumed expert-reference participant-score mean | 0.95 |
| Assumed K-Slide participant-score SD | 0.10 |
| Assumed expert-reference participant-score SD | 0.10 |
| Planning mean difference | 0.00 |
| Non-inferiority margin | **0.05** |
| Analysis unit | One participant-level mean score |
| Sample-size method | Normal-approximation difference-of-independent-means formula |

Use the frozen normal quantiles `z(1-alpha) = 1.959963984540054` and
`z(power) = 1.281551565544600` and calculate the number needed in each arm as:

```text
ceil(((z(1-alpha) + z(power))^2 * (sd_kslide^2 + sd_reference^2))
     / (margin + assumed_mean_difference)^2)
```

The raw per-arm result is `84.0593844915249361179725304`; deterministic ceiling
gives a fixed target of **exactly 85 analyzable participants per arm**. Do not
conduct interim analyses, replace randomized participants, or extend
enrollment based on results. Any target change requires a new protocol before
collecting its results. The study contract recomputes this number from the
frozen assumptions; a declared count cannot override the calculation. The 680
question outcomes in an arm are not 680 independent sample units.

Estimate each arm's sample variance from its participant scores. Calculate the
Welch standard error for the difference of means and subtract
`1.959963984540054 * standard_error` to get the predeclared one-sided lower
bound. Non-inferiority passes only when that lower bound is **strictly greater
than -0.05**. Point estimates alone do not establish non-inferiority. Use exact
integer/rational participant-score arithmetic and 50-digit decimal arithmetic
for the bound; round only displayed rates and bounds to 12 decimal places
using half-up rounding. This makes sample-size and result rounding stable
across Python 3.11 and 3.12.

## Separate absolute safety gates

Apply each floor independently to each condition. Both conditions must have
100% correctness on critical questions, at least 95% overall answer
comprehension, and zero non-correct critical outcomes. Any non-correct outcome
on a critical question counts as a critical misunderstanding. The study also
requires zero `serious_misleading` outcomes across both conditions. Passing
the comparative test cannot compensate for any absolute floor or serious
outcome.

The existing release state and evidence type remain unchanged. The evidence
validator derives arm counts, scores, rates, critical and serious counts,
sample sufficiency, the Welch bound, and the final result from the opaque
participant/question/outcome ledger. It rejects aggregate-only predecessor
attestations and summaries that disagree with the ledger.

## Truth, privacy, and evidence boundary

Before results can qualify, KSA-29 `internal_bilingual` evidence must pass for
the exact candidate. The study authority binds to its attestation and exact
reviewed corpus item, candidate-output artifact hash, expert-English gold
hash, and question-set identity. The gold file must contain the frozen
questions and approved answer key. Human reviewers and the expert-English
reference establish truth; model output, AI scoring, and study participation
do not.

The source-free evidence contains only candidate and protocol hashes, opaque
participant and record hashes, fixed condition/question/outcome codes, the
question/gold hash, and rederived aggregate statistics. It rejects unsupported
fields. Do not persist employee names, emails, user IDs, demographics or free
text, answers, source/gold/reference text, comments, filenames, private paths,
or confidential artifact contents in Git, Fabric evidence, release manifests,
or repository-visible study evidence. The approved company environment keeps
the actual study material and data under company access and retention policy.

## BUILD boundary

This BUILD freezes the contract and validator only. It does not recruit
participants, execute the protocol, create a human-study result, select or
promote a champion, authorize a pilot, release a product, or claim production
certification. Any later execution requires the applicable company approval
and must use the exact candidate and KSA-29 truth authority recorded in its
source-free evidence.
