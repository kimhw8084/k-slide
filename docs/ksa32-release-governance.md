# KSA-32 release-governance evidence

KSA-32 keeps `governance` as the existing machine evidence type and does not
add a release state. The closed evidence contract is version `1.2`; the
governance policy remains version `1.1` with unchanged release-gate behavior.
Their identities are pinned in `src/k_slide/release_governance.py` and the
matching candidate policy is `security/release-governance-policy.json`.
Evidence loading replays the derivation from the raw snapshot roles and
requires the exact candidate specification, deployment fingerprint, current
`main` head, and merged PR subject.

The normal PR check policy is exactly `test (3.11)`, `test (3.12)`, `security`,
`fast (3.11)`, and `fast (3.12)`. Each is bound to its repository workflow path,
workflow name, job name, and GitHub Actions app ID `15368` (`github-actions`).
The selected job must be successful in the latest attempt of an exact
`pull_request` run whose head matches the governed PR. GitHub may return an
empty `workflow_run.pull_requests` array for a real PR event, so that array is
not treated as proof that no PR exists. A separate authoritative
`GET /repos/{owner}/{repo}/commits/{head_sha}/pulls` snapshot must be complete
and contain the requested PR exactly once. The PR number, immutable PR ID,
head SHA/ref and repository, and base branch and repository are rechecked
against the separately captured exact PR object during evidence derivation.
Other historical PR associations are allowed when the requested PR remains
unique and consistent. A populated workflow-run association is additional
consistency evidence and fails if it names a different PR or head.

Push-triggered runs for the same SHA remain visible in the raw snapshot but
cannot satisfy the PR gate or make its result ambiguous. Two eligible current
PR runs for one context fail closed. `heavy` remains a manual/dispatch-only
job and is not a normal PR requirement.

The raw `workflow_run_provenance.json` snapshot records the complete workflow
catalog, repository-owned workflow IDs and paths, every workflow run returned
for the exact head SHA, its event and PR associations, its latest run attempt,
and normalized jobs joined to their check-run IDs and app identities. The raw
`head_commit_pull_requests.json` snapshot records every page of the exact-head
commit-to-pulls API as a closed set of PR IDs, numbers, repository identities,
branches, and head SHAs. The source-free governance payload includes a
deterministic identity hash of this normalized association snapshot; it stores
no PR descriptions, titles, URLs, API response bodies, job logs, or review
text. GitHub documents this endpoint as a paginated array with up to 100 items
per page; capture continues through the first short page ([REST API docs](https://docs.github.com/en/rest/commits/commits#list-pull-requests-associated-with-a-commit)).

The effective protection may be a set of active repository rulesets or
authoritative legacy branch-protection detail. Rulesets must apply exactly to
`refs/heads/main`, have active enforcement, and collectively require PR review,
at least one approval, code-owner review, stale-review dismissal, approval
after the latest push, strict required checks, conversation resolution,
non-fast-forward prevention, and deletion prevention. Bypass actors fail. A
legacy response must prove those controls, strict check/app bindings, and
admin enforcement. A 401, 403, or 404 is an unavailable legacy response; it
does not qualify without sufficient ruleset facts.

The candidate CODEOWNERS blob and this policy blob are read from the exact
merge commit and checked against their Git object identities. The policy's
production-sensitive path classes must all be covered. The current eligible
code owner is the existing repository owner `@kimhw8084`; no other user or team
is declared. A PR that changes a sensitive path needs an independent current
head approval from each effective owner group. An owner-authored PR therefore
cannot use the same owner as its qualifying reviewer.

## Authorized manual capture

The dispatch-only workflow is
`.github/workflows/k-slide-governance.yml`. It does not run on pushes or pull
requests. Configure the repository Actions secret
`KSLIDE_GOVERNANCE_READ_TOKEN` with a read-only credential that can read
repository metadata, contents, pull requests/reviews/files, check runs,
workflow runs/jobs/workflows, repository rulesets, and legacy branch-protection
detail (`Administration: read` for the latter endpoints). The workflow exits before capture if the
secret is absent. The token stays in the process environment and is never
written to an artifact.

Dispatch the workflow on the exact current `main` merge commit and enter that
merged PR number. The capture tool requests only the fields needed for
derivation. It omits review bodies, comments, PR descriptions, check output,
and credentials. The sanitized `evidence.json` and status record are uploaded
for 90 days. Minimal rederivation snapshots are uploaded as a separate
90-day artifact. To revalidate, download both artifacts into the same
directory so the raw JSON filenames sit beside `evidence.json`, then call
`load_evidence` with the exact subject and candidate specification. A
`NOT_QUALIFIED` status record is diagnostic only and cannot satisfy release
loading.

## Live repository status supplied for this BUILD

The observed main branch reports `protected=false`; the repository ruleset
collection is empty; the connected App receives GitHub 403 when reading the
legacy protection detail; and PR #31 has zero reviews. Its accepted head had
successful checks named `test (3.11)`, `test (3.12)`, `security`, `fast
(3.11)`, and `fast (3.12)`. The three observed required workflow runs report
`pull_requests: []`; the separately supplied commit-to-pulls observation
associates the exact head with PR #31. `heavy` was skipped on the normal PR
path. These facts leave the repository **NOT QUALIFIED** until protection
settings and independent review are actually present and a fresh evidence
capture passes. Fabric did not change GitHub administration or reviewer
assignments.
