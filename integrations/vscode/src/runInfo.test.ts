import assert from "node:assert/strict"
import {test} from "node:test"
import {doctorSummary, parseRunList, progressLabel} from "./runInfo"
import {SafeKSlideError} from "./safeError"

const row = {run_id: "k-slide-run-1", phase: "NEEDS_REVIEW", updated_at: "2026-10-02T00:00:00Z",
  input_count: 1, total_units: 8, verified_units: 6, review_units: 1, progress_available: true}
const envelope = (value: unknown) => ({schema_version: "1.0", runs: [value]})

test("saved progress contains only validated engine fields", () => {
  const result = parseRunList(envelope({...row, source_text: "secret source", AccessKey: "secret credential"}))
  assert.equal(progressLabel(result[0]), "Needs review · 6/8 pages verified")
  assert.doesNotMatch(JSON.stringify(result), /secret/)
  assert.doesNotMatch(progressLabel(parseRunList(envelope({...row, phase: "COMPLETE"}))[0]), /DONE/)
  assert.equal(progressLabel(parseRunList(envelope({...row, progress_available: false}))[0]), "Saved run needs recovery")
})

test("malformed or forged saved runs cannot become navigable UI items", () => {
  for (const replacement of [
    {run_id: "../outside"}, {phase: "SOURCE_SECRET"}, {updated_at: "private source text"},
    {verified_units: 20}, {review_units: -1}, {total_units: NaN}, {input_count: "1"},
  ]) assert.throws(() => parseRunList(envelope({...row, ...replacement})), SafeKSlideError)
  assert.throws(() => parseRunList({schema_version: "1.0", runs: [row, row]}), SafeKSlideError)
})

test("runtime diagnostics never display raw details, credentials or arbitrary labels", () => {
  const summary = doctorSummary({overall: "FAIL", runtime: {AccessKey: "secret"},
    checks: [{label: "Image decoder", status: "FAIL", detail: "secret /private/path"},
      {label: "secret source", status: "FAIL"}]})
  assert(summary.includes("FAIL · Image decoder"))
  assert.doesNotMatch(summary.join("\n"), /secret|private/)
})
