import {SafeKSlideError} from "./safeError"

export const PHASE_LABELS: Record<string, string> = {
  CREATED: "Preparing", INPUT_VALIDATED: "Files accepted", NORMALIZING: "Preparing pages",
  NORMALIZED: "Pages ready", EXTRACTING: "Reading source", EXTRACTED: "Ready for translation",
  TRANSLATING: "Translating", TRANSLATED: "Ready for verification", VERIFYING: "Verifying",
  FAIL_REPAIRABLE: "Repair needed", REPAIRING: "Repairing", NEEDS_REVIEW: "Needs review",
  VERIFIED: "Finalizing", COMPLETE: "Result saved — verified when opened",
  FAILED_INPUT: "Check input files", FAILED_RUNTIME: "Runtime needs attention",
  FAILED_NORMALIZATION: "Page preparation stopped", FAILED_EXTRACTION: "Source reading stopped",
  FAILED_SCHEMA: "Translation needs attention", FAILED_INTERNAL: "Run stopped",
}

export interface RunInfo {
  runId: string
  phase: string
  progressAvailable: boolean
  updatedAt: string
  inputCount: number
  totalUnits: number
  verifiedUnits: number
  reviewUnits: number
}

export function parseRunList(value: unknown): RunInfo[] {
  const invalid = (): never => { throw new SafeKSlideError("Saved run information is unavailable. Refresh or contact your workspace administrator.") }
  if (!value || typeof value !== "object" || Array.isArray(value)) return invalid()
  const envelope = value as Record<string, unknown>
  if (envelope.schema_version !== "1.0" || !Array.isArray(envelope.runs) || envelope.runs.length > 100) return invalid()
  const seen = new Set<string>()
  return envelope.runs.map((item: unknown) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) return invalid()
    const row = item as Record<string, unknown>
    if (typeof row.run_id !== "string" || !/^k-slide-[A-Za-z0-9_.:-]{1,120}$/.test(row.run_id) || seen.has(row.run_id)) return invalid()
    if (typeof row.phase !== "string" || !Object.hasOwn(PHASE_LABELS, row.phase)) return invalid()
    if (typeof row.progress_available !== "boolean") return invalid()
    if (typeof row.updated_at !== "string" || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:Z|[+-]\d\d:\d\d)$/.test(row.updated_at) || !Number.isFinite(Date.parse(row.updated_at))) return invalid()
    const counts = [row.input_count, row.total_units, row.verified_units, row.review_units]
    if (counts.some((count) => typeof count !== "number" || !Number.isSafeInteger(count) || count < 0)) return invalid()
    if ((row.verified_units as number) + (row.review_units as number) > (row.total_units as number)) return invalid()
    seen.add(row.run_id)
    return {runId: row.run_id, phase: row.phase, progressAvailable: row.progress_available, updatedAt: row.updated_at,
      inputCount: row.input_count as number, totalUnits: row.total_units as number,
      verifiedUnits: row.verified_units as number, reviewUnits: row.review_units as number}
  })
}

export function progressLabel(run: RunInfo): string {
  if (!run.progressAvailable) return "Saved run needs recovery"
  return PHASE_LABELS[run.phase] + (run.totalUnits ? " · " + run.verifiedUnits + "/" + run.totalUnits + " pages verified" : "")
}

const DOCTOR_LABELS = new Set(["K-Slide source tree", "Python runtime", "OpenCode executable", "OpenCode config",
  "Model identity", "Model compatibility", "Vision support", "Image decoder", "PDF extraction/rendering",
  "PPTX extraction", "PPTX rendering", "OCR policy", "Korean OCR", "Writable run directory", "Input validation"])

export function doctorSummary(value: unknown): string[] {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new SafeKSlideError("Runtime diagnostics are unavailable.")
  const record = value as Record<string, unknown>
  if (!["PASS", "WARN", "FAIL"].includes(String(record.overall)) || !Array.isArray(record.checks)) throw new SafeKSlideError("Runtime diagnostics are unavailable.")
  const lines = ["K-Slide runtime checks: " + record.overall, "These checks do not certify a production deployment."]
  for (const row of record.checks) {
    if (row && DOCTOR_LABELS.has(row.label) && ["PASS", "WARN", "FAIL"].includes(row.status)) lines.push(row.status + " · " + row.label)
  }
  lines.push("For warnings or failures, ask your workspace administrator to check the managed runtime. No API key or manual setup is needed from employees.")
  return lines
}
