import { tool } from "@opencode-ai/plugin"
import path from "node:path"
import { existsSync } from "node:fs"
import { trustedAccessKey } from "../internal/lib/k-slide-access-key.ts"

type ToolContext = {
  sessionID: string
  messageID?: string
  directory: string
  worktree: string
}

const hostInputReference = tool.schema.object({
  source_kind: tool.schema.enum(["attachment", "workspace_file"]),
  logical_name: tool.schema.string(),
  locator: tool.schema.string(),
}).strict()

const hangulRetention = tool.schema.object({
  reason: tool.schema.string(),
  evidence_id: tool.schema.string(),
}).strict()

const translationRegion = tool.schema.object({
  region_id: tool.schema.string(),
  english: tool.schema.string(),
  commitment_status: tool.schema.enum(["decided", "committed", "planned", "scheduled", "target", "proposed", "under_review", "needs_review", "discussion_required", "expected", "forecast", "possible", "tentative", "not_decided", "completed", "in_progress", "unknown"]).optional(),
  speech_act: tool.schema.enum(["fact", "status", "decision", "plan", "request", "recommendation", "risk", "dependency", "forecast", "question", "unknown"]).optional(),
  term_ids: tool.schema.array(tool.schema.string()),
  unresolved: tool.schema.boolean(),
  unresolved_reason: tool.schema.string().optional(),
  hangul_retention: hangulRetention.optional(),
  provenance: tool.schema.enum(["source_fact", "supported_interpretation", "unresolved"]).optional(),
  evidence_ids: tool.schema.array(tool.schema.string()).optional(),
}).strict()

const translationCell = tool.schema.object({
  cell_id: tool.schema.string(),
  english: tool.schema.string(),
  unresolved: tool.schema.boolean(),
  unresolved_reason: tool.schema.string().optional(),
  hangul_retention: hangulRetention.optional(),
  provenance: tool.schema.enum(["source_fact", "supported_interpretation", "unresolved"]).optional(),
  evidence_ids: tool.schema.array(tool.schema.string()).optional(),
}).strict()

const translationTable = tool.schema.object({
  table_id: tool.schema.string(),
  cells: tool.schema.array(translationCell),
}).strict()

const chartClaim = tool.schema.object({
  chart_element_id: tool.schema.string(),
  kind: tool.schema.enum(["trend", "value", "ranking", "comparison"]),
  series_index: tool.schema.number(),
  series_name: tool.schema.string(),
  point_index: tool.schema.number().optional(),
  category: tool.schema.string().optional(),
  value: tool.schema.number().optional(),
  direction: tool.schema.enum(["increasing", "decreasing", "flat"]).optional(),
  ranking: tool.schema.enum(["highest", "lowest"]).optional(),
  rank: tool.schema.number().optional(),
  other_series_index: tool.schema.number().optional(),
  other_series_name: tool.schema.string().optional(),
  operator: tool.schema.enum(["greater_than", "less_than", "equal_to"]).optional(),
}).strict()

const visualInterpretation = tool.schema.object({
  relation_id: tool.schema.string(),
  interpretation: tool.schema.string(),
  evidence_ids: tool.schema.array(tool.schema.string()),
  source_element_ids: tool.schema.array(tool.schema.string()).optional(),
  relation_type: tool.schema.enum(["next", "depends_on", "contains", "before", "after", "causes", "mitigates", "compares_to", "part_of", "flows_to", "highlights", "other"]).optional(),
  direction: tool.schema.enum(["left_to_right", "right_to_left", "top_to_bottom", "bottom_to_top", "bidirectional", "none", "unknown"]).optional(),
  chart_claim: chartClaim.optional(),
  hangul_retention: hangulRetention.optional(),
  provenance: tool.schema.enum(["source_fact", "supported_interpretation", "unresolved"]).optional(),
  unresolved_reason: tool.schema.string().optional(),
}).strict()

const executiveClaim = tool.schema.object({
  claim_id: tool.schema.string(),
  kind: tool.schema.enum(["takeaway", "decision_status", "decision_or_ask", "timing", "key_number", "risk", "dependency", "owner", "trend", "next_step", "other"]),
  text: tool.schema.string(),
  evidence_ids: tool.schema.array(tool.schema.string()),
  uncertainty: tool.schema.enum(["low", "medium", "high"]),
  hangul_retention: hangulRetention.optional(),
  provenance: tool.schema.enum(["source_fact", "supported_interpretation", "unresolved"]).optional(),
  unresolved_reason: tool.schema.string().optional(),
}).strict()

const translationPatch = tool.schema.object({
  schema_version: tool.schema.enum(["1.0"]),
  work_unit_id: tool.schema.string(),
  evidence_revision: tool.schema.string(),
  regions: tool.schema.array(translationRegion),
  tables: tool.schema.array(translationTable),
  visual_interpretations: tool.schema.array(visualInterpretation),
  executive_claims: tool.schema.array(executiveClaim),
  repair_revision: tool.schema.string().optional(),
}).strict()

const conflictAssertionReference = tool.schema.object({
  work_unit_id: tool.schema.string(),
  semantic_kind: tool.schema.enum(["region", "table_cell", "visual_relation", "executive_claim", "numeric_fact"]),
  semantic_id: tool.schema.string(),
}).strict()

const conflictAssessment = tool.schema.object({
  schema_version: tool.schema.enum(["1.0"]),
  candidate_groups: tool.schema.array(tool.schema.object({
    assertions: tool.schema.array(conflictAssertionReference),
  }).strict()).default([]),
}).strict()

const authorityEvidenceInput = tool.schema.object({
  work_unit_id: tool.schema.string(),
  evidence_ids: tool.schema.array(tool.schema.string()),
}).strict()

const conflictResolution = tool.schema.object({
  schema_version: tool.schema.enum(["1.0"]),
  conflict_id: tool.schema.string(),
  authority_evidence: tool.schema.array(authorityEvidenceInput).optional(),
}).strict()

function projectAndEngine(context: ToolContext): { root: string; engine: string; opencodeRoot: string } {
  const candidates = [context.directory, context.worktree]
  for (const candidate of candidates) {
    const installed = path.join(candidate, ".k-slide-engine", "src", "k_slide")
    if (existsSync(installed)) return { root: candidate, engine: path.join(candidate, ".k-slide-engine"), opencodeRoot: path.join(candidate, ".opencode") }
    const source = path.join(candidate, "src", "k_slide")
    if (existsSync(source)) return { root: candidate, engine: candidate, opencodeRoot: path.join(candidate, ".opencode") }
    const nested = path.join(candidate, "k-slide", "src", "k_slide")
    if (existsSync(nested)) return { root: path.join(candidate, "k-slide"), engine: path.join(candidate, "k-slide"), opencodeRoot: path.join(candidate, "k-slide", ".opencode") }
  }
  const globalEngine = path.resolve(import.meta.dir, "..", "k-slide-engine")
  if (existsSync(path.join(globalEngine, "src", "k_slide"))) {
    return { root: context.worktree, engine: globalEngine, opencodeRoot: path.resolve(import.meta.dir, "..") }
  }
  throw new Error("K-Slide core is not installed for this OpenCode project.")
}

async function runCore(context: ToolContext, command: string, args: string[] = []): Promise<string> {
  const project = projectAndEngine(context)
  const environment: Record<string, string> = { ...process.env, PYTHONPATH: path.join(project.engine, "src") } as Record<string, string>
  if (trustedAccessKey !== undefined) environment.AccessKey = trustedAccessKey
  const child = Bun.spawn(
    ["python3", "-m", "k_slide.cli", command, "--root", project.root, "--json", ...(command === "doctor" ? ["--engine-root", project.engine, "--opencode-root", project.opencodeRoot] : []), ...args],
    {
      cwd: project.root,
      env: environment,
      stdout: "pipe",
      stderr: "pipe",
    },
  )
  const stdout = await new Response(child.stdout).text()
  const stderr = await new Response(child.stderr).text()
  const exitCode = await child.exited
  if (stdout.trim()) return stdout.trim()
  // A crashed/empty core response may contain arbitrary interpreter or
  // dependency text. Never forward stderr across the OpenCode boundary.
  return JSON.stringify(
    exitCode === 0
      ? { status: "OK" }
      : { status: "FAILED", error: { code: "KSLIDE_INTERNAL", message: "K-Slide core failed before producing a safe response." } },
  )
}

export const prepare = tool({
  description: "Create or resume a validated immutable K-Slide run and return its next work target. Does not translate.",
  args: {
    explicit_input_paths: tool.schema.array(tool.schema.string()).default([]),
    host_input_refs: tool.schema.array(hostInputReference).default([]),
  },
  async execute(args, context) {
    const hostInvocation = args.host_input_refs.length
      ? JSON.stringify({ schema_version: "1.0", adapter_version: "1.0", input_refs: args.host_input_refs })
      : null
    return runCore(context, "prepare", [
      "--session-id",
      context.sessionID,
      ...(hostInvocation ? ["--host-inputs-json", hostInvocation, "--host-worktree", context.worktree] : []),
      ...args.explicit_input_paths,
    ])
  },
})

export const next = tool({
  description: "Return the next persisted K-Slide work unit using session-aware run resolution.",
  args: { run_id: tool.schema.string().optional() },
  async execute(args, context) {
    return runCore(context, "next", ["--session-id", context.sessionID, ...(args.run_id ? ["--run", args.run_id] : [])])
  },
})

export const evidence = tool({
  description: "Return compact source evidence and constraints for the current K-Slide work unit. Does not translate.",
  args: { run_id: tool.schema.string().optional() },
  async execute(args, context) {
    return runCore(context, "evidence", ["--session-id", context.sessionID, ...(args.run_id ? ["--run", args.run_id] : [])])
  },
})

export const submit = tool({
  description: "Validate and atomically merge one structured TranslationPatch against immutable engine evidence.",
  args: {
    run_id: tool.schema.string(),
    payload: translationPatch,
  },
  async execute(args, context) {
    return runCore(context, "submit", ["--run", args.run_id, "--session-id", context.sessionID, "--payload-json", JSON.stringify(args.payload)])
  },
})

export const conflict_assess = tool({
  description: "Engine-owned KSA-23 conflict assessment. The model may submit only references to existing canonical semantic objects; the engine rebuilds all evidence, locations, provenance, and conflict context and records an explicit zero-conflict result when none are found.",
  args: {
    run_id: tool.schema.string(),
    payload: conflictAssessment,
  },
  async execute(args, context) {
    return runCore(context, "conflict-assess", ["--run", args.run_id, "--session-id", context.sessionID, "--payload-json", JSON.stringify(args.payload)])
  },
})

export const conflict_resolve = tool({
  description: "Resolve one existing KSA-23 conflict through deterministic configured authority or current explicit AUTHORITY_SUPERSEDES evidence. The engine derives and validates every supersession field; the caller supplies no winner, loser, relation, source text, or resolution state.",
  args: {
    run_id: tool.schema.string(),
    payload: conflictResolution,
  },
  async execute(args, context) {
    return runCore(context, "conflict-resolve", ["--run", args.run_id, "--session-id", context.sessionID, "--payload-json", JSON.stringify(args.payload)])
  },
})

export const verify = tool({
  description: "Run deterministic K-Slide verification and return exact repair targets or PASS.",
  args: { run_id: tool.schema.string() },
  async execute(args, context) {
    return runCore(context, "verify", ["--run", args.run_id, "--session-id", context.sessionID])
  },
})

export const finalize = tool({
  description: "Create final K-Slide reports and completion marker only after deterministic verification passes.",
  args: { run_id: tool.schema.string() },
  async execute(args, context) {
    return runCore(context, "finalize", ["--run", args.run_id, "--session-id", context.sessionID])
  },
})

export const status = tool({
  description: "Show compact current-session K-Slide status; an explicit run ID is optional.",
  args: { run_id: tool.schema.string().optional() },
  async execute(args, context) {
    return runCore(context, "status", ["--session-id", context.sessionID, ...(args.run_id ? ["--run", args.run_id] : [])])
  },
})

export const doctor = tool({
  description: "Diagnose K-Slide runtime, model identity, file capabilities, installation, and privacy posture.",
  args: {},
  async execute(_args, context) {
    return runCore(context, "doctor")
  },
})
