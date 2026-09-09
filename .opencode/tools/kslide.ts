import { tool } from "@opencode-ai/plugin"
import path from "node:path"
import { existsSync } from "node:fs"

type ToolContext = {
  sessionID: string
  messageID?: string
  directory: string
  worktree: string
}

const translationRegion = tool.schema.object({
  region_id: tool.schema.string(),
  english: tool.schema.string(),
  commitment_status: tool.schema.string().optional(),
  speech_act: tool.schema.string().optional(),
  term_ids: tool.schema.array(tool.schema.string()).default([]),
  numeric_fact_ids: tool.schema.array(tool.schema.string()).default([]),
  unresolved: tool.schema.boolean().default(false),
  unresolved_reason: tool.schema.string().optional(),
})

const translationCell = tool.schema.object({
  cell_id: tool.schema.string(),
  english: tool.schema.string(),
  unresolved: tool.schema.boolean().default(false),
  unresolved_reason: tool.schema.string().optional(),
})

const translationTable = tool.schema.object({
  table_id: tool.schema.string(),
  cells: tool.schema.array(translationCell),
})

const visualInterpretation = tool.schema.object({
  relation_id: tool.schema.string(),
  interpretation: tool.schema.string(),
  evidence_ids: tool.schema.array(tool.schema.string()).default([]),
})

const executiveSemantics = tool.schema.object({
  source_faithful: tool.schema.string().optional(),
  takeaway: tool.schema.string().optional(),
  decision_or_ask: tool.schema.string().optional(),
  status: tool.schema.string().optional(),
  risk: tool.schema.string().optional(),
  dependency: tool.schema.string().optional(),
  timing: tool.schema.string().optional(),
  evidence_ids: tool.schema.array(tool.schema.string()).default([]),
})

const translationPatch = tool.schema.object({
  schema_version: tool.schema.string(),
  work_unit_id: tool.schema.string(),
  evidence_revision: tool.schema.string(),
  regions: tool.schema.array(translationRegion),
  tables: tool.schema.array(translationTable),
  visual_interpretations: tool.schema.array(visualInterpretation).default([]),
  executive_semantics: executiveSemantics.default({}),
  repair_revision: tool.schema.string().optional(),
})

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
  const child = Bun.spawn(
    ["python3", "-m", "k_slide.cli", command, "--root", project.root, "--json", ...(command === "doctor" ? ["--engine-root", project.engine, "--opencode-root", project.opencodeRoot] : []), ...args],
    {
      cwd: project.root,
      env: { ...process.env, PYTHONPATH: path.join(project.engine, "src") },
      stdout: "pipe",
      stderr: "pipe",
    },
  )
  const stdout = await new Response(child.stdout).text()
  const stderr = await new Response(child.stderr).text()
  const exitCode = await child.exited
  if (exitCode !== 0 && !stdout.trim()) return JSON.stringify({ status: "FAILED", error: stderr.trim() || "K-Slide core failed." })
  return stdout.trim() || JSON.stringify({ status: exitCode === 0 ? "OK" : "FAILED", detail: stderr.trim() })
}

export const prepare = tool({
  description: "Create or resume a validated immutable K-Slide run and return its next work target. Does not translate.",
  args: {
    mode: tool.schema.enum(["smart", "strict", "safe"]).default("smart"),
    explicit_input_paths: tool.schema.array(tool.schema.string()).default([]),
  },
  async execute(args, context) {
    return runCore(context, "prepare", ["--mode", args.mode, "--session-id", context.sessionID, ...args.explicit_input_paths])
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
