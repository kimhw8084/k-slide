import {runProcess} from "./process"
import path from "node:path"
import {BuiltInvocation, serializeHostInvocation, summarizeEngineResponse} from "./hostInvocation"
import {SafeKSlideError} from "./safeError"
import {doctorSummary, parseRunList, RunInfo} from "./runInfo"

export interface EngineTarget {
  readonly root: string
  readonly engineRoot?: string
  readonly pythonPath: string
}

export interface EngineSummary {
  readonly runId?: string
  readonly status?: string
  readonly semanticOutcome?: string
}

export function buildPrepareArguments(root: string): string[] {
  return [
    "-m", "k_slide.cli", "prepare",
    "--root", root,
    "--json",
    "--host-adapter", "cloud_vscode",
    "--host-worktree", root,
    "--host-inputs-stdin",
  ]
}

export function buildPresentationArguments(root: string, runId: string): string[] {
  return [
    "-m", "k_slide.cli", "presentation",
    "--root", root,
    "--run", runId,
    "--json",
    "--host-adapter", "cloud_vscode",
  ]
}

function environmentFor(target: EngineTarget): NodeJS.ProcessEnv {
  const previous = process.env.PYTHONPATH
  return {
    ...process.env,
    ...(target.engineRoot ? {PYTHONPATH: [path.join(target.engineRoot, "src"), previous].filter(Boolean).join(path.delimiter)} : {}),
  }
}

export async function invokePrepare(target: EngineTarget, built: BuiltInvocation, signal?: AbortSignal): Promise<EngineSummary> {
  const stdout = await runProcess(target.pythonPath, buildPrepareArguments(built.root), {
    cwd: built.root, env: environmentFor(target), input: serializeHostInvocation(built.invocation), signal,
  })
  try {
    return summarizeEngineResponse(JSON.parse(stdout))
  } catch {
    throw new SafeKSlideError("K-Slide returned an invalid response. Contact your workspace administrator.")
  }
}

export async function invokePresentation(target: EngineTarget, runId: string): Promise<unknown> {
  const stdout = await runProcess(target.pythonPath, buildPresentationArguments(target.root, runId), {
    cwd: target.root, env: environmentFor(target),
  })
  try {
    return JSON.parse(stdout)
  } catch {
    throw new SafeKSlideError("K-Slide returned an invalid presentation response.")
  }
}

export async function invokeRuns(target: EngineTarget): Promise<RunInfo[]> {
  const stdout = await runProcess(target.pythonPath, ["-m", "k_slide.cli", "runs", "--root", target.root, "--json", "--host-adapter", "cloud_vscode"], {
    cwd: target.root, env: environmentFor(target), timeoutMs: 15_000,
  })
  try { return parseRunList(JSON.parse(stdout)) }
  catch { throw new SafeKSlideError("Saved runs could not be read. Check the runtime installation and refresh.") }
}

export async function invokeDoctor(target: EngineTarget, signal?: AbortSignal): Promise<string[]> {
  const args = ["-m", "k_slide.cli", "doctor", "--root", target.root, "--json"]
  if (target.engineRoot) args.push("--engine-root", target.engineRoot)
  const stdout = await runProcess(target.pythonPath, args, {
    cwd: target.root, env: environmentFor(target), acceptedExitCodes: [0, 2], signal,
  })
  try { return doctorSummary(JSON.parse(stdout)) }
  catch { throw new SafeKSlideError("Runtime diagnostics could not be read. Contact your workspace administrator.") }
}
