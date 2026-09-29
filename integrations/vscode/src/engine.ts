import {spawn} from "node:child_process"
import path from "node:path"
import {BuiltInvocation, serializeHostInvocation, summarizeEngineResponse} from "./hostInvocation"
import {SafeKSlideError} from "./safeError"

export interface EngineTarget {
  readonly root: string
  readonly engineRoot: string
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
    PYTHONPATH: [path.join(target.engineRoot, "src"), previous].filter(Boolean).join(path.delimiter),
  }
}

export function invokePrepare(target: EngineTarget, built: BuiltInvocation): Promise<EngineSummary> {
  const child = spawn(target.pythonPath, buildPrepareArguments(built.root), {
    cwd: built.root,
    env: environmentFor(target),
    windowsHide: true,
    stdio: ["pipe", "pipe", "pipe"],
  })
  return new Promise((resolve, reject) => {
    let stdout = ""
    let tooLarge = false
    child.stdout.setEncoding("utf8")
    child.stdout.on("data", (chunk: string) => {
      if (stdout.length + chunk.length > 1_000_000) {
        tooLarge = true
        child.kill()
        return
      }
      stdout += chunk
    })
    child.stderr.on("data", () => undefined)
    child.on("error", () => reject(new SafeKSlideError("K-Slide runtime is unavailable. Configure the Python executable and install the K-Slide engine.")))
    child.on("close", (code) => {
      if (tooLarge || code !== 0) {
        reject(new SafeKSlideError("K-Slide could not prepare the selected file(s). Check the K-Slide runtime and input eligibility."))
        return
      }
      try {
        resolve(summarizeEngineResponse(JSON.parse(stdout)))
      } catch {
        reject(new SafeKSlideError("K-Slide returned an invalid response. Check the K-Slide runtime installation."))
      }
    })
    child.stdin.on("error", () => undefined)
    child.stdin.end(serializeHostInvocation(built.invocation))
  })
}

export function invokePresentation(target: EngineTarget, runId: string): Promise<unknown> {
  const child = spawn(target.pythonPath, buildPresentationArguments(target.root, runId), {
    cwd: target.root,
    env: environmentFor(target),
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
  })
  return new Promise((resolve, reject) => {
    let stdout = ""
    let tooLarge = false
    child.stdout.setEncoding("utf8")
    child.stdout.on("data", (chunk: string) => {
      if (stdout.length + chunk.length > 1_000_000) {
        tooLarge = true
        child.kill()
        return
      }
      stdout += chunk
    })
    child.stderr.on("data", () => undefined)
    child.on("error", () => reject(new SafeKSlideError("K-Slide runtime is unavailable. Configure the Python executable and install the K-Slide engine.")))
    child.on("close", (code) => {
      if (tooLarge || code !== 0) {
        reject(new SafeKSlideError("K-Slide could not read the requested run presentation."))
        return
      }
      try {
        resolve(JSON.parse(stdout))
      } catch {
        reject(new SafeKSlideError("K-Slide returned an invalid presentation response."))
      }
    })
  })
}
