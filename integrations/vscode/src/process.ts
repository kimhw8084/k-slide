import {spawn} from "node:child_process"
import {SafeKSlideError} from "./safeError"

export interface ProcessOptions {
  cwd: string
  env: NodeJS.ProcessEnv
  input?: string
  signal?: AbortSignal
  timeoutMs?: number
  maxBytes?: number
  acceptedExitCodes?: readonly number[]
}

/** Drain both pipes concurrently; never disclose interpreter diagnostics. */
export function runProcess(executable: string, args: string[], options: ProcessOptions): Promise<string> {
  if (options.signal?.aborted) return Promise.reject(new SafeKSlideError("K-Slide action was canceled. Reopen the run to resume from saved progress."))
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, {cwd: options.cwd, env: options.env,
      detached: process.platform !== "win32", windowsHide: true, stdio: ["pipe", "pipe", "pipe"]})
    const chunks: Buffer[] = []
    const limit = options.maxBytes ?? 8 * 1024 * 1024
    let stdoutBytes = 0, stderrBytes = 0
    let failure: string | undefined
    const kill = (signal: NodeJS.Signals): void => {
      try {
        if (process.platform !== "win32" && child.pid) process.kill(-child.pid, signal)
        else child.kill(signal)
      } catch { /* Process already exited. */ }
    }
    const stop = (message: string): void => {
      if (failure) return
      failure = message
      kill("SIGTERM")
      setTimeout(() => kill("SIGKILL"), 500)
    }
    const abort = (): void => stop("K-Slide action was canceled. Reopen the run to resume from saved progress.")
    const timeout = setTimeout(() => stop("K-Slide action timed out. Reopen the run to check saved progress before retrying."), options.timeoutMs ?? 120_000)
    const cleanup = (): void => {
      clearTimeout(timeout)
      options.signal?.removeEventListener("abort", abort)
    }
    options.signal?.addEventListener("abort", abort, {once: true})
    if (options.signal?.aborted) abort()
    child.stdout.on("data", (chunk: Buffer) => {
      stdoutBytes += chunk.length
      if (stdoutBytes > limit) stop("K-Slide response exceeded the allowed size. Check the run status.")
      else if (!failure) chunks.push(chunk)
    })
    child.stderr.on("data", (chunk: Buffer) => {
      stderrBytes += chunk.length
      if (stderrBytes > limit) stop("K-Slide diagnostics exceeded the allowed size. Check the runtime installation.")
    })
    child.stdin.on("error", () => undefined)
    child.on("error", () => {
      cleanup()
      reject(new SafeKSlideError("K-Slide runtime is unavailable. Contact your workspace administrator."))
    })
    child.on("close", (code) => {
      cleanup()
      if (failure || code === null || !(options.acceptedExitCodes ?? [0]).includes(code)) reject(new SafeKSlideError(failure ?? "K-Slide could not complete this action. Check the run status and input eligibility."))
      else resolve(Buffer.concat(chunks).toString("utf8"))
    })
    child.stdin.end(options.input)
  })
}
