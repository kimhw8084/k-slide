import path from "node:path"
import {existsSync} from "node:fs"

/** Only host/deployment configuration selects executable code, never tool arguments. */
export function discoverEngine(directory: string, worktree: string, configRoot: string, environment = process.env): {
  root: string; engine?: string; opencodeRoot: string; python: string
} {
  let root = worktree
  let engine: string | undefined
  let opencodeRoot = configRoot
  const explicit = environment.KSLIDE_ENGINE_ROOT?.trim()
  if (explicit) {
    engine = path.resolve(explicit)
    if (!existsSync(path.join(engine, "src/k_slide/cli.py"))) throw new Error("Configured engine is unavailable")
  } else {
    for (const candidate of [directory, worktree]) {
      const found = [path.join(candidate, ".k-slide-engine"), candidate, path.join(candidate, "k-slide")]
        .find((value) => existsSync(path.join(value, "src/k_slide/cli.py")))
      if (found) {
        engine = found
        root = found === path.join(candidate, "k-slide") ? found : candidate
        opencodeRoot = path.join(root, ".opencode")
        break
      }
    }
    const global = path.join(configRoot, "k-slide-engine")
    if (!engine && existsSync(path.join(global, "src/k_slide/cli.py"))) engine = global
  }
  const interpreters = [engine, root].filter((item): item is string => Boolean(item))
    .map((value) => path.join(value, ".venv", process.platform === "win32" ? "Scripts/python.exe" : "bin/python"))
  return {root, engine, opencodeRoot,
    python: environment.KSLIDE_PYTHON?.trim() || interpreters.find((value) => existsSync(value)) || "python3"}
}
