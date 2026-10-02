import fs from "node:fs"
import path from "node:path"
import {EngineTarget} from "./engine"
import {SafeKSlideError} from "./safeError"

/** Deployment configuration precedes workspace discovery; never install at run time. */
export function resolveEngineTarget(root: string, settings: {engineRoot?: string; pythonPath?: string}, environment = process.env): EngineTarget {
  const explicit = settings.engineRoot?.trim() || environment.KSLIDE_ENGINE_ROOT?.trim()
  const candidates = explicit ? [path.resolve(explicit)] : [path.join(root, ".k-slide-engine"), root]
  const engineRoot = candidates.find((candidate) => fs.existsSync(path.join(candidate, "src", "k_slide", "cli.py")))
  if (explicit && !engineRoot) throw new SafeKSlideError("The configured K-Slide engine is unavailable. Contact your workspace administrator.")
  const interpreters = [engineRoot, root].filter((item): item is string => Boolean(item))
    .map((directory) => path.join(directory, ".venv", process.platform === "win32" ? "Scripts/python.exe" : "bin/python"))
  return {
    root,
    engineRoot,
    pythonPath: settings.pythonPath?.trim() || environment.KSLIDE_PYTHON?.trim()
      || interpreters.find((candidate) => fs.existsSync(candidate)) || "python3",
  }
}
