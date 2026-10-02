import assert from "node:assert/strict"
import {mkdtemp, mkdir, writeFile, rm} from "node:fs/promises"
import path from "node:path"
import {tmpdir} from "node:os"
import {discoverEngine} from "../.opencode/internal/lib/k-slide-runtime.ts"

const root = await mkdtemp(path.join(tmpdir(), "kslide-host-runtime-"))
try {
  const config = path.join(root, "managed-config")
  assert.deepEqual(discoverEngine(root, root, config, {KSLIDE_PYTHON: "/managed/python"}),
    {root, engine: undefined, opencodeRoot: config, python: "/managed/python"})
  const engine = path.join(root, ".k-slide-engine")
  const python = path.join(engine, ".venv", process.platform === "win32" ? "Scripts/python.exe" : "bin/python")
  for (const file of [path.join(engine, "src/k_slide/cli.py"), python]) {
    await mkdir(path.dirname(file), {recursive: true})
    await writeFile(file, "")
  }
  assert.equal(discoverEngine(root, root, config, {}).python, python)
  assert.equal(discoverEngine(root, root, config, {}).engine, engine)
  assert.equal(discoverEngine(root, root, config, {KSLIDE_PYTHON: "/managed/python"}).python, "/managed/python")
  assert.throws(() => discoverEngine(root, root, config, {KSLIDE_ENGINE_ROOT: "/missing"}))
  console.log("OpenCode runtime discovery passed.")
} finally { await rm(root, {recursive: true, force: true}) }
