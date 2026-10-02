import assert from "node:assert/strict"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import {test} from "node:test"
import {resolveEngineTarget} from "./runtime"
import {SafeKSlideError} from "./safeError"

test("clean workspace uses deployed Python wheel without a source checkout", () => {
  const target = resolveEngineTarget("/empty-workspace", {}, {KSLIDE_PYTHON: "/runtime/bin/python"})
  assert.equal(target.engineRoot, undefined)
  assert.equal(target.pythonPath, "/runtime/bin/python")
})

test("installed engine virtual environment is discovered without employee settings", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "kslide-runtime-"))
  try {
    const engineRoot = path.join(root, ".k-slide-engine")
    const cli = path.join(engineRoot, "src/k_slide/cli.py")
    const python = path.join(engineRoot, ".venv", process.platform === "win32" ? "Scripts/python.exe" : "bin/python")
    for (const file of [cli, python]) { fs.mkdirSync(path.dirname(file), {recursive: true}); fs.writeFileSync(file, "") }
    assert.deepEqual(resolveEngineTarget(root, {}, {}), {root, engineRoot, pythonPath: python})
    assert.equal(resolveEngineTarget(root, {}, {KSLIDE_PYTHON: "/managed/python"}).pythonPath, "/managed/python")
    assert.equal(resolveEngineTarget(root, {pythonPath: "/explicit/python"}, {KSLIDE_PYTHON: "/managed/python"}).pythonPath, "/explicit/python")
    assert.throws(() => resolveEngineTarget(root, {engineRoot: "/missing-engine"}, {}), SafeKSlideError)
  } finally { fs.rmSync(root, {recursive: true, force: true}) }
})
