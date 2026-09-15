import assert from "node:assert/strict"
import { createHash } from "node:crypto"
import { spawnSync } from "node:child_process"
import { mkdtemp, readFile, rm, stat } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import { fileURLToPath } from "node:url"
import KSlideHostPlugin from "../.opencode/plugin/k-slide-host.ts"

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
const PNG = Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=", "base64")

function minimalPdf(): Buffer {
  const objects = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Contents 4 0 R >>",
    "<< /Length 0 >>\nstream\n\nendstream",
  ]
  const offsets = [0]
  let body = "%PDF-1.4\n"
  for (const [index, object] of objects.entries()) {
    offsets.push(Buffer.byteLength(body, "latin1"))
    body += `${index + 1} 0 obj\n${object}\nendobj\n`
  }
  const xref = Buffer.byteLength(body, "latin1")
  body += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`
  body += offsets.slice(1).map((offset) => `${String(offset).padStart(10, "0")} 00000 n \n`).join("")
  body += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`
  return Buffer.from(body, "latin1")
}

function safeMinimalPptx(): Buffer | undefined {
  const script = [
    "from pptx import Presentation",
    "import sys",
    "presentation = Presentation()",
    "presentation.slides.add_slide(presentation.slide_layouts[6])",
    "presentation.save(sys.stdout.buffer)",
  ].join("; ")
  const result = spawnSync("python3", ["-c", script], { cwd: ROOT, env: { ...process.env, PYTHONPATH: path.join(ROOT, "src") } })
  return result.status === 0 && Buffer.isBuffer(result.stdout) ? result.stdout : undefined
}

function dataPart(mime: string, filename: string, bytes: Buffer, url = `data:${mime};base64,${bytes.toString("base64")}`): Record<string, unknown> {
  return { type: "file", mime, filename, url }
}

function sha256(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex")
}

async function hooksFor(worktree: string) {
  return KSlideHostPlugin({ worktree } as never)
}

async function capture(worktree: string, sessionID: string, parts: Record<string, unknown>[]) {
  const hooks = await hooksFor(worktree)
  const message = hooks["chat.message"]
  const before = hooks["tool.execute.before"]
  const after = hooks["tool.execute.after"]
  assert.ok(message && before && after)
  await message({ sessionID } as never, { message: {} as never, parts } as never)
  const output = { args: { explicit_input_paths: [] as string[] } }
  await before({ tool: "kslide_prepare", sessionID, callID: "call-1" } as never, output)
  return { hooks, output, after }
}

function hostInvocation(refs: unknown[]): string {
  return JSON.stringify({ schema_version: "1.0", adapter_version: "1.0", input_refs: refs })
}

function runPrepare(root: string, sessionID: string, refs: unknown[]): { status: number | null; output: Record<string, unknown>; stderr: string } {
  const result = spawnSync(
    "python3",
    ["-m", "k_slide.cli", "prepare", "--root", root, "--json", "--session-id", sessionID, "--host-inputs-json", hostInvocation(refs), "--host-worktree", root],
    { cwd: ROOT, env: { ...process.env, PYTHONPATH: path.join(ROOT, "src") }, encoding: "utf8" },
  )
  return { status: result.status, output: JSON.parse(result.stdout), stderr: result.stderr }
}

async function runCoreSnapshot(root: string, sessionID: string, refs: unknown[]): Promise<string> {
  const script = [
    "import sys",
    "from k_slide.ingest import prepare_run",
    "run = prepare_run(__import__('pathlib').Path(sys.argv[1]), host_input_refs=__import__('json').loads(sys.argv[3])['input_refs'], approved_root=__import__('pathlib').Path(sys.argv[1]), session_id=sys.argv[2])",
    "print(run)",
  ].join("; ")
  const result = spawnSync(
    "python3",
    ["-c", script, root, sessionID, hostInvocation(refs)],
    { cwd: ROOT, env: { ...process.env, PYTHONPATH: path.join(ROOT, "src") }, encoding: "utf8" },
  )
  assert.equal(result.status, 0, result.stderr)
  return result.stdout.trim()
}

async function assertPrivateFile(locator: string): Promise<void> {
  assert.ok(locator.startsWith(path.resolve(tmpdir()) + path.sep))
  const details = await stat(locator)
  assert.equal(details.mode & 0o777, 0o600)
}

async function successBoundary(): Promise<void> {
  const pdf = minimalPdf()
  const pptx = safeMinimalPptx()
  const sessionID = "composer-success-session"
  const parts = [
    dataPart("image/png", "first-slide.png", PNG),
    dataPart("application/pdf", "second-source.pdf", pdf),
  ]
  if (pptx) parts.push(dataPart("application/vnd.openxmlformats-officedocument.presentationml.presentation", "third-source.pptx", pptx))
  const originalBytes = [PNG, pdf, ...(pptx ? [pptx] : [])]
  const encodedValues = originalBytes.map((bytes) => bytes.toString("base64"))
  const { output, after } = await capture(ROOT, sessionID, [
    ...parts,
  ])
  const args = output.args as unknown as { host_input_refs: Array<{ logical_name: string; locator: string }> }
  assert.deepEqual(args.host_input_refs.map((ref) => ref.logical_name), parts.map((part) => part.filename))
  assert.equal(args.host_input_refs.length, parts.length)
  for (const ref of args.host_input_refs) {
    assert.ok(!ref.locator.startsWith("data:"))
    assert.ok(!encodedValues.some((encoded) => JSON.stringify(output.args).includes(encoded)))
    await assertPrivateFile(ref.locator)
  }
  assert.equal(new Set(args.host_input_refs.map((ref) => path.dirname(ref.locator))).size, 1)

  const cliRoot = await mkdtemp(path.join(path.resolve(tmpdir()), "k-slide-host-cli-"))
  try {
    const cliResult = runPrepare(cliRoot, "composer-cli-success", [args.host_input_refs[0]])
    assert.equal(cliResult.status, 0, cliResult.stderr)
    assert.notEqual(cliResult.output.status, "FAILED")
    assert.equal(cliResult.output.input_count, 1)
    assert.ok(!JSON.stringify(cliResult.output).includes(args.host_input_refs[0].locator))
  } finally {
    await rm(cliRoot, { recursive: true, force: true })
  }

  const snapshotRoot = await mkdtemp(path.join(path.resolve(tmpdir()), "k-slide-host-test-"))
  try {
    const run = await runCoreSnapshot(snapshotRoot, sessionID, args.host_input_refs)
    const manifest = JSON.parse(await readFile(path.join(run, "RUN_MANIFEST.json"), "utf8"))
    assert.deepEqual(manifest.inputs.map((item: { source_name: string }) => item.source_name), parts.map((part) => part.filename))
    assert.deepEqual(manifest.inputs.map((item: { sha256: string }) => item.sha256), originalBytes.map(sha256))
    assert.deepEqual(await readFile(path.join(run, "inputs", "source-001.png")), PNG)
    assert.deepEqual(await readFile(path.join(run, "inputs", "source-002.pdf")), pdf)
    if (pptx) assert.deepEqual(await readFile(path.join(run, "inputs", "source-003.pptx")), pptx)
    const durable = JSON.stringify(manifest)
    for (const ref of args.host_input_refs) assert.ok(!durable.includes(ref.locator))

    const status = spawnSync("python3", ["-m", "k_slide.cli", "status", "--root", snapshotRoot, "--run", path.basename(run), "--json"], {
      cwd: ROOT,
      env: { ...process.env, PYTHONPATH: path.join(ROOT, "src") },
      encoding: "utf8",
    })
    assert.equal(status.status, 0, status.stderr)
    assert.ok(!args.host_input_refs.some((ref) => status.stdout.includes(ref.locator)))
    assert.ok(!encodedValues.some((encoded) => status.stdout.includes(encoded)))
    const supportPath = path.join(snapshotRoot, "support.zip")
    const support = spawnSync("python3", ["-m", "k_slide.cli", "support-bundle", "--root", snapshotRoot, "--output", supportPath, "--json"], {
      cwd: ROOT,
      env: { ...process.env, PYTHONPATH: path.join(ROOT, "src") },
      encoding: "utf8",
    })
    assert.equal(support.status, 0, support.stderr)
    const supportMetadata = spawnSync("unzip", ["-p", supportPath, "support-metadata.json"], { encoding: "utf8" })
    assert.equal(supportMetadata.status, 0, supportMetadata.stderr)
    assert.ok(!args.host_input_refs.some((ref) => supportMetadata.stdout.includes(ref.locator)))
    assert.ok(!encodedValues.some((encoded) => supportMetadata.stdout.includes(encoded)))
  } finally {
    await rm(snapshotRoot, { recursive: true, force: true })
  }

  await after({ tool: "kslide_prepare", sessionID, callID: "call-1" } as never, {} as never)
  for (const ref of args.host_input_refs) {
    await assert.rejects(stat(ref.locator))
  }
}

async function failureBoundary(): Promise<void> {
  const cases = [
    dataPart("image/png", "malformed.png", PNG, "data:image/png;base64,YQ="),
    dataPart("application/pdf", "mismatch.pdf", PNG, `data:image/png;base64,${PNG.toString("base64")}`),
    dataPart("text/plain", "unsupported.txt", Buffer.from("not a source"), `data:text/plain;base64,${Buffer.from("not a source").toString("base64")}`),
    dataPart("image/png", "remote-http.png", PNG, "http://example.invalid/remote.png"),
    dataPart("image/png", "remote-https.png", PNG, "https://example.invalid/remote.png"),
    dataPart("image/png", "remote-blob.png", PNG, "blob:https://example.invalid/attachment"),
    dataPart("image/png", "remote-ftp.png", PNG, "ftp://example.invalid/attachment"),
    dataPart("image/png", "empty.png", Buffer.alloc(0), "data:image/png;base64,"),
    dataPart("application/vnd.openxmlformats-officedocument.presentationml.presentation", "corrupt.pptx", Buffer.from("not-a-zip")),
  ]
  for (const [index, part] of cases.entries()) {
    const sessionID = `composer-failure-${index}`
    const { output, after } = await capture(ROOT, sessionID, [part])
    const args = output.args as unknown as { host_input_refs: Array<{ locator: string }> }
    assert.equal(args.host_input_refs.length, 1)
    assert.ok(!JSON.stringify(output.args).includes(String(part.url)))
    assert.ok(!JSON.stringify(output.args).includes("base64,"))
    const failureRoot = await mkdtemp(path.join(path.resolve(tmpdir()), "k-slide-host-failure-"))
    try {
      const result = runPrepare(failureRoot, sessionID, args.host_input_refs)
      assert.equal(result.status, 1)
      assert.equal(result.output.status, "FAILED_INPUT", `negative case ${index}: ${JSON.stringify(result.output)}`)
      assert.equal(result.output.semantic_outcome, null)
      assert.equal(result.output.operational_state, "PROCESSING_FAILED")
      assert.ok(!JSON.stringify(result.output).includes(String(part.url)))
    } finally {
      await rm(failureRoot, { recursive: true, force: true })
    }
    await after({ tool: "kslide_prepare", sessionID, callID: "call-1" } as never, {} as never)
    assert.ok(!args.host_input_refs[0].locator.startsWith("data:"))
    await assert.rejects(stat(args.host_input_refs[0].locator))
  }
}

async function negativeBoundary(): Promise<void> {
  const pluginSource = await readFile(path.join(ROOT, ".opencode", "plugin", "k-slide-host.ts"), "utf8")
  const maxInputBytes = 512 * 1024 * 1024
  const overLimitEncodedLength = 4 * Math.ceil((maxInputBytes + 1) / 3)
  assert.ok((overLimitEncodedLength / 4) * 3 > maxInputBytes)
  assert.match(pluginSource, /decodedLength > MAX_INPUT_BYTES/)
  const hooks = await hooksFor(ROOT)
  const before = hooks["tool.execute.before"]
  assert.ok(before)
  const output = { args: { host_input_refs: [{ source_kind: "attachment", logical_name: "fake.png", locator: "data:image/png;base64,AAAA" }] } }
  await before({ tool: "kslide_prepare", sessionID: "model-only-session", callID: "call-1" } as never, output)
  assert.deepEqual(output.args, {})
}

async function main(): Promise<void> {
  await successBoundary()
  await failureBoundary()
  await negativeBoundary()
  console.log("OpenCode host attachment regression tests passed")
}

main().catch((error: unknown) => {
  console.error(error)
  process.exitCode = 1
})
