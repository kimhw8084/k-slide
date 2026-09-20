import assert from "node:assert/strict"
import { createHash } from "node:crypto"
import { spawnSync } from "node:child_process"
import { mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import { fileURLToPath, pathToFileURL } from "node:url"
import KSlideHostPlugin, { deploymentBoundRouteIdentity, opencodeRouteIdentity } from "../.opencode/plugin/k-slide-host.ts"

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
  return { id: "prt_test", sessionID: "ses_test", messageID: "msg_test", type: "file", mime, filename, url }
}

function sha256(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex")
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "number" || typeof value === "boolean") return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(",")}]`
  return `{${Object.entries(value as Record<string, unknown>).sort(([left], [right]) => left.localeCompare(right)).map(([key, child]) => `${JSON.stringify(key)}:${canonicalJson(child)}`).join(",")}}`
}

function routePolicy(endpointIdentity: string): Record<string, unknown> {
  const capabilities = [
    { capability_class: "inference_route", purpose: "model_inference", service_identity: "inference-service-v1", route_identity: "route-v1", endpoint_identity: endpointIdentity, data_class: "source_content" },
    { capability_class: "durable_job_control", purpose: "job_control", service_identity: "job-service-v1", route_identity: null, endpoint_identity: null, data_class: "operational_metadata" },
    { capability_class: "scoped_storage", purpose: "scoped_storage", service_identity: "storage-service-v1", route_identity: null, endpoint_identity: null, data_class: "source_content" },
    { capability_class: "non_content_telemetry", purpose: "non_content_telemetry", service_identity: "telemetry-service-v1", route_identity: null, endpoint_identity: null, data_class: "non_content" },
  ].sort((left, right) => left.capability_class.localeCompare(right.capability_class))
  const policyHash = sha256(Buffer.from(canonicalJson({ schema_version: "1.0", policy_version: "2026.09.19", default_action: "deny", capabilities })))
  const policyIdentity = sha256(Buffer.from(canonicalJson({ schema_version: "1.0", policy_version: "2026.09.19", policy_hash: policyHash })))
  return { schema_version: "1.0", policy_version: "2026.09.19", policy_hash: policyHash, policy_identity: policyIdentity, default_action: "deny", capabilities }
}

async function writeRoutePolicy(worktree: string, endpointIdentity: string, mutate?: (policy: Record<string, unknown>) => Record<string, unknown>): Promise<void> {
  const config = path.join(worktree, ".k-slide-config")
  await mkdir(config, { recursive: true })
  const policy = mutate ? mutate(routePolicy(endpointIdentity)) : routePolicy(endpointIdentity)
  await writeFile(path.join(config, "egress-policy.json"), JSON.stringify(policy), "utf8")
}

function routeCandidate(endpointIdentity: string, policy = routePolicy(endpointIdentity)): Record<string, unknown> {
  return {
    schema_version: "1.1",
    candidate_spec_version: "1.1",
    requested_model: "google/gemma-4-31b-it",
    effective_model: "google/gemma-4-31b-it",
    provider: "google",
    opencode_version: "1.3.9",
    network_egress: "default_deny",
    inference_route_identity: "route-v1",
    inference_endpoint_identity: endpointIdentity,
    egress_policy_version: policy.policy_version,
    egress_policy_hash: policy.policy_hash,
    egress_policy_identity: policy.policy_identity,
  }
}

async function writeRouteCandidate(worktree: string, endpointIdentity: string, relative = ".k-slide-config/production-candidate.json", mutate?: (candidate: Record<string, unknown>) => Record<string, unknown>): Promise<string> {
  const candidatePath = path.join(worktree, relative)
  await mkdir(path.dirname(candidatePath), { recursive: true })
  const candidate = mutate ? mutate(routeCandidate(endpointIdentity)) : routeCandidate(endpointIdentity)
  if (path.extname(candidatePath) === ".yaml") {
    await writeFile(candidatePath, Object.entries(candidate).map(([key, value]) => `${key}: ${JSON.stringify(value)}`).join("\n") + "\n", "utf8")
  } else {
    await writeFile(candidatePath, JSON.stringify(candidate), "utf8")
  }
  return candidatePath
}

async function hooksFor(worktree: string) {
  return KSlideHostPlugin({ worktree } as never)
}

async function stagingEntries(sessionID: string): Promise<string[]> {
  const prefix = `k-slide-opencode-attachments-${sha256(Buffer.from(sessionID))}-`
  const entries = await readdir(path.resolve(tmpdir()), { withFileTypes: true })
  return entries.filter((entry) => entry.isDirectory() && entry.name.startsWith(prefix)).map((entry) => entry.name)
}

async function capture(worktree: string, sessionID: string, parts: Record<string, unknown>[], agent = "k-slide") {
  const hooks = await hooksFor(worktree)
  const message = hooks["chat.message"]
  const before = hooks["tool.execute.before"]
  const after = hooks["tool.execute.after"]
  assert.ok(message && before && after)
  const messageOutput = { message: {} as never, parts }
  await message({ sessionID, agent } as never, messageOutput as never)
  const output = { args: { explicit_input_paths: [] as string[] } }
  await before({ tool: "kslide_prepare", sessionID, callID: "call-1" } as never, output)
  return { hooks, output, messageOutput, after }
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
  const textPart = { type: "text", text: "/k-slide preserve this command text" }
  const fileParts = [
    dataPart("image/png", "first-slide.png", PNG),
    dataPart("application/pdf", "second-source.pdf", pdf),
  ]
  if (pptx) fileParts.push(dataPart("application/vnd.openxmlformats-officedocument.presentationml.presentation", "third-source.pptx", pptx))
  const originalBytes = [PNG, pdf, ...(pptx ? [pptx] : [])]
  const encodedValues = originalBytes.map((bytes) => bytes.toString("base64"))
  const parts = [textPart, ...fileParts]
  const { output, messageOutput, after } = await capture(ROOT, sessionID, parts)
  assert.deepEqual(messageOutput.parts, [textPart])
  assert.ok(!JSON.stringify(messageOutput).includes("data:"))
  assert.ok(!encodedValues.some((encoded) => JSON.stringify(messageOutput).includes(encoded)))
  assert.ok(!originalBytes.some((bytes) => JSON.stringify(messageOutput).includes(bytes.toString("latin1"))))
  const args = output.args as unknown as { host_input_refs: Array<{ logical_name: string; locator: string; classification: string }> }
  assert.deepEqual(args.host_input_refs.map((ref) => ref.logical_name), fileParts.map((part) => part.filename))
  assert.equal(args.host_input_refs.length, fileParts.length)
  assert.deepEqual(args.host_input_refs.map((ref) => ref.classification), fileParts.map(() => "company_confidential"))
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
    assert.deepEqual(manifest.inputs.map((item: { source_name: string }) => item.source_name), fileParts.map((part) => part.filename))
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
    dataPart("image/png", "remote-file.png", PNG, "file://example.invalid/remote.png"),
    dataPart("image/png", "remote-unc-slash.png", PNG, "//example.invalid/share/remote.png"),
    dataPart("image/png", "remote-unc-backslash.png", PNG, "\\\\example.invalid\\share\\remote.png"),
    dataPart("image/png", "empty.png", Buffer.alloc(0), "data:image/png;base64,"),
    dataPart("application/vnd.openxmlformats-officedocument.presentationml.presentation", "corrupt.pptx", Buffer.from("not-a-zip")),
  ]
  for (const [index, part] of cases.entries()) {
    const sessionID = `composer-failure-${index}`
    const { output, messageOutput, after } = await capture(ROOT, sessionID, [part])
    assert.deepEqual(messageOutput.parts, [])
    assert.ok(!JSON.stringify(messageOutput).includes(String(part.url)))
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

async function routingBoundary(): Promise<void> {
  const command = await readFile(path.join(ROOT, ".opencode", "commands", "k-slide.md"), "utf8")
  assert.match(command, /^agent:\s*k-slide\s*$/m)

  const hooks = await hooksFor(ROOT)
  const message = hooks["chat.message"]
  const before = hooks["tool.execute.before"]
  assert.ok(message && before)

  const sessionID = "ordinary-agent-session"
  const textPart = { type: "text", text: "ordinary chat text" }
  const sourcePart = dataPart("image/png", "ordinary.png", PNG)
  const parts = [textPart, sourcePart]
  const messageValue = { role: "user", text: "ordinary message" }
  const output = { message: messageValue as never, parts }
  const beforeMessage = JSON.stringify(output)
  await message({ sessionID, agent: "general" } as never, output as never)
  assert.equal(JSON.stringify(output), beforeMessage)
  assert.strictEqual(output.message, messageValue)
  assert.strictEqual(output.parts, parts)
  assert.deepEqual(await stagingEntries(sessionID), [])

  const toolOutput = {
    args: {
      explicit_input_paths: [],
      host_input_refs: [{ source_kind: "attachment", logical_name: "model.png", locator: "data:image/png;base64,AAAA" }],
    },
  }
  await before({ tool: "kslide_prepare", sessionID, callID: "ordinary-call" } as never, toolOutput)
  assert.deepEqual(toolOutput.args, { explicit_input_paths: [] })

  const routedSessionID = "k-slide-agent-session"
  const routedParts = [dataPart("image/png", "routed.png", PNG)]
  const routedOutput = { message: {} as never, parts: routedParts }
  await message({ sessionID: routedSessionID, agent: "k-slide" } as never, routedOutput as never)
  assert.deepEqual(routedOutput.parts, [])
  const routedToolOutput = { args: { explicit_input_paths: [] as string[] } }
  await before({ tool: "kslide_prepare", sessionID: routedSessionID, callID: "routed-call" } as never, routedToolOutput)
  const routedArgs = routedToolOutput.args as unknown as { host_input_refs: Array<{ logical_name: string; classification: string }> }
  assert.deepEqual(routedArgs.host_input_refs.map((ref) => ref.logical_name), ["routed.png"])
  assert.equal(routedArgs.host_input_refs[0].classification, "company_confidential")
  await hooks["tool.execute.after"]?.({ tool: "kslide_prepare", sessionID: routedSessionID, callID: "routed-call", args: routedToolOutput.args } as never, {} as never)
  assert.deepEqual(await stagingEntries(routedSessionID), [])

  const spoofSessionID = "model-classification-spoof-session"
  const spoofParts = [dataPart("image/png", "trusted.png", PNG)]
  const spoofMessageOutput = { message: {} as never, parts: spoofParts }
  await message({ sessionID: spoofSessionID, agent: "k-slide" } as never, spoofMessageOutput as never)
  const spoofToolOutput = {
    args: {
      explicit_input_paths: [],
      classification: "restricted",
      classifications: ["restricted"],
      classification_policy: { classification_rules: { restricted: true } },
      inference_route_identity: "model-route",
      inference_data_use_policy: { classification_rules: { restricted: true } },
      inference_data_policy: { classification_rules: { restricted: true } },
      host_input_refs: [{ source_kind: "attachment", logical_name: "spoof.png", locator: "model-value", classification: "restricted" }],
    },
  }
  await before({ tool: "kslide_prepare", sessionID: spoofSessionID, callID: "spoof-call" } as never, spoofToolOutput)
  const trustedArgs = spoofToolOutput.args as unknown as {
    classification?: string
    classifications?: unknown
    classification_policy?: unknown
    inference_route_identity?: unknown
    inference_data_use_policy?: unknown
    inference_data_policy?: unknown
    host_input_refs: Array<{ logical_name: string; classification: string }>
  }
  assert.equal(trustedArgs.classification, undefined)
  assert.equal(trustedArgs.classifications, undefined)
  assert.equal(trustedArgs.classification_policy, undefined)
  assert.equal(trustedArgs.inference_route_identity, undefined)
  assert.equal(trustedArgs.inference_data_use_policy, undefined)
  assert.equal(trustedArgs.inference_data_policy, undefined)
  assert.deepEqual(trustedArgs.host_input_refs.map((ref) => ref.logical_name), ["trusted.png"])
  assert.equal(trustedArgs.host_input_refs[0].classification, "company_confidential")
  await hooks["tool.execute.after"]?.({ tool: "kslide_prepare", sessionID: spoofSessionID, callID: "spoof-call", args: spoofToolOutput.args } as never, {} as never)
}

async function replacementBoundary(): Promise<void> {
  const sessionID = "replaced-k-slide-session"
  const hooks = await hooksFor(ROOT)
  const message = hooks["chat.message"]
  const before = hooks["tool.execute.before"]
  assert.ok(message && before)

  const exactOutput = { message: {} as never, parts: [dataPart("image/png", "captured.png", PNG)] }
  await message({ sessionID, agent: "k-slide" } as never, exactOutput as never)
  assert.equal((await stagingEntries(sessionID)).length, 1)

  const unrelatedParts = [{ type: "text", text: "unrelated later turn" }, dataPart("image/png", "unrelated.png", PNG)]
  const unrelatedOutput = { message: {} as never, parts: unrelatedParts }
  const snapshot = JSON.stringify(unrelatedOutput)
  await message({ sessionID, agent: "general" } as never, unrelatedOutput as never)
  assert.equal(JSON.stringify(unrelatedOutput), snapshot)
  assert.deepEqual(await stagingEntries(sessionID), [])

  const toolOutput = { args: { explicit_input_paths: [] as string[], host_input_refs: [{ source_kind: "attachment", logical_name: "stale.png", locator: "stale" }] } }
  await before({ tool: "kslide_prepare", sessionID, callID: "replacement-call" } as never, toolOutput)
  assert.deepEqual(toolOutput.args, { explicit_input_paths: [] })
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

export async function modelPinBoundary(): Promise<void> {
  const agentSource = await readFile(path.join(ROOT, ".opencode", "agents", "k-slide.md"), "utf8")
  assert.match(agentSource, /^model:\s*google\/gemma-4-31b-it\s*$/m)
  const worktree = await mkdtemp(path.join(path.resolve(tmpdir()), "k-slide-route-policy-"))
  const api = { id: "gemma-4-31b-it", npm: "@ai-sdk/google", url: "https://generativelanguage.googleapis.com/v1beta" }
  const endpointIdentity = opencodeRouteIdentity({ providerID: "google", modelID: "gemma-4-31b-it", apiID: api.id, apiNpm: api.npm, apiURL: api.url })
  assert.equal(endpointIdentity, "ee228eb59b413294128d01a917aba9a5841fb1f3fb26322c6c39ddc4c28f94e7")
  await writeRoutePolicy(worktree, endpointIdentity)
  await writeRouteCandidate(worktree, endpointIdentity)
  try {
    const hooks = await hooksFor(worktree)
    const params = hooks["chat.params"]
    assert.ok(params)
    const base = {
      sessionID: "model-pin-session",
      agent: "k-slide",
      model: {
        id: "gemma-4-31b-it",
        providerID: "google",
        api,
        name: "Gemma 4 31B IT",
        capabilities: { temperature: true, reasoning: false, attachment: true, toolcall: true, input: { text: true, audio: false, image: true, video: false, pdf: false }, output: { text: true, audio: false, image: false, video: false, pdf: false } },
        cost: { input: 0, output: 0, cache: { read: 0, write: 0 } },
        limit: { context: 131072, output: 8192 },
        status: "active",
        options: {},
        headers: {},
      },
      provider: { info: { id: "google", name: "Google", source: "config", env: [], options: {}, models: {} }, options: {} },
      message: { model: { providerID: "google", modelID: "gemma-4-31b-it" } },
    }
    const paramsOutput = { temperature: 0.1, topP: 1, topK: 0, options: {} }
    await params(base as never, paramsOutput as never)
    for (const mutation of [
      { model: { ...base.model, id: "other-model" } },
      { model: { ...base.model, providerID: "other-provider" } },
      { model: { ...base.model, api: { ...api, id: "other-model" } } },
      { model: { ...base.model, api: { ...api, npm: "@ai-sdk/openai" } } },
      { model: { ...base.model, api: { ...api, url: "https://attacker.invalid" } } },
      { model: { ...base.model, provider: { endpoint: "https://attacker.invalid" } } },
      { provider: { info: { ...base.provider.info, id: "other-provider" }, options: {} } },
      { provider: { info: { ...base.provider.info, options: { baseURL: "https://attacker.invalid" } }, options: {} } },
      { provider: { info: base.provider.info, options: { proxy: "http://attacker.invalid" } } },
      { model: { ...base.model, options: { endpoint: "https://attacker.invalid" } } },
      { model: { ...base.model, options: { fallback: "other-route" } } },
      { model: { ...base.model, options: { api: "other-route" } } },
      { model: { ...base.model, options: { npm: "@ai-sdk/openai" } } },
      { message: { model: { providerID: "other-provider", modelID: "other-model" } } },
    ]) {
      await assert.rejects(params({ ...base, ...mutation } as never, paramsOutput as never))
    }
    await assert.rejects(params(base as never, { ...paramsOutput, options: { baseURL: "https://attacker.invalid" } } as never))
    await writeRoutePolicy(worktree, endpointIdentity, (policy) => {
      const capabilities = policy.capabilities as Array<Record<string, unknown>>
      delete capabilities.find((item) => item.capability_class === "inference_route")?.endpoint_identity
      return policy
    })
    await assert.rejects(params(base as never, paramsOutput as never))
    await writeRoutePolicy(worktree, endpointIdentity, (policy) => {
      const capabilities = policy.capabilities as Array<Record<string, unknown>>
      const inference = capabilities.find((item) => item.capability_class === "inference_route")
      if (inference) inference.endpoint_identity = "malformed"
      return policy
    })
    await assert.rejects(params(base as never, paramsOutput as never))
    await writeRoutePolicy(worktree, "a".repeat(64))
    await assert.rejects(params(base as never, paramsOutput as never))
    await writeRoutePolicy(worktree, endpointIdentity)
    await params({ ...base, agent: "general" } as never, paramsOutput as never)
    const flatProvider = { ...base, provider: { id: "google", options: {} } }
    await params(flatProvider as never, paramsOutput as never)
  } finally {
    await rm(worktree, { recursive: true, force: true })
  }
}

export async function v139ProviderOrderingBoundary(): Promise<void> {
  const worktree = await mkdtemp(path.join(path.resolve(tmpdir()), "k-slide-provider-order-"))
  const api = { id: "gemma-4-31b-it", npm: "@ai-sdk/google", url: "https://generativelanguage.googleapis.com/v1beta" }
  const endpointIdentity = opencodeRouteIdentity({ providerID: "google", modelID: "gemma-4-31b-it", apiID: api.id, apiNpm: api.npm, apiURL: api.url })
  await writeRoutePolicy(worktree, endpointIdentity)
  await writeRouteCandidate(worktree, endpointIdentity)
  try {
    const hooks = await hooksFor(worktree)
    const configHook = hooks.config
    const chatParams = hooks["chat.params"]
    assert.ok(configHook && chatParams)
    const baseModel = { id: "gemma-4-31b-it", providerID: "google", api, options: {} }
    const streamV139 = async (config: Record<string, unknown>, ordering: { providerConstruction: number; dynamicInstall: number; chatParams: number; llmRequest: number }, model = baseModel): Promise<void> => {
      await configHook(config as never)
      const disabled = new Set(Array.isArray(config.disabled_providers) ? config.disabled_providers : [])
      if (disabled.has(model.providerID)) throw new Error("provider unavailable")

      // Exact v1.3.9 SessionLLM.stream order: getLanguage/getSDK precedes chat.params.
      ordering.providerConstruction += 1
      if (model.api.npm !== "@ai-sdk/google") ordering.dynamicInstall += 1
      ordering.chatParams += 1
      await chatParams({ agent: "k-slide", model, provider: { info: { id: "google", options: {} }, options: {} }, message: { model: { providerID: "google", modelID: "gemma-4-31b-it" } } } as never, { options: {} } as never)
      ordering.llmRequest += 1
    }
    const unsafeConfigs = [
      { provider: { google: { models: { "gemma-4-31b-it": { provider: { npm: "evil/unbundled-provider" } } } } } },
      { provider: { google: { models: { "gemma-4-31b-it": { id: "attacker-api-id" } } } } },
      { provider: { google: { models: { "gemma-4-31b-it": { provider: { api: "https://attacker.invalid" } } } } } },
      { provider: { google: { options: { baseURL: "https://attacker.invalid" } } } },
      { agent: { "k-slide": { model: "google/gemma-4-31b-it", options: { fallback: "attacker-route" } } } },
      { agent: { "k-slide": { model: "attacker/provider" } } },
    ]
    for (const config of unsafeConfigs) {
      const ordering = { providerConstruction: 0, dynamicInstall: 0, chatParams: 0, llmRequest: 0 }
      const configuredModel = (config.agent as Record<string, unknown> | undefined)?.["k-slide"] as Record<string, unknown> | undefined
      const selectedModel = configuredModel?.model === "attacker/provider"
        ? { ...baseModel, providerID: "attacker", id: "provider", api: { ...api, npm: "evil/unbundled-provider" } }
        : baseModel
      await assert.rejects(streamV139(config, ordering, selectedModel))
      assert.deepEqual(ordering, { providerConstruction: 0, dynamicInstall: 0, chatParams: 0, llmRequest: 0 })
    }

    const approvedConfig: Record<string, unknown> = { provider: { google: { options: { apiKey: "key-is-not-a-route" } } } }
    const ordering = { providerConstruction: 0, dynamicInstall: 0, chatParams: 0, llmRequest: 0 }
    await streamV139(approvedConfig, ordering)
    assert.deepEqual(ordering, { providerConstruction: 1, dynamicInstall: 0, chatParams: 1, llmRequest: 1 })
    assert.deepEqual(approvedConfig.disabled_providers, undefined)
  } finally {
    await rm(worktree, { recursive: true, force: true })
  }
}

export async function candidateBindingBoundary(): Promise<void> {
  const api = { id: "gemma-4-31b-it", npm: "@ai-sdk/google", url: "https://generativelanguage.googleapis.com/v1beta" }
  const endpointIdentity = opencodeRouteIdentity({ providerID: "google", modelID: "gemma-4-31b-it", apiID: api.id, apiNpm: api.npm, apiURL: api.url })
  const locations = [
    ".k-slide-config/resolved-candidate.json",
    ".k-slide-config/production-candidate.json",
    "resolved-candidate.json",
    "production-candidate.json",
    "evals/production-candidate.yaml",
  ]
  for (const location of locations) {
    const worktree = await mkdtemp(path.join(path.resolve(tmpdir()), "k-slide-candidate-source-"))
    try {
      await writeRoutePolicy(worktree, endpointIdentity)
      await writeRouteCandidate(worktree, endpointIdentity, location)
      assert.equal(await deploymentBoundRouteIdentity(worktree), endpointIdentity, location)
    } finally {
      await rm(worktree, { recursive: true, force: true })
    }
  }

  const worktree = await mkdtemp(path.join(path.resolve(tmpdir()), "k-slide-candidate-negative-"))
  try {
    await writeRoutePolicy(worktree, endpointIdentity)
    assert.equal(await deploymentBoundRouteIdentity(worktree), "")

    await writeRouteCandidate(worktree, endpointIdentity, ".k-slide-config/production-candidate.json", (candidate) => ({ ...candidate, requested_model: "UNSET" }))
    assert.equal(await deploymentBoundRouteIdentity(worktree), "")

    await rm(path.join(worktree, ".k-slide-config/production-candidate.json"), { force: true })
    await writeRouteCandidate(worktree, endpointIdentity, ".k-slide-config/resolved-candidate.json")
    await writeRouteCandidate(worktree, endpointIdentity, ".k-slide-config/production-candidate.json", (candidate) => ({ ...candidate, effective_model: "google/other-model" }))
    assert.equal(await deploymentBoundRouteIdentity(worktree), "")

    await rm(path.join(worktree, ".k-slide-config", "production-candidate.json"), { force: true })
    await writeRouteCandidate(worktree, endpointIdentity, ".k-slide-config/production-candidate.json")
    assert.equal(await deploymentBoundRouteIdentity(worktree), endpointIdentity)

    await rm(path.join(worktree, ".k-slide-config/production-candidate.json"), { force: true })
    const candidateTarget = await writeRouteCandidate(worktree, endpointIdentity, "candidate-target.json")
    await symlink(candidateTarget, path.join(worktree, ".k-slide-config", "production-candidate.json"))
    assert.equal(await deploymentBoundRouteIdentity(worktree), "")

    await rm(path.join(worktree, ".k-slide-config", "production-candidate.json"), { force: true })
    await writeRouteCandidate(worktree, endpointIdentity)
    const policyTarget = path.join(worktree, "egress-policy-target.json")
    await writeFile(policyTarget, await readFile(path.join(worktree, ".k-slide-config", "egress-policy.json")))
    await rm(path.join(worktree, ".k-slide-config", "egress-policy.json"), { force: true })
    await symlink(policyTarget, path.join(worktree, ".k-slide-config", "egress-policy.json"))
    assert.equal(await deploymentBoundRouteIdentity(worktree), "")

    await rm(path.join(worktree, ".k-slide-config", "egress-policy.json"), { force: true })
    await writeRoutePolicy(worktree, endpointIdentity, (policy) => ({ ...policy, default_action: "allow" }))
    assert.equal(await deploymentBoundRouteIdentity(worktree), "")

    await writeRoutePolicy(worktree, endpointIdentity)
    await writeRouteCandidate(worktree, "a".repeat(64))
    assert.equal(await deploymentBoundRouteIdentity(worktree), "")
  } finally {
    await rm(worktree, { recursive: true, force: true })
  }
}

export async function openCodeV139PluginLoaderCompatibilityBoundary(): Promise<void> {
  const autoDiscovered: string[] = []
  for (const directoryName of ["plugin", "plugins"]) {
    const directory = path.join(ROOT, ".opencode", directoryName)
    let entries
    try {
      entries = await readdir(directory, { withFileTypes: true })
    } catch {
      continue
    }
    for (const entry of entries) {
      if (entry.isFile() && /\.(?:ts|js)$/.test(entry.name)) autoDiscovered.push(path.join(directory, entry.name))
    }
  }
  autoDiscovered.sort()

  const helper = path.join(ROOT, ".opencode", "internal", "lib", "k-slide-access-key.ts")
  assert.ok(await stat(helper))
  assert.equal(autoDiscovered.includes(helper), false)
  assert.equal(autoDiscovered.some((file) => path.basename(file) === "k-slide-access-key.ts"), false)
  assert.ok(autoDiscovered.length > 0)

  for (const file of autoDiscovered) {
    const loaded = await import(pathToFileURL(file).href)
    assert.equal(typeof loaded.default, "function", `OpenCode v1.3.9 rejected ${file}: Plugin export is not a function`)
  }

  const hostSource = await readFile(path.join(ROOT, ".opencode", "plugin", "k-slide-host.ts"), "utf8")
  const toolSource = await readFile(path.join(ROOT, ".opencode", "tools", "kslide.ts"), "utf8")
  const canonicalImport = "../internal/lib/k-slide-access-key.ts"
  assert.match(hostSource, new RegExp(`from [\"']${canonicalImport.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}[\"']`))
  assert.match(toolSource, new RegExp(`from [\"']${canonicalImport.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}[\"']`))
  assert.doesNotMatch(hostSource, /from [\"']\.\/k-slide-access-key\.ts[\"']/) // The helper is not an independent plugin entrypoint.
  assert.doesNotMatch(hostSource, /hostClassificationForPart|part as unknown as \{ classification/)
  assert.doesNotMatch(toolSource, /classification: tool\.schema/)
}

async function main(): Promise<void> {
  await openCodeV139PluginLoaderCompatibilityBoundary()
  await routingBoundary()
  await replacementBoundary()
  await successBoundary()
  await failureBoundary()
  await negativeBoundary()
  await v139ProviderOrderingBoundary()
  await candidateBindingBoundary()
  await modelPinBoundary()
  console.log("OpenCode host attachment regression tests passed")
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error: unknown) => {
    console.error(error)
    process.exitCode = 1
  })
}
