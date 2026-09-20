import type { Part } from "@opencode-ai/sdk"
import type { Plugin } from "@opencode-ai/plugin"
import { createHash, randomBytes } from "node:crypto"
import { chmod, lstat, mkdtemp, open, readdir, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { trustedAccessKey } from "../internal/lib/k-slide-access-key.ts"

type HostInputReference = {
  source_kind: "attachment" | "workspace_file"
  logical_name: string
  locator: string
  classification: string
}

type FilePart = Extract<Part, { type: "file" }>

type SessionInputs = {
  refs: HostInputReference[]
  stagingDirectory?: string
}

const MAX_INPUT_BYTES = 512 * 1024 * 1024
const STAGING_PREFIX = "k-slide-opencode-attachments-"
const DEFAULT_CLASSIFICATION = "company_confidential"
const K_SLIDE_AGENT = "k-slide"
const APPROVED_PROVIDER_ID = "google"
const APPROVED_MODEL_ID = "gemma-4-31b-it"
const APPROVED_API_ID = "gemma-4-31b-it"
const APPROVED_API_NPM = "@ai-sdk/google"
const EGRESS_POLICY_SCHEMA_VERSION = "1.0"
const EGRESS_DEFAULT_ACTION = "deny"
const EGRESS_CAPABILITY_CLASSES = new Set(["inference_route", "durable_job_control", "scoped_storage", "non_content_telemetry"])
const EGRESS_CAPABILITY_FIELDS = new Set(["capability_class", "purpose", "service_identity", "route_identity", "endpoint_identity", "data_class"])
const DATA_URL = /^data:([^;,]+);base64,([A-Za-z0-9+/]*={0,2})$/
const URI_SCHEME = /^[A-Za-z][A-Za-z\d+.-]*:/

void trustedAccessKey

const extensionByMime: Record<string, string> = {
  "image/png": ".png",
  "image/jpeg": ".jpg",
  "image/webp": ".webp",
  "application/pdf": ".pdf",
  "application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx",
}

const extensionsByMime: Record<string, readonly string[]> = {
  "image/png": [".png"],
  "image/jpeg": [".jpg", ".jpeg"],
  "image/webp": [".webp"],
  "application/pdf": [".pdf"],
  "application/vnd.openxmlformats-officedocument.presentationml.presentation": [".pptx"],
}

function isFilePart(part: Part): part is FilePart {
  return part.type === "file"
}

function isSupportedMime(value: unknown): value is string {
  return typeof value === "string" && Boolean(extensionByMime[value.toLowerCase()])
}

function normalizedMime(value: unknown): string {
  if (!isSupportedMime(value)) throw new Error("K-Slide attachment was rejected.")
  return value.toLowerCase()
}

function hasProviderRouteOverride(value: unknown): boolean {
  if (!value || typeof value !== "object") return false
  const routeKeys = new Set([
    "api",
    "apiid",
    "apinpm",
    "apiurl",
    "baseurl",
    "endpoint",
    "fallback",
    "host",
    "model",
    "npm",
    "package",
    "packagename",
    "proxy",
    "provider",
    "route",
    "transport",
    "url",
  ])
  return Object.entries(value).some(([key, child]) => {
    const normalized = key.toLowerCase().replaceAll("_", "").replaceAll("-", "")
    return routeKeys.has(normalized) || (child && typeof child === "object" && hasProviderRouteOverride(child))
  })
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "number" || typeof value === "boolean") return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(",")}]`
  if (typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, child]) => `${JSON.stringify(key)}:${canonicalJson(child)}`)
      .join(",")}}`
  }
  throw new Error("K-Slide deployment policy is malformed.")
}

function sha256Text(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex")
}

function isSha256(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value)
}

export function opencodeRouteIdentity(route: { providerID: string; modelID: string; apiID: string; apiNpm: string; apiURL: string }): string {
  const values = [
    ["providerID", route.providerID],
    ["modelID", route.modelID],
    ["api.id", route.apiID],
    ["api.npm", route.apiNpm],
    ["api.url", route.apiURL],
  ] as const
  const lines = ["k-slide-opencode-route-v1"]
  for (const [label, value] of values) {
    if (typeof value !== "string" || !value || value.includes("\x00") || value.includes("\r") || value.includes("\n")) return ""
    lines.push(`${label}=${Buffer.byteLength(value, "utf8")}:${value}`)
  }
  return sha256Text(`${lines.join("\n")}\n`)
}

function providerInfo(provider: unknown): { id: unknown; options: unknown } {
  if (!provider || typeof provider !== "object") return { id: undefined, options: undefined }
  const value = provider as Record<string, unknown>
  const info = value.info && typeof value.info === "object" ? value.info as Record<string, unknown> : value
  return { id: info.id, options: [info.options, value.options] }
}

async function readUtf8(filePath: string): Promise<string> {
  const handle = await open(filePath, "r")
  try {
    const details = await handle.stat()
    if (!Number.isSafeInteger(details.size) || details.size < 0 || details.size > 4 * 1024 * 1024) throw new Error("K-Slide deployment policy is malformed.")
    const buffer = Buffer.alloc(details.size)
    let offset = 0
    while (offset < buffer.length) {
      const result = await handle.read(buffer, offset, buffer.length - offset, offset)
      if (result.bytesRead === 0) throw new Error("K-Slide deployment policy is malformed.")
      offset += result.bytesRead
    }
    return buffer.toString("utf8")
  } finally {
    await handle.close()
  }
}

function assertPolicyShape(value: unknown): { endpointIdentity: string; policyVersion: string; policyHash: string; policyIdentity: string } {
  if (!value || typeof value !== "object") throw new Error("K-Slide deployment policy is malformed.")
  const policy = value as Record<string, unknown>
  if (new Set(Object.keys(policy)).size !== 6 || !["schema_version", "policy_version", "policy_hash", "policy_identity", "default_action", "capabilities"].every((key) => key in policy)) {
    throw new Error("K-Slide deployment policy is malformed.")
  }
  if (policy.schema_version !== EGRESS_POLICY_SCHEMA_VERSION || policy.default_action !== EGRESS_DEFAULT_ACTION || typeof policy.policy_version !== "string" || !policy.policy_version || !isSha256(policy.policy_hash) || !isSha256(policy.policy_identity) || !Array.isArray(policy.capabilities) || policy.capabilities.length !== 4) {
    throw new Error("K-Slide deployment policy is malformed.")
  }
  const capabilities = policy.capabilities.map((item) => {
    if (!item || typeof item !== "object") throw new Error("K-Slide deployment policy is malformed.")
    const capability = item as Record<string, unknown>
    if (new Set(Object.keys(capability)).size !== EGRESS_CAPABILITY_FIELDS.size || [...EGRESS_CAPABILITY_FIELDS].some((key) => !(key in capability))) {
      throw new Error("K-Slide deployment policy is malformed.")
    }
    const capabilityClass = capability.capability_class
    if (typeof capabilityClass !== "string" || !EGRESS_CAPABILITY_CLASSES.has(capabilityClass) || typeof capability.purpose !== "string" || typeof capability.service_identity !== "string") {
      throw new Error("K-Slide deployment policy is malformed.")
    }
    const expectedPurpose: Record<string, string> = {
      inference_route: "model_inference",
      durable_job_control: "job_control",
      scoped_storage: "scoped_storage",
      non_content_telemetry: "non_content_telemetry",
    }
    const expectedDataClass: Record<string, string> = {
      inference_route: "source_content",
      durable_job_control: "operational_metadata",
      scoped_storage: "source_content",
      non_content_telemetry: "non_content",
    }
    if (capability.purpose !== expectedPurpose[capabilityClass] || capability.data_class !== expectedDataClass[capabilityClass]) throw new Error("K-Slide deployment policy is malformed.")
    if (capabilityClass === "inference_route") {
      if (typeof capability.route_identity !== "string" || !capability.route_identity || !isSha256(capability.endpoint_identity)) throw new Error("K-Slide deployment policy is malformed.")
    } else if (capability.route_identity !== null || capability.endpoint_identity !== null) {
      throw new Error("K-Slide deployment policy is malformed.")
    }
    return {
      capability_class: capability.capability_class,
      purpose: capability.purpose,
      service_identity: capability.service_identity,
      route_identity: capability.route_identity,
      endpoint_identity: capability.endpoint_identity,
      data_class: capability.data_class,
    }
  }).sort((left, right) => left.capability_class.localeCompare(right.capability_class))
  if (new Set(capabilities.map((item) => item.capability_class)).size !== 4) throw new Error("K-Slide deployment policy is malformed.")
  const expectedHash = sha256Text(canonicalJson({ schema_version: EGRESS_POLICY_SCHEMA_VERSION, policy_version: policy.policy_version, default_action: EGRESS_DEFAULT_ACTION, capabilities }))
  const expectedIdentity = sha256Text(canonicalJson({ schema_version: EGRESS_POLICY_SCHEMA_VERSION, policy_version: policy.policy_version, policy_hash: expectedHash }))
  if (policy.policy_hash !== expectedHash || policy.policy_identity !== expectedIdentity) throw new Error("K-Slide deployment policy is malformed.")
  const inference = capabilities.find((item) => item.capability_class === "inference_route")
  if (!inference || !isSha256(inference.endpoint_identity)) throw new Error("K-Slide deployment policy is malformed.")
  return { endpointIdentity: inference.endpoint_identity, policyVersion: policy.policy_version, policyHash: policy.policy_hash, policyIdentity: policy.policy_identity }
}

async function deploymentBoundRouteIdentity(worktree: string): Promise<string> {
  const policyPath = path.join(worktree, ".k-slide-config", "egress-policy.json")
  try {
    const details = await lstat(policyPath)
    if (!details.isFile() || details.isSymbolicLink()) return ""
    const binding = assertPolicyShape(JSON.parse(await readUtf8(policyPath)))
    const candidatePath = path.join(worktree, ".k-slide-config", "production-candidate.json")
    try {
      const candidateDetails = await lstat(candidatePath)
      if (!candidateDetails.isFile() || candidateDetails.isSymbolicLink()) return ""
      const candidateValue = JSON.parse(await readUtf8(candidatePath)) as Record<string, unknown>
      const candidate = candidateValue.candidate_spec && typeof candidateValue.candidate_spec === "object" ? candidateValue.candidate_spec as Record<string, unknown> : candidateValue
      for (const [key, expected] of Object.entries({
        egress_policy_version: binding.policyVersion,
        egress_policy_hash: binding.policyHash,
        egress_policy_identity: binding.policyIdentity,
        inference_endpoint_identity: binding.endpointIdentity,
      })) {
        if (candidate[key] !== expected) return ""
      }
    } catch (error) {
      if (!(error && typeof error === "object" && "code" in error && error.code === "ENOENT")) return ""
    }
    return binding.endpointIdentity
  } catch {
    return ""
  }
}

async function assertPinnedKSlideModel(input: {
  agent: string
  model: { id: string; providerID: string; api: { id: string; url: string; npm: string }; options: Record<string, unknown>; provider?: unknown }
  provider: unknown
  message: { model: { providerID: string; modelID: string } }
}, worktree: string, output: unknown): Promise<void> {
  if (input.agent !== K_SLIDE_AGENT) return
  const provider = providerInfo(input.provider)
  const exactModel =
    input.model.providerID === APPROVED_PROVIDER_ID &&
    input.model.id === APPROVED_MODEL_ID &&
    provider.id === APPROVED_PROVIDER_ID &&
    input.message.model.providerID === APPROVED_PROVIDER_ID &&
    input.message.model.modelID === APPROVED_MODEL_ID
  const actualRouteIdentity = opencodeRouteIdentity({
    providerID: input.model.providerID,
    modelID: input.model.id,
    apiID: input.model.api?.id,
    apiNpm: input.model.api?.npm,
    apiURL: input.model.api?.url,
  })
  const expectedRouteIdentity = await deploymentBoundRouteIdentity(worktree)
  const routeApproved = isSha256(expectedRouteIdentity) && actualRouteIdentity === expectedRouteIdentity
  const outputOptions = output && typeof output === "object" && "options" in output ? (output as { options?: unknown }).options : undefined
  if (!exactModel || input.model.api?.id !== APPROVED_API_ID || input.model.api?.npm !== APPROVED_API_NPM || !routeApproved || input.model.provider !== undefined || hasProviderRouteOverride(input.model.options) || hasProviderRouteOverride(provider.options) || hasProviderRouteOverride(outputOptions)) {
    throw new Error("K-Slide refused an unapproved provider/model or provider route before the LLM request.")
  }
}

function isSafeLogicalName(value: string): boolean {
  return Boolean(value) && value !== "." && value !== ".." && !value.includes("\x00") && !value.includes("/") && !value.includes("\\")
}

function logicalNameForPart(part: FilePart, index: number, mime?: string, sourcePath?: string, locator?: string): string {
  const fallbackExtension = mime && extensionByMime[mime] ? extensionByMime[mime] : ""
  const fallback = `attachment-${String(index).padStart(3, "0")}${fallbackExtension}`
  let name = part.filename || ""
  if (!name && sourcePath) name = path.basename(sourcePath)
  if (!name && locator && !URI_SCHEME.test(locator)) name = path.basename(locator)
  if (!name && locator?.toLowerCase().startsWith("file:")) {
    try {
      name = path.basename(fileURLToPath(new URL(locator)))
    } catch {
      name = ""
    }
  }
  name = name || fallback
  if (!isSafeLogicalName(name)) throw new Error("K-Slide attachment was rejected.")
  const extension = path.extname(name).toLowerCase()
  if (!Object.values(extensionsByMime).some((extensions) => extensions.includes(extension))) {
    throw new Error("K-Slide attachment was rejected.")
  }
  if (mime && !extensionsByMime[mime]?.includes(extension)) {
    throw new Error("K-Slide attachment was rejected.")
  }
  return name
}

function sourcePathForPart(part: FilePart): string | undefined {
  const source = part.source
  if (!source || typeof source !== "object") return undefined
  const candidate = "path" in source ? source.path : undefined
  return typeof candidate === "string" && candidate.length > 0 ? candidate : undefined
}

function isInside(root: string, candidate: string): boolean {
  const relative = path.relative(path.resolve(root), path.resolve(root, candidate))
  return relative === "" || (relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative))
}

function sourceKindForLocator(locator: string, worktree: string): HostInputReference["source_kind"] {
  try {
    const parsed = URI_SCHEME.test(locator) ? new URL(locator) : undefined
    const localPath = parsed ? fileURLToPath(parsed) : locator
    return isInside(worktree, localPath) ? "workspace_file" : "attachment"
  } catch {
    return "attachment"
  }
}

function localReference(part: FilePart, index: number, worktree: string, sourcePath?: string): HostInputReference {
  const locator = sourcePath || part.url
  if (typeof locator !== "string" || !locator || locator.includes("\x00")) throw new Error("K-Slide attachment was rejected.")
  const scheme = locator.match(URI_SCHEME)?.[0].slice(0, -1).toLowerCase()
  if (scheme && scheme !== "file") throw new Error("K-Slide attachment was rejected.")
  const logicalName = logicalNameForPart(part, index, undefined, sourcePath, locator)
  return { source_kind: sourceKindForLocator(locator, worktree), logical_name: logicalName, locator, classification: DEFAULT_CLASSIFICATION }
}

function decodedDataByteLength(encodedLength: number, padding: number): number {
  if (!Number.isSafeInteger(encodedLength) || !Number.isSafeInteger(padding) || encodedLength < 0 || padding < 0 || padding > 2) return -1
  return (encodedLength / 4) * 3 - padding
}

function decodedDataUrl(part: FilePart): { mime: string; bytes: Buffer } {
  const mime = normalizedMime(part.mime)
  if (typeof part.url !== "string") throw new Error("K-Slide attachment was rejected.")
  const match = DATA_URL.exec(part.url)
  if (!match || match[1].toLowerCase() !== mime) throw new Error("K-Slide attachment was rejected.")
  const encoded = match[2]
  if (!encoded || encoded.length % 4 !== 0) throw new Error("K-Slide attachment was rejected.")
  const padding = encoded.endsWith("==") ? 2 : encoded.endsWith("=") ? 1 : 0
  const decodedLength = decodedDataByteLength(encoded.length, padding)
  if (decodedLength <= 0 || decodedLength > MAX_INPUT_BYTES) throw new Error("K-Slide attachment was rejected.")
  const bytes = Buffer.from(encoded, "base64")
  if (bytes.length !== decodedLength || bytes.toString("base64") !== encoded) throw new Error("K-Slide attachment was rejected.")
  return { mime, bytes }
}

function sessionDigest(sessionID: string): string {
  return createHash("sha256").update(sessionID).digest("hex")
}

function stagingPrefix(sessionID: string): string {
  return `${STAGING_PREFIX}${sessionDigest(sessionID)}-`
}

async function removeOwnedStaging(directory: string, sessionID: string): Promise<void> {
  const root = path.resolve(tmpdir())
  const candidate = path.resolve(directory)
  const relative = path.relative(root, candidate)
  if (!relative || relative.includes(path.sep) || !path.basename(candidate).startsWith(stagingPrefix(sessionID))) return
  try {
    const details = await lstat(candidate)
    if (!details.isDirectory() || details.isSymbolicLink()) return
    await rm(candidate, { recursive: true, force: true })
  } catch {
    // Cleanup is best effort and never crosses the private staging boundary.
  }
}

async function cleanupStaleStaging(sessionID: string): Promise<void> {
  const root = path.resolve(tmpdir())
  const prefix = stagingPrefix(sessionID)
  try {
    const entries = await readdir(root, { withFileTypes: true })
    await Promise.all(
      entries
        .filter((entry) => entry.isDirectory() && entry.name.startsWith(prefix))
        .map((entry) => removeOwnedStaging(path.join(root, entry.name), sessionID)),
    )
  } catch {
    // Cleanup is best effort and never affects attachment validation.
  }
}

async function createStagingDirectory(sessionID: string): Promise<string> {
  await cleanupStaleStaging(sessionID)
  const directory = await mkdtemp(path.join(path.resolve(tmpdir()), stagingPrefix(sessionID)))
  await chmod(directory, 0o700)
  return directory
}

function unavailableLocator(sessionID: string): string {
  return path.join(path.resolve(tmpdir()), `${stagingPrefix(sessionID)}unmaterialized-${randomBytes(18).toString("hex")}.missing`)
}

function rejectedReference(sessionID: string, index: number, mime: unknown, stagingDirectory?: string): HostInputReference {
  const normalized = typeof mime === "string" ? mime.toLowerCase() : ""
  // Keep the rejection packet schema-valid even when the advertised MIME is
  // unsupported; the missing private locator makes prepare persist FAILED_INPUT.
  const extension = extensionByMime[normalized] || ".png"
  const locator = stagingDirectory
    ? path.join(stagingDirectory, `rejected-${randomBytes(18).toString("hex")}.missing`)
    : unavailableLocator(sessionID)
  return {
    source_kind: "attachment",
    logical_name: `attachment-${String(index).padStart(3, "0")}${extension}`,
    locator,
    classification: DEFAULT_CLASSIFICATION,
  }
}

async function materializeDataAttachment(part: FilePart, index: number, stagingDirectory: string): Promise<HostInputReference> {
  const { mime, bytes } = decodedDataUrl(part)
  const logicalName = logicalNameForPart(part, index, mime)
  const destination = path.join(stagingDirectory, `attachment-${randomBytes(18).toString("hex")}${extensionByMime[mime]}`)
  await writeFile(destination, bytes, { flag: "wx", mode: 0o600 })
  await chmod(destination, 0o600)
  return { source_kind: "attachment", logical_name: logicalName, locator: destination, classification: DEFAULT_CLASSIFICATION }
}

async function referenceFromPart(part: FilePart, index: number, sessionID: string, worktree: string, stagingDirectory?: string): Promise<{ ref: HostInputReference; stagingDirectory?: string }> {
  const sourcePath = sourcePathForPart(part)
  if (sourcePath) return { ref: localReference(part, index, worktree, sourcePath), stagingDirectory }

  if (typeof part.url === "string" && part.url.startsWith("data:")) {
    const directory = stagingDirectory || await createStagingDirectory(sessionID)
    try {
      return { ref: await materializeDataAttachment(part, index, directory), stagingDirectory: directory }
    } catch {
      return { ref: rejectedReference(sessionID, index, part.mime, directory), stagingDirectory: directory }
    }
  }

  return { ref: localReference(part, index, worktree), stagingDirectory }
}

const KSlideHostPlugin: Plugin = async ({ worktree }) => {
  const currentMessageInputs = new Map<string, SessionInputs>()

  const isKSlideInvocation = (input: { agent?: string }): boolean => input.agent === K_SLIDE_AGENT

  const releaseSession = async (sessionID: string): Promise<void> => {
    const current = currentMessageInputs.get(sessionID)
    currentMessageInputs.delete(sessionID)
    if (current?.stagingDirectory) await removeOwnedStaging(current.stagingDirectory, sessionID)
    await cleanupStaleStaging(sessionID)
  }

  return {
    "chat.params": async (input, output) => {
      await assertPinnedKSlideModel(input, worktree, output)
    },
    "chat.message": async (input, output) => {
      await releaseSession(input.sessionID)
      if (!isKSlideInvocation(input)) return

      const refs: HostInputReference[] = []
      let stagingDirectory: string | undefined
      const fileParts = output.parts.filter(isFilePart)
      for (const [offset, part] of fileParts.entries()) {
        const index = offset + 1
        try {
          const captured = await referenceFromPart(part, index, input.sessionID, worktree, stagingDirectory)
          refs.push(captured.ref)
          stagingDirectory = captured.stagingDirectory
        } catch {
          refs.push(rejectedReference(input.sessionID, index, part.mime, stagingDirectory))
        }
      }
      for (let index = output.parts.length - 1; index >= 0; index -= 1) {
        if (isFilePart(output.parts[index])) output.parts.splice(index, 1)
      }
      currentMessageInputs.set(input.sessionID, { refs, stagingDirectory })
    },
    "tool.execute.before": async (input, output) => {
      if (input.tool !== "kslide_prepare") return
      const args = output.args && typeof output.args === "object" ? { ...output.args } : {}
      delete (args as { host_input_refs?: unknown }).host_input_refs
      delete (args as { classification?: unknown }).classification
      delete (args as { classifications?: unknown }).classifications
      delete (args as { classification_policy?: unknown }).classification_policy
      delete (args as { inference_route_identity?: unknown }).inference_route_identity
      delete (args as { inference_data_use_policy?: unknown }).inference_data_use_policy
      delete (args as { inference_data_policy?: unknown }).inference_data_policy
      const references = currentMessageInputs.get(input.sessionID)?.refs || []
      if (Array.isArray((args as { explicit_input_paths?: unknown }).explicit_input_paths) && (args as { explicit_input_paths: unknown[] }).explicit_input_paths.length) {
        output.args = args
        return
      }
      output.args = references.length ? { ...args, host_input_refs: references } : args
    },
    "tool.execute.after": async (input) => {
      if (input.tool === "kslide_prepare") await releaseSession(input.sessionID)
    },
  }
}

export default KSlideHostPlugin
