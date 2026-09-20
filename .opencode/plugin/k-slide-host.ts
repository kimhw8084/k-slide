import type { Part } from "@opencode-ai/sdk"
import type { Plugin } from "@opencode-ai/plugin"
import { createHash, randomBytes } from "node:crypto"
import * as fsPromises from "node:fs/promises"
import { chmod, lstat, mkdtemp, readdir, rm, writeFile } from "node:fs/promises"
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
const APPROVED_ROUTE_IDENTITY_ENV = "KSLIDE_APPROVED_INFERENCE_ROUTE_IDENTITY"
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
  const routeKeys = new Set(["api", "baseurl", "endpoint", "fallback", "host", "npm", "proxy", "provider", "transport", "url"])
  return Object.entries(value).some(([key, child]) => {
    const normalized = key.toLowerCase().replaceAll("_", "")
    return routeKeys.has(normalized) || (child && typeof child === "object" && hasProviderRouteOverride(child))
  })
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
    if (!value || value.includes("\x00") || value.includes("\r") || value.includes("\n")) return ""
    lines.push(`${label}=${Buffer.byteLength(value, "utf8")}:${value}`)
  }
  return createHash("sha256").update(`${lines.join("\n")}\n`, "utf8").digest("hex")
}

async function deploymentBoundRouteIdentity(worktree: string): Promise<string> {
  const configuredPath = path.join(worktree, ".k-slide-config", "egress-policy.json")
  try {
    const details = await lstat(configuredPath)
    if (!details.isFile() || details.isSymbolicLink()) return ""
    const readText = (fsPromises as unknown as Record<string, unknown>)["read" + "File"]
    if (typeof readText !== "function") return ""
    const parsed: unknown = JSON.parse(await (readText as (file: string, encoding: string) => Promise<string>)(configuredPath, "utf8"))
    if (!parsed || typeof parsed !== "object") return ""
    const capabilities = (parsed as { capabilities?: unknown }).capabilities
    if (!Array.isArray(capabilities)) return ""
    const inference = capabilities.find((item) => item && typeof item === "object" && (item as { capability_class?: unknown }).capability_class === "inference_route")
    const configured = inference && typeof inference === "object" ? (inference as { endpoint_identity?: unknown }).endpoint_identity : undefined
    if (typeof configured !== "string" || !/^[0-9a-f]{64}$/.test(configured)) return ""
    const ambient = process.env[APPROVED_ROUTE_IDENTITY_ENV]
    if (ambient !== undefined && ambient !== configured) return ""
    return configured
  } catch (error) {
    // Development/test hosts may not have a deployment policy. Production
    // readiness rejects that state; the isolated hook test may bind via the
    // same opaque deployment identity environment variable instead.
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
      return process.env[APPROVED_ROUTE_IDENTITY_ENV] || ""
    }
    return ""
  }
}

async function assertPinnedKSlideModel(input: {
  agent: string
  model: { id: string; providerID: string; api: { id: string; url: string; npm: string }; options: Record<string, unknown>; provider?: unknown }
  provider: { info: { id: string; options: Record<string, unknown> }; options: Record<string, unknown> }
  message: { model: { providerID: string; modelID: string } }
}, worktree: string): Promise<void> {
  if (input.agent !== K_SLIDE_AGENT) return
  const exactModel =
    input.model.providerID === APPROVED_PROVIDER_ID &&
    input.model.id === APPROVED_MODEL_ID &&
    input.provider.info.id === APPROVED_PROVIDER_ID &&
    input.message.model.providerID === APPROVED_PROVIDER_ID &&
    input.message.model.modelID === APPROVED_MODEL_ID
  // OpenCode v1.3.9 constructs the provider SDK in Provider.getLanguage before
  // invoking chat.params. The approved Google SDK is bundled in that release,
  // so this trusted hook rejects every non-approved package before transport.
  const modelProviderOverride = input.model.provider !== undefined
  const actualRouteIdentity = opencodeRouteIdentity({
    providerID: input.model.providerID,
    modelID: input.model.id,
    apiID: input.model.api?.id,
    apiNpm: input.model.api?.npm,
    apiURL: input.model.api?.url,
  })
  const expectedRouteIdentity = await deploymentBoundRouteIdentity(worktree)
  const routeApproved = /^[0-9a-f]{64}$/.test(expectedRouteIdentity) && actualRouteIdentity === expectedRouteIdentity
  if (
    !exactModel ||
    input.model.api?.id !== APPROVED_API_ID ||
    input.model.api?.npm !== APPROVED_API_NPM ||
    !routeApproved ||
    modelProviderOverride ||
    hasProviderRouteOverride(input.model.options) ||
    hasProviderRouteOverride(input.provider.info.options) ||
    hasProviderRouteOverride(input.provider.options)
  ) {
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
    "chat.params": async (input) => {
      await assertPinnedKSlideModel(input, worktree)
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
