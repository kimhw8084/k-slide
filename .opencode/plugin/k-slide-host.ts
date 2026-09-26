import type { Part } from "@opencode-ai/sdk"
import type { Config, Plugin } from "@opencode-ai/plugin"
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
  rejection_code?: "KSLIDE_INPUT_TOO_LARGE" | "KSLIDE_RESOURCE_LIMIT" | "KSLIDE_RESOURCE_BUDGET_INVALID" | "KSLIDE_RESOURCE_BUDGET_UNAVAILABLE"
}

type FilePart = Extract<Part, { type: "file" }>

type SessionInputs = {
  refs: HostInputReference[]
  stagingDirectory?: string
}

const MAX_INPUT_BYTES = 512 * 1024 * 1024
const RESOURCE_BUDGET_CEILINGS: Record<string, number> = {
  max_file_bytes: 512 * 1024 * 1024,
  max_total_file_bytes_per_run: 2_000_000_000,
  max_documents_per_run: 32,
  max_pdf_pages_per_document: 200,
  max_pptx_slides_per_deck: 200,
  max_work_units_per_run: 500,
  max_pixels_per_image: 120_000_000,
  max_total_decoded_pixels_per_run: 500_000_000,
  max_normalized_bytes_per_run: 2_000_000_000,
  max_image_dimension: 20_000,
  max_media_items_per_work_unit: 256,
  model_media_token_reserve_per_item: 1_024,
  max_model_input_tokens_per_work_unit: 2_000_000,
  max_model_output_tokens_per_work_unit: 2_000_000,
  max_model_tokens_per_run: 100_000_000,
  max_concurrent_runs_per_scope: 1,
  max_queued_runs_per_scope: 100_000,
  max_concurrent_work_units_per_run: 1,
}
const RESOURCE_BUDGET_FIELDS = [...Object.keys(RESOURCE_BUDGET_CEILINGS), "max_media_duration_seconds"].sort()
const STAGING_PREFIX = "k-slide-opencode-attachments-"
const DEFAULT_CLASSIFICATION = "company_confidential"
const K_SLIDE_AGENT = "k-slide"
const APPROVED_PROVIDER_ID = "google"
const APPROVED_MODEL_ID = "gemma-4-31b-it"
const APPROVED_API_ID = "gemma-4-31b-it"
const APPROVED_API_NPM = "@ai-sdk/google"
const APPROVED_API_URL = "https://generativelanguage.googleapis.com/v1beta"
const EGRESS_POLICY_SCHEMA_VERSION = "1.0"
const EGRESS_DEFAULT_ACTION = "deny"
const EGRESS_CAPABILITY_CLASSES = new Set(["inference_route", "durable_job_control", "scoped_storage", "non_content_telemetry"])
const EGRESS_CAPABILITY_FIELDS = new Set(["capability_class", "purpose", "service_identity", "route_identity", "endpoint_identity", "data_class"])
const DATA_URL = /^data:([^;,]+);base64,([A-Za-z0-9+/]*={0,2})$/
const URI_SCHEME = /^[A-Za-z][A-Za-z\d+.-]*:/
const IDENTITY = /^[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}$/
const POLICY_VERSION = /^[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,127}$/
const FORBIDDEN_IDENTITY_MARKERS = ["access", "credential", "password", "prompt", "secret", "source_text", "token"]
const CANDIDATE_SOURCES = [
  [".k-slide-config", "resolved-candidate.json"],
  [".k-slide-config", "production-candidate.json"],
  ["resolved-candidate.json"],
  ["production-candidate.json"],
  ["evals", "production-candidate.yaml"],
] as const
const ROUTE_CONTROL_KEYS = new Set([
  "api",
  "apiid",
  "apinpm",
  "apiurl",
  "backend",
  "baseurl",
  "endpoint",
  "fallback",
  "host",
  "headers",
  "model",
  "npm",
  "package",
  "packagename",
  "proxy",
  "provider",
  "route",
  "transport",
  "url",
  "variants",
])
const PROVIDER_ROUTE_KEYS = new Set([...ROUTE_CONTROL_KEYS, "headers", "provider"])

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
  return Object.entries(value).some(([key, child]) => {
    const normalized = key.toLowerCase().replaceAll("_", "").replaceAll("-", "")
    return ROUTE_CONTROL_KEYS.has(normalized) || (child && typeof child === "object" && hasProviderRouteOverride(child))
  })
}

function hasModelRouteOverride(value: unknown): boolean {
  return hasUnsafeRouteOverride(value, true)
}

function hasProviderConfigRouteOverride(value: unknown): boolean {
  if (!isRecord(value)) return false
  return Object.entries(value).some(([key, child]) => key !== "models" && hasUnsafeRouteEntry(key, child, false))
}

function hasUnsafeRouteEntry(key: string, child: unknown, modelContext: boolean): boolean {
  const normalized = key.toLowerCase().replaceAll("_", "").replaceAll("-", "")
  if (normalized === "id") return modelContext && child !== APPROVED_API_ID
  if (normalized === "provider") return !isRecord(child) || hasUnsafeRouteOverride(child, false)
  if (normalized === "options") return hasUnsafeRouteOverride(child, true)
  if (normalized === "headers") return true
  if (!PROVIDER_ROUTE_KEYS.has(normalized) && !ROUTE_CONTROL_KEYS.has(normalized)) return isRecord(child) && hasUnsafeRouteOverride(child, modelContext)
  if (normalized === "npm" || normalized === "apinpm") return child !== APPROVED_API_NPM
  if (normalized === "apiid") return child !== APPROVED_API_ID
  if (normalized === "api") return modelContext || child !== APPROVED_API_URL
  if (normalized === "apiurl" || normalized === "baseurl" || normalized === "endpoint" || normalized === "host" || normalized === "url") return true
  return true
}

function hasUnsafeRouteOverride(value: unknown, modelContext = false): boolean {
  if (!value || typeof value !== "object") return false
  return Object.entries(value).some(([key, child]) => hasUnsafeRouteEntry(key, child, modelContext))
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value))
}

function providerIDForModel(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined
  const separator = value.indexOf("/")
  if (separator <= 0) return undefined
  return value.slice(0, separator)
}

function addDisabledProvider(config: Record<string, unknown>, providerID: string): void {
  if (!providerID) return
  const existing = Array.isArray(config.disabled_providers) ? config.disabled_providers.filter((value): value is string => typeof value === "string") : []
  config.disabled_providers = [...new Set([...existing, providerID])]
}

function targetModelsFromConfig(config: Record<string, unknown>): string[] {
  const targets: string[] = []
  for (const section of [config.agent, config.mode]) {
    if (!isRecord(section)) continue
    const agent = section[K_SLIDE_AGENT]
    if (isRecord(agent) && typeof agent.model === "string") targets.push(agent.model)
  }
  if (!targets.length && typeof config.model === "string") targets.push(config.model)
  if (!targets.length) targets.push(`${APPROVED_PROVIDER_ID}/${APPROVED_MODEL_ID}`)
  return targets
}

function targetProviderConfig(config: Record<string, unknown>, providerID: string, modelID: string): Record<string, unknown> | undefined {
  const providers = isRecord(config.provider) ? config.provider : undefined
  const provider = providers && isRecord(providers[providerID]) ? providers[providerID] : undefined
  if (!provider) return undefined
  if (hasProviderConfigRouteOverride(provider)) return provider
  const models = isRecord(provider.models) ? provider.models : undefined
  if (!models) return undefined
  for (const [configuredID, value] of Object.entries(models)) {
    if (!isRecord(value)) continue
    if (configuredID === modelID || value.id === modelID) {
      if (hasModelRouteOverride(value)) return value
    }
  }
  return undefined
}

function hasExactKSlideProviderSurface(config: Record<string, unknown>): boolean {
  if (!Array.isArray(config.enabled_providers) || config.enabled_providers.length !== 1 || config.enabled_providers[0] !== APPROVED_PROVIDER_ID) return false
  const providers = isRecord(config.provider) ? config.provider : undefined
  if (!providers || Object.keys(providers).length !== 1 || !isRecord(providers[APPROVED_PROVIDER_ID])) return false
  const google = providers[APPROVED_PROVIDER_ID] as Record<string, unknown>
  if (Object.keys(google).length !== 1 || !Array.isArray(google.whitelist) || google.whitelist.length !== 1 || google.whitelist[0] !== APPROVED_MODEL_ID) return false
  const disabled = Array.isArray(config.disabled_providers) ? config.disabled_providers : []
  return !disabled.includes(APPROVED_PROVIDER_ID)
}

/**
 * OpenCode v1.3.9 calls this config hook during bootstrap before any session
 * can resolve Provider.getLanguage. Config-hook exceptions are swallowed by
 * OpenCode, so this gate only mutates the merged config and never throws.
 */
export function protectKSlideProviderConfig(config: Record<string, unknown>): void {
  if (!hasExactKSlideProviderSurface(config)) {
    addDisabledProvider(config, APPROVED_PROVIDER_ID)
    config.enabled_providers = []
  }
  const targets = targetModelsFromConfig(config)
  for (const target of targets) {
    const providerID = providerIDForModel(target)
    const modelID = providerID ? target.slice(providerID.length + 1) : undefined
    if (!providerID || !modelID) {
      addDisabledProvider(config, APPROVED_PROVIDER_ID)
      continue
    }
    if (providerID !== APPROVED_PROVIDER_ID || modelID !== APPROVED_MODEL_ID) {
      addDisabledProvider(config, providerID)
      continue
    }
    if (targetProviderConfig(config, providerID, modelID)) addDisabledProvider(config, providerID)
    for (const section of [config.agent, config.mode]) {
      if (!isRecord(section)) continue
      const agent = section[K_SLIDE_AGENT]
      if (isRecord(agent) && hasUnsafeRouteOverride(agent.options, true)) addDisabledProvider(config, providerID)
    }
  }
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "number" || typeof value === "boolean") return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(",")}]`
  if (typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
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

function isIdentity(value: unknown): value is string {
  return typeof value === "string" && IDENTITY.test(value) && !value.includes("://") && !value.startsWith("/") && !value.startsWith("\\") && !FORBIDDEN_IDENTITY_MARKERS.some((marker) => value.toLowerCase().includes(marker))
}

function isPolicyVersion(value: unknown): value is string {
  return typeof value === "string" && POLICY_VERSION.test(value)
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

function assertPolicyShape(value: unknown): { endpointIdentity: string; routeIdentity: string; policyVersion: string; policyHash: string; policyIdentity: string } {
  if (!value || typeof value !== "object") throw new Error("K-Slide deployment policy is malformed.")
  const policy = value as Record<string, unknown>
  if (new Set(Object.keys(policy)).size !== 6 || !["schema_version", "policy_version", "policy_hash", "policy_identity", "default_action", "capabilities"].every((key) => key in policy)) {
    throw new Error("K-Slide deployment policy is malformed.")
  }
  if (policy.schema_version !== EGRESS_POLICY_SCHEMA_VERSION || policy.default_action !== EGRESS_DEFAULT_ACTION || !isPolicyVersion(policy.policy_version) || !isSha256(policy.policy_hash) || !isSha256(policy.policy_identity) || !Array.isArray(policy.capabilities) || policy.capabilities.length !== 4) {
    throw new Error("K-Slide deployment policy is malformed.")
  }
  const capabilities = policy.capabilities.map((item) => {
    if (!item || typeof item !== "object") throw new Error("K-Slide deployment policy is malformed.")
    const capability = item as Record<string, unknown>
    if (new Set(Object.keys(capability)).size !== EGRESS_CAPABILITY_FIELDS.size || [...EGRESS_CAPABILITY_FIELDS].some((key) => !(key in capability))) {
      throw new Error("K-Slide deployment policy is malformed.")
    }
    const capabilityClass = capability.capability_class
    if (typeof capabilityClass !== "string" || !EGRESS_CAPABILITY_CLASSES.has(capabilityClass) || typeof capability.purpose !== "string" || !isIdentity(capability.service_identity)) {
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
      if (!isIdentity(capability.route_identity) || !isSha256(capability.endpoint_identity)) throw new Error("K-Slide deployment policy is malformed.")
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
  }).sort((left, right) => left.capability_class < right.capability_class ? -1 : left.capability_class > right.capability_class ? 1 : 0)
  if (new Set(capabilities.map((item) => item.capability_class)).size !== 4) throw new Error("K-Slide deployment policy is malformed.")
  const expectedHash = sha256Text(canonicalJson({ schema_version: EGRESS_POLICY_SCHEMA_VERSION, policy_version: policy.policy_version, default_action: EGRESS_DEFAULT_ACTION, capabilities }))
  const expectedIdentity = sha256Text(canonicalJson({ schema_version: EGRESS_POLICY_SCHEMA_VERSION, policy_version: policy.policy_version, policy_hash: expectedHash }))
  if (policy.policy_hash !== expectedHash || policy.policy_identity !== expectedIdentity) throw new Error("K-Slide deployment policy is malformed.")
  const inference = capabilities.find((item) => item.capability_class === "inference_route")
  if (!inference || !isSha256(inference.endpoint_identity)) throw new Error("K-Slide deployment policy is malformed.")
  return { endpointIdentity: inference.endpoint_identity as string, routeIdentity: inference.route_identity as string, policyVersion: policy.policy_version as string, policyHash: policy.policy_hash as string, policyIdentity: policy.policy_identity as string }
}

function candidateScalar(raw: string): unknown {
  const value = raw.trim()
  if (!value) return {}
  if (value === "null" || value === "NULL" || value === "~") return null
  if (value.toLowerCase() === "true") return true
  if (value.toLowerCase() === "false") return false
  try {
    return JSON.parse(value)
  } catch {
    return value.replace(/^(?:"([\s\S]*)"|'([\s\S]*)')$/, (_match, doubleQuoted, singleQuoted) => doubleQuoted ?? singleQuoted)
  }
}

function parseCandidateYaml(text: string): Record<string, unknown> {
  const root: Record<string, unknown> = {}
  const stack: Array<{ indent: number; value: Record<string, unknown> | unknown[] }> = [{ indent: -1, value: root }]
  for (const raw of text.split(/\r?\n/)) {
    if (!raw.trim() || raw.trimStart().startsWith("#")) continue
    const indent = raw.length - raw.trimStart().length
    const line = raw.trim()
    while (stack.length && indent <= stack[stack.length - 1].indent) stack.pop()
    const parent = stack[stack.length - 1]?.value
    if (!parent) throw new Error("K-Slide deployment candidate is malformed.")
    if (line.startsWith("- ")) {
      if (!Array.isArray(parent)) throw new Error("K-Slide deployment candidate is malformed.")
      parent.push(candidateScalar(line.slice(2)))
      continue
    }
    const separator = line.indexOf(":")
    if (separator <= 0 || !isRecord(parent)) throw new Error("K-Slide deployment candidate is malformed.")
    const key = line.slice(0, separator).trim()
    const rawValue = line.slice(separator + 1)
    const value = rawValue.trim() ? candidateScalar(rawValue) : {}
    parent[key] = value
    if (!rawValue.trim()) stack.push({ indent, value: value as Record<string, unknown> })
  }
  return root
}

function normalizeCandidate(value: unknown): Record<string, unknown> {
  if (!isRecord(value)) throw new Error("K-Slide deployment candidate is malformed.")
  const nested = isRecord(value.candidate_spec) ? { ...value.candidate_spec } : {}
  for (const [key, child] of Object.entries(value)) {
    if (key !== "candidate_spec") nested[key] = child
  }
  return nested
}

async function readCandidate(filePath: string): Promise<Record<string, unknown>> {
  const rawText = await readUtf8(filePath)
  const parsed = path.extname(filePath).toLowerCase() === ".json" ? JSON.parse(rawText) : parseCandidateYaml(rawText)
  return normalizeCandidate(parsed)
}

function candidateRouteBinding(value: Record<string, unknown>): Record<string, unknown> | undefined {
  const fields = ["candidate_spec_version", "schema_version", "requested_model", "effective_model", "provider", "opencode_version", "network_egress", "inference_route_identity", "inference_endpoint_identity", "egress_policy_version", "egress_policy_hash", "egress_policy_identity"]
  const binding = Object.fromEntries(fields.filter((field) => field in value).map((field) => [field, value[field]]))
  const unresolved = ["requested_model", "effective_model", "provider", "opencode_version", "network_egress", "inference_route_identity", "inference_endpoint_identity", "egress_policy_version", "egress_policy_hash", "egress_policy_identity"].some((field) => {
    const child = binding[field]
    return child === undefined || child === null || child === "" || (typeof child === "string" && ["UNSET", "NOT_YET_CONFIGURED"].includes(child.toUpperCase()))
  })
  return unresolved ? undefined : binding
}

function assertCandidateBinding(value: Record<string, unknown>, policy: { endpointIdentity: string; routeIdentity: string; policyVersion: string; policyHash: string; policyIdentity: string }): void {
  const schemaVersion = value.candidate_spec_version ?? value.schema_version
  if (schemaVersion !== "1.1") throw new Error("K-Slide deployment candidate is unresolved or malformed.")
  const expected: Record<string, unknown> = {
    requested_model: `${APPROVED_PROVIDER_ID}/${APPROVED_MODEL_ID}`,
    effective_model: `${APPROVED_PROVIDER_ID}/${APPROVED_MODEL_ID}`,
    provider: APPROVED_PROVIDER_ID,
    opencode_version: "1.3.9",
    network_egress: "default_deny",
    inference_route_identity: policy.routeIdentity,
    inference_endpoint_identity: policy.endpointIdentity,
    egress_policy_version: policy.policyVersion,
    egress_policy_hash: policy.policyHash,
    egress_policy_identity: policy.policyIdentity,
  }
  for (const [key, expectedValue] of Object.entries(expected)) {
    const actual = value[key]
    if (actual === undefined || actual === null || actual === "" || (typeof actual === "string" && ["UNSET", "NOT_YET_CONFIGURED"].includes(actual.toUpperCase())) || actual !== expectedValue) {
      throw new Error("K-Slide deployment candidate is unresolved or inconsistent.")
    }
  }
  if (!isIdentity(value.inference_route_identity) || !isSha256(value.inference_endpoint_identity) || !isSha256(value.egress_policy_hash) || !isSha256(value.egress_policy_identity)) {
    throw new Error("K-Slide deployment candidate is malformed.")
  }
}

async function candidateSourcePaths(worktree: string): Promise<string[]> {
  const present: string[] = []
  for (const parts of CANDIDATE_SOURCES) {
    const candidatePath = path.join(worktree, ...parts)
    try {
      const details = await lstat(candidatePath)
      if (details.isSymbolicLink() || !details.isFile()) throw new Error("K-Slide deployment candidate is missing or symlinked.")
      present.push(candidatePath)
    } catch (error) {
      if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") continue
      throw error
    }
  }
  if (!present.length) throw new Error("K-Slide deployment candidate is missing.")
  return present
}

export async function deploymentBoundRouteIdentity(worktree: string): Promise<string> {
  const policyPath = path.join(worktree, ".k-slide-config", "egress-policy.json")
  try {
    const details = await lstat(policyPath)
    if (!details.isFile() || details.isSymbolicLink()) return ""
    const binding = assertPolicyShape(JSON.parse(await readUtf8(policyPath)))
    const sources = await candidateSourcePaths(worktree)
    const candidate = await readCandidate(sources[0])
    assertCandidateBinding(candidate, binding)
    for (const source of sources.slice(1)) {
      const lower = await readCandidate(source)
      const lowerBinding = candidateRouteBinding(lower)
      if (lowerBinding && JSON.stringify(lowerBinding) !== JSON.stringify(candidateRouteBinding(candidate))) return ""
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

function isRemoteFileLocator(locator: string): boolean {
  if (locator.startsWith("//") || locator.startsWith("\\\\")) return true
  const scheme = locator.match(URI_SCHEME)?.[0].slice(0, -1).toLowerCase()
  if (scheme !== "file") return false
  try {
    const host = new URL(locator).hostname.toLowerCase()
    return Boolean(host && host !== "localhost")
  } catch {
    return true
  }
}

function localReference(part: FilePart, index: number, worktree: string, sourcePath?: string): HostInputReference {
  const locator = sourcePath || part.url
  if (typeof locator !== "string" || !locator || locator.includes("\x00")) throw new Error("K-Slide attachment was rejected.")
  const scheme = locator.match(URI_SCHEME)?.[0].slice(0, -1).toLowerCase()
  if (scheme && scheme !== "file") throw new Error("K-Slide attachment was rejected.")
  if (isRemoteFileLocator(locator)) throw new Error("K-Slide attachment was rejected.")
  const logicalName = logicalNameForPart(part, index, undefined, sourcePath, locator)
  return { source_kind: sourceKindForLocator(locator, worktree), logical_name: logicalName, locator, classification: DEFAULT_CLASSIFICATION }
}

function decodedDataByteLength(encodedLength: number, padding: number): number {
  if (!Number.isSafeInteger(encodedLength) || !Number.isSafeInteger(padding) || encodedLength < 0 || padding < 0 || padding > 2) return -1
  return (encodedLength / 4) * 3 - padding
}

class ResourceBudgetAttachmentError extends Error {
  code: HostInputReference["rejection_code"]

  constructor(code: NonNullable<HostInputReference["rejection_code"]>) {
    super("K-Slide attachment was rejected by resource-budget admission.")
    this.code = code
  }
}

async function managedCandidateExists(worktree: string): Promise<boolean> {
  for (const parts of CANDIDATE_SOURCES) {
    try {
      const details = await lstat(path.join(worktree, ...parts))
      if (details.isSymbolicLink() || !details.isFile()) return true
      try {
        if (candidateRouteBinding(await readCandidate(path.join(worktree, ...parts))) !== undefined) return true
      } catch {
        return true
      }
    } catch (error) {
      if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") continue
      return true
    }
  }
  return false
}

function validateResourceBudget(raw: unknown): { maxInputBytes?: number; rejectionCode?: HostInputReference["rejection_code"] } {
  if (!isRecord(raw) || Object.keys(raw).sort().join("\n") !== ["environment", "limits", "schema_version"].sort().join("\n")) {
    return { rejectionCode: "KSLIDE_RESOURCE_BUDGET_INVALID" }
  }
  if (raw.schema_version !== "1.0" || !["production", "reference_non_production"].includes(String(raw.environment)) || !isRecord(raw.limits)) {
    return { rejectionCode: "KSLIDE_RESOURCE_BUDGET_INVALID" }
  }
  const limits = raw.limits
  if (Object.keys(limits).sort().join("\n") !== RESOURCE_BUDGET_FIELDS.join("\n") || limits.max_media_duration_seconds !== null) {
    return { rejectionCode: "KSLIDE_RESOURCE_BUDGET_INVALID" }
  }
  for (const [field, ceiling] of Object.entries(RESOURCE_BUDGET_CEILINGS)) {
    const value = limits[field]
    if (!Number.isSafeInteger(value) || Number(value) < 1 || Number(value) > ceiling) {
      return { rejectionCode: "KSLIDE_RESOURCE_BUDGET_INVALID" }
    }
  }
  return { maxInputBytes: Number(limits.max_file_bytes) }
}

async function configuredInputBudget(worktree: string): Promise<{ maxInputBytes?: number; rejectionCode?: HostInputReference["rejection_code"] }> {
  try {
    const handle = await open(path.join(worktree, ".k-slide-config", "production-profile.json"), "r")
    let raw: string
    try {
      const details = await handle.stat()
      if (!details.isFile() || details.size > 2 * 1024 * 1024) throw new Error("resource budget profile is invalid")
      const contents = Buffer.alloc(details.size)
      const { bytesRead } = await handle.read(contents, 0, contents.length, 0)
      if (bytesRead !== contents.length) throw new Error("resource budget profile changed while being read")
      raw = contents.toString("utf8")
    } finally {
      await handle.close()
    }
    const profile = JSON.parse(raw) as { resource_budget?: unknown; release_state?: unknown }
    if (!profile || typeof profile !== "object" || Array.isArray(profile)) {
      return { rejectionCode: "KSLIDE_RESOURCE_BUDGET_INVALID" }
    }
    if (!("resource_budget" in profile) || profile.resource_budget === null) {
      return profile.release_state === "PRODUCTION_CERTIFIED" || await managedCandidateExists(worktree)
        ? { rejectionCode: "KSLIDE_RESOURCE_BUDGET_UNAVAILABLE" }
        : { maxInputBytes: MAX_INPUT_BYTES }
    }
    return validateResourceBudget(profile.resource_budget)
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
      return (await managedCandidateExists(worktree))
        ? { rejectionCode: "KSLIDE_RESOURCE_BUDGET_UNAVAILABLE" }
        : { maxInputBytes: MAX_INPUT_BYTES }
    }
    return { rejectionCode: "KSLIDE_RESOURCE_BUDGET_INVALID" }
  }
}

function decodedDataUrl(part: FilePart, maxInputBytes: number): { mime: string; bytes: Buffer } {
  const mime = normalizedMime(part.mime)
  if (typeof part.url !== "string") throw new Error("K-Slide attachment was rejected.")
  const match = DATA_URL.exec(part.url)
  if (!match || match[1].toLowerCase() !== mime) throw new Error("K-Slide attachment was rejected.")
  const encoded = match[2]
  if (!encoded || encoded.length % 4 !== 0) throw new Error("K-Slide attachment was rejected.")
  const padding = encoded.endsWith("==") ? 2 : encoded.endsWith("=") ? 1 : 0
  const decodedLength = decodedDataByteLength(encoded.length, padding)
  if (decodedLength <= 0) throw new Error("K-Slide attachment was rejected.")
  if (decodedLength > maxInputBytes || decodedLength > MAX_INPUT_BYTES) throw new ResourceBudgetAttachmentError("KSLIDE_INPUT_TOO_LARGE")
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

function rejectedReference(sessionID: string, index: number, mime: unknown, stagingDirectory?: string, rejection_code?: HostInputReference["rejection_code"]): HostInputReference {
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
    ...(rejection_code ? { rejection_code } : {}),
  }
}

async function materializeDataAttachment(part: FilePart, index: number, stagingDirectory: string, maxInputBytes: number): Promise<HostInputReference> {
  const { mime, bytes } = decodedDataUrl(part, maxInputBytes)
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
    const budget = await configuredInputBudget(worktree)
    const directory = stagingDirectory || await createStagingDirectory(sessionID)
    if (budget.rejectionCode) {
      return { ref: rejectedReference(sessionID, index, part.mime, directory, budget.rejectionCode), stagingDirectory: directory }
    }
    try {
      return { ref: await materializeDataAttachment(part, index, directory, budget.maxInputBytes ?? MAX_INPUT_BYTES), stagingDirectory: directory }
    } catch (error) {
      if (error instanceof ResourceBudgetAttachmentError) return { ref: rejectedReference(sessionID, index, part.mime, directory, error.code), stagingDirectory: directory }
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
    config: async (config: Config) => {
      protectKSlideProviderConfig(config as unknown as Record<string, unknown>)
    },
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
