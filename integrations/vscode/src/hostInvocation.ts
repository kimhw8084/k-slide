import path from "node:path"

export interface HostUri {
  readonly scheme: string
  readonly authority?: string
  readonly path: string
  readonly fsPath: string
  readonly query?: string
  readonly fragment?: string
  toString(skipEncoding?: boolean): string
}

export interface WorkspaceRoot {
  readonly uri: HostUri
}

export interface HostInputReference {
  readonly source_kind: "attachment" | "workspace_file"
  readonly logical_name: string
  readonly locator: string
}

export interface HostInvocation {
  readonly schema_version: "1.0"
  readonly adapter_version: "1.0"
  readonly input_refs: readonly HostInputReference[]
}

export interface BuiltInvocation {
  readonly root: string
  readonly invocation: HostInvocation
}

export class HostSelectionError extends Error {
  constructor(message: string) {
    super(message)
    this.name = "HostSelectionError"
  }
}

function isSafeAbsolutePath(value: string, allowBackslash = true): boolean {
  if (!value || value.includes("\0") || value.startsWith("//") || value.startsWith("\\\\") || (!allowBackslash && value.includes("\\"))) return false
  if (!path.isAbsolute(value)) return false
  return !value.split(/[\\/]+/).some((part) => part === "..")
}

function uriPath(uri: HostUri, workspaceRoots: readonly WorkspaceRoot[]): string {
  if (uri.query || uri.fragment) throw new HostSelectionError("K-Slide accepts local files without URI query or fragment data.")
  if (uri.scheme === "file") {
    if (uri.authority && uri.authority !== "localhost") throw new HostSelectionError("K-Slide accepts local file URIs only.")
    if (!isSafeAbsolutePath(uri.fsPath)) throw new HostSelectionError("K-Slide file selection is not a safe local path.")
    return path.resolve(uri.fsPath)
  }
  if (uri.scheme === "vscode-remote") {
    const matchingRoot = workspaceRoots.some((root) => root.uri.scheme === uri.scheme && root.uri.authority === uri.authority)
    if (!matchingRoot || !isSafeAbsolutePath(uri.fsPath, false)) {
      throw new HostSelectionError("K-Slide accepts files only from the current remote workspace filesystem.")
    }
    return path.resolve(uri.fsPath)
  }
  throw new HostSelectionError("K-Slide accepts local files from a file or remote workspace URI.")
}

function isWithin(root: string, file: string): boolean {
  const relative = path.relative(root, file)
  return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative))
}

function pathForRoot(uri: HostUri): string | undefined {
  if (uri.scheme === "file") {
    if (uri.authority && uri.authority !== "localhost") return undefined
    return isSafeAbsolutePath(uri.fsPath) ? path.resolve(uri.fsPath) : undefined
  }
  if (uri.scheme === "vscode-remote") {
    return isSafeAbsolutePath(uri.fsPath, false) ? path.resolve(uri.fsPath) : undefined
  }
  return undefined
}

function compareText(left: string, right: string): number {
  const a = Array.from(left, (character) => character.codePointAt(0) ?? 0)
  const b = Array.from(right, (character) => character.codePointAt(0) ?? 0)
  const count = Math.min(a.length, b.length)
  for (let index = 0; index < count; index += 1) {
    if (a[index] !== b[index]) return a[index] < b[index] ? -1 : 1
  }
  return a.length === b.length ? 0 : a.length < b.length ? -1 : 1
}

function selectedUris(value: HostUri | readonly HostUri[]): readonly HostUri[] {
  return Array.isArray(value) ? value : [value as HostUri]
}

function isHostUri(value: unknown): value is HostUri {
  if (!value || typeof value !== "object") return false
  const candidate = value as Partial<HostUri>
  return typeof candidate.scheme === "string"
    && typeof candidate.path === "string"
    && typeof candidate.fsPath === "string"
    && typeof candidate.toString === "function"
}

export function selectCurrentFileUri(activeTextEditorUri: unknown, activeTabInput: unknown): HostUri | undefined {
  if (isHostUri(activeTextEditorUri)) return activeTextEditorUri
  if (!activeTabInput || typeof activeTabInput !== "object") return undefined
  const input = activeTabInput as {uri?: unknown; modified?: unknown; original?: unknown; notebook?: {uri?: unknown}}
  if (isHostUri(input.uri)) return input.uri
  if (input.notebook && isHostUri(input.notebook.uri)) return input.notebook.uri
  if (isHostUri(input.modified)) return input.modified
  if (isHostUri(input.original)) return input.original
  return undefined
}

export function buildHostInvocation(
  selected: HostUri | readonly HostUri[],
  workspaceRoots: readonly WorkspaceRoot[],
): BuiltInvocation {
  const uris = selectedUris(selected)
  if (uris.length === 0) throw new HostSelectionError("Select at least one supported local file for K-Slide.")
  const selectedPaths = uris.map((uri) => ({uri, filePath: uriPath(uri, workspaceRoots)}))
  const rootCandidates: string[] = []
  const refs: HostInputReference[] = []
  for (const {uri, filePath} of selectedPaths) {
    const rootsForFile = workspaceRoots
      .filter((folder) => folder.uri.scheme === uri.scheme && (folder.uri.authority ?? "") === (uri.authority ?? ""))
      .map((folder) => pathForRoot(folder.uri))
      .filter((value): value is string => value !== undefined && isWithin(value, filePath))
      .sort(compareText)
    if (rootsForFile.length > 1 && rootsForFile.some((value) => value !== rootsForFile[0])) {
      throw new HostSelectionError("K-Slide could not identify one workspace root for the selected files.")
    }
    const workspaceRoot = rootsForFile[0]
    if (workspaceRoot) rootCandidates.push(workspaceRoot)
    refs.push({
      source_kind: workspaceRoot ? "workspace_file" : "attachment",
      logical_name: path.basename(filePath),
      locator: filePath,
    })
  }
  const distinctRoots = Array.from(new Set(rootCandidates))
  if (distinctRoots.length > 1) throw new HostSelectionError("K-Slide runs one workspace at a time. Select files from a single workspace.")
  const fallbackRoot = workspaceRoots.map((folder) => pathForRoot(folder.uri)).find((value): value is string => value !== undefined)
  const root = distinctRoots[0] ?? fallbackRoot ?? path.dirname(selectedPaths[0].filePath)
  const unique = new Map<string, HostInputReference>()
  for (const reference of refs) {
    const key = `${reference.logical_name}\0${reference.source_kind}\0${reference.locator}`
    unique.set(key, reference)
  }
  const inputRefs = Array.from(unique.values()).sort((left, right) =>
    compareText(left.logical_name, right.logical_name)
    || compareText(left.source_kind, right.source_kind)
    || compareText(left.locator, right.locator),
  )
  return {
    root,
    invocation: {schema_version: "1.0", adapter_version: "1.0", input_refs: inputRefs},
  }
}

export function serializeHostInvocation(invocation: HostInvocation): string {
  return JSON.stringify({
    schema_version: "1.0",
    adapter_version: "1.0",
    input_refs: invocation.input_refs.map((reference) => ({
      source_kind: reference.source_kind,
      logical_name: reference.logical_name,
      locator: reference.locator,
    })),
  })
}

export function summarizeEngineResponse(value: unknown): {runId?: string; status?: string; semanticOutcome?: string} {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {}
  const record = value as Record<string, unknown>
  const runId = typeof record.run_id === "string" && /^[A-Za-z0-9_.:-]{1,128}$/.test(record.run_id) ? record.run_id : undefined
  const status = typeof record.operational_state === "string" && /^[A-Z_]{1,64}$/.test(record.operational_state)
    ? record.operational_state
    : typeof record.status === "string" && /^[A-Z_]{1,64}$/.test(record.status) ? record.status : undefined
  const semanticOutcome = ["PENDING", "DONE", "NEEDS_REVIEW"].includes(String(record.semantic_outcome))
    ? String(record.semantic_outcome)
    : undefined
  return {
    ...(runId ? {runId} : {}),
    ...(status ? {status} : {}),
    ...(semanticOutcome ? {semanticOutcome} : {}),
  }
}
