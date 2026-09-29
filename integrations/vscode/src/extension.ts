import * as fs from "node:fs"
import * as path from "node:path"
import * as vscode from "vscode"
import {EngineTarget, invokePrepare, invokePresentation} from "./engine"
import {buildHostInvocation, HostSelectionError, HostUri, selectCurrentFileUri, WorkspaceRoot} from "./hostInvocation"
import {SafeKSlideError} from "./safeError"

const LAST_RUN_KEY = "kSlide.lastRunId"
const LAST_RUN_CONTEXT_KEY = "kSlide.lastRunContext"
const PRESENTATION_ACTIONS = new Set(["decision_view", "reconstruction", "review_disclosure", "evidence_drilldown"])
const ACTION_FILE: Record<string, string> = {
  decision_view: "05_decision_view.md",
  reconstruction: "05_final_report.md",
  review_disclosure: "07_unresolved_items.md",
  evidence_drilldown: "08_evidence_drilldown.json",
}

function hostUri(uri: vscode.Uri): HostUri {
  return uri
}

function workspaceRoots(): WorkspaceRoot[] {
  return (vscode.workspace.workspaceFolders ?? []).map((folder) => ({uri: hostUri(folder.uri)}))
}

function workspaceRootPath(): string | undefined {
  const root = vscode.workspace.workspaceFolders?.[0]?.uri
  if (!root) return undefined
  if (root.scheme !== "file" && root.scheme !== "vscode-remote") return undefined
  return path.resolve(root.fsPath)
}

function engineTarget(root: string): EngineTarget {
  const configuration = vscode.workspace.getConfiguration("kSlide")
  const configuredEngineRoot = configuration.get<string>("engineRoot", "").trim()
  const engineCandidates = [
    ...(configuredEngineRoot ? [path.resolve(configuredEngineRoot)] : []),
    path.join(root, ".k-slide-engine"),
    root,
  ]
  const engineRoot = engineCandidates.find((candidate) => fs.existsSync(path.join(candidate, "src", "k_slide", "cli.py")))
  if (!engineRoot) throw new SafeKSlideError("K-Slide engine is not installed in this workspace. Install the repository-owned K-Slide package or set the K-Slide engine root.")
  return {
    root,
    engineRoot,
    pythonPath: configuration.get<string>("pythonPath", "python3").trim() || "python3",
  }
}

function toUris(values: unknown[]): vscode.Uri[] {
  const result: vscode.Uri[] = []
  for (const value of values) {
    if (value instanceof vscode.Uri) result.push(value)
    else if (Array.isArray(value)) result.push(...value.filter((item): item is vscode.Uri => item instanceof vscode.Uri))
  }
  return result
}

function currentRunId(context: vscode.ExtensionContext, supplied?: unknown): string | undefined {
  const value = typeof supplied === "string" ? supplied : context.workspaceState.get<string>(LAST_RUN_KEY)
  return value && /^[A-Za-z0-9_.:-]{1,128}$/.test(value) ? value : undefined
}

async function pickRunId(context: vscode.ExtensionContext, supplied?: unknown): Promise<string | undefined> {
  const known = currentRunId(context, supplied)
  if (known) return known
  const value = await vscode.window.showInputBox({
    title: "Open K-Slide artifacts",
    prompt: "Enter the run ID returned by K-Slide.",
    validateInput: (input) => /^[A-Za-z0-9_.:-]{1,128}$/.test(input) ? undefined : "Enter a valid K-Slide run ID.",
  })
  return value && /^[A-Za-z0-9_.:-]{1,128}$/.test(value) ? value : undefined
}

function validatePresentation(response: unknown, runId: string): Record<string, unknown> {
  if (!response || typeof response !== "object" || Array.isArray(response)) throw new SafeKSlideError("K-Slide returned an invalid presentation descriptor.")
  const record = response as Record<string, unknown>
  const descriptor = record.presentation
  if (!descriptor || typeof descriptor !== "object" || Array.isArray(descriptor)) throw new SafeKSlideError("K-Slide presentation descriptor is unavailable for this run.")
  const presentation = descriptor as Record<string, unknown>
  if (presentation.schema_version !== "1.0" || presentation.run_id !== runId || !Array.isArray(presentation.actions)) {
    throw new SafeKSlideError("K-Slide presentation descriptor is invalid or stale.")
  }
  return presentation
}

async function openPresentationAction(context: vscode.ExtensionContext, actionId: string, suppliedRunId?: unknown): Promise<void> {
  if (!PRESENTATION_ACTIONS.has(actionId)) throw new SafeKSlideError("K-Slide presentation action is unsupported.")
  const runId = await pickRunId(context, suppliedRunId)
  if (!runId) return
  const stored = context.workspaceState.get<Record<string, unknown>>(LAST_RUN_CONTEXT_KEY)
  const storedMatches = stored?.runId === runId
  const rootValue = storedMatches && typeof stored?.root === "string" ? stored.root : workspaceRootPath()
  if (!rootValue) throw new SafeKSlideError("Open the workspace that contains this K-Slide run before opening its artifacts.")
  const root = path.resolve(rootValue)
  const scheme = storedMatches && (stored?.scheme === "file" || stored?.scheme === "vscode-remote")
    ? stored.scheme
    : vscode.workspace.workspaceFolders?.find((folder) => path.resolve(folder.uri.fsPath) === root)?.uri.scheme ?? "file"
  const authority = storedMatches && typeof stored?.authority === "string"
    ? stored.authority
    : vscode.workspace.workspaceFolders?.find((folder) => path.resolve(folder.uri.fsPath) === root)?.uri.authority ?? ""
  const target = engineTarget(root)
  const response = await invokePresentation(target, runId)
  const descriptor = validatePresentation(response, runId)
  const actions = descriptor.actions as Record<string, unknown>[]
  const action = actions.find((item) => item.action_id === actionId)
  const expectedFile = ACTION_FILE[actionId]
  if (!action || action.path !== expectedFile || action.role !== (actionId === "decision_view" ? "first_view" : "follow_on")) {
    throw new SafeKSlideError("K-Slide presentation action does not match the engine-owned artifact contract.")
  }
  const runRoot = path.resolve(root, ".k-slide-runs", runId)
  const artifactPath = path.resolve(runRoot, expectedFile)
  const relative = path.relative(runRoot, artifactPath)
  if (relative.startsWith(`..${path.sep}`) || relative === ".." || path.isAbsolute(relative)) {
    throw new SafeKSlideError("K-Slide artifact location is outside the selected run.")
  }
  const [realRunRoot, realArtifactPath] = await Promise.all([fs.promises.realpath(runRoot), fs.promises.realpath(artifactPath)])
  const realRelative = path.relative(realRunRoot, realArtifactPath)
  if (realRelative.startsWith(`..${path.sep}`) || realRelative === ".." || path.isAbsolute(realRelative)) {
    throw new SafeKSlideError("K-Slide artifact location is outside the selected run.")
  }
  const artifactUri = scheme === "file"
    ? vscode.Uri.file(realArtifactPath)
    : vscode.Uri.from({scheme, authority, path: realArtifactPath})
  const document = await vscode.workspace.openTextDocument(artifactUri)
  await vscode.window.showTextDocument(document, {preview: true})
}

function showSafeError(error: unknown): void {
  const message = error instanceof HostSelectionError || error instanceof SafeKSlideError
    ? error.message
    : "K-Slide could not complete this action. Check the K-Slide runtime and run status."
  void vscode.window.showErrorMessage(message)
}

export function activate(context: vscode.ExtensionContext): void {
  const output = vscode.window.createOutputChannel("K-Slide")
  context.subscriptions.push(output)

  const runSelected = async (uris: vscode.Uri[]): Promise<void> => {
    if (uris.length === 0) {
      const selected = await vscode.window.showOpenDialog({
        canSelectMany: true,
        canSelectFiles: true,
        canSelectFolders: false,
        openLabel: "Run K-Slide",
        title: "Select files for K-Slide",
      })
      uris = selected ?? []
    }
    if (uris.length === 0) return
    const built = buildHostInvocation(uris, workspaceRoots())
    const target = engineTarget(built.root)
    const summary = await vscode.window.withProgress(
      {location: vscode.ProgressLocation.Notification, title: "K-Slide is preparing the selected files", cancellable: false},
      () => invokePrepare(target, built),
    )
    if (summary.runId) {
      const folder = vscode.workspace.workspaceFolders?.find((item) => path.resolve(item.uri.fsPath) === path.resolve(built.root))
      const runContext = {
        runId: summary.runId,
        root: path.resolve(built.root),
        scheme: folder?.uri.scheme ?? "file",
        authority: folder?.uri.authority ?? "",
      }
      await Promise.all([
        context.workspaceState.update(LAST_RUN_KEY, summary.runId),
        context.workspaceState.update(LAST_RUN_CONTEXT_KEY, runContext),
      ])
    }
    output.appendLine(`Prepared K-Slide run${summary.runId ? ` ${summary.runId}` : ""}; status ${summary.status ?? "PENDING"}; outcome ${summary.semanticOutcome ?? "PENDING"}.`)
    output.show(true)
    if (summary.semanticOutcome === "NEEDS_REVIEW") {
      void vscode.window.showInformationMessage(`K-Slide run ${summary.runId ?? ""} needs review. The engine has not marked it DONE.`)
    } else {
      void vscode.window.showInformationMessage(`K-Slide run ${summary.runId ?? ""} prepared. Translation and completion remain governed by the K-Slide engine.`)
    }
  }

  context.subscriptions.push(
    vscode.commands.registerCommand("kSlide.runCurrent", async () => {
      try {
        const editor = vscode.window.activeTextEditor
        const current = selectCurrentFileUri(editor?.document.uri, vscode.window.tabGroups.activeTabGroup.activeTab?.input)
        if (!current) throw new SafeKSlideError("Open a supported local or workspace file before running K-Slide.")
        await runSelected([current as vscode.Uri])
      } catch (error) { showSafeError(error) }
    }),
    vscode.commands.registerCommand("kSlide.runSelectedFiles", async (...args: unknown[]) => {
      try { await runSelected(toUris(args)) } catch (error) { showSafeError(error) }
    }),
    vscode.commands.registerCommand("kSlide.runExplorerFile", async (...args: unknown[]) => {
      try {
        const uris = toUris(args)
        if (uris.length === 0) throw new SafeKSlideError("Select a local or workspace file in Explorer before running K-Slide.")
        await runSelected(uris)
      } catch (error) { showSafeError(error) }
    }),
    vscode.commands.registerCommand("kSlide.openDecisionView", async (runId?: unknown) => {
      try { await openPresentationAction(context, "decision_view", runId) } catch (error) { showSafeError(error) }
    }),
    vscode.commands.registerCommand("kSlide.openReconstruction", async (runId?: unknown) => {
      try { await openPresentationAction(context, "reconstruction", runId) } catch (error) { showSafeError(error) }
    }),
    vscode.commands.registerCommand("kSlide.openReviewDisclosure", async (runId?: unknown) => {
      try { await openPresentationAction(context, "review_disclosure", runId) } catch (error) { showSafeError(error) }
    }),
    vscode.commands.registerCommand("kSlide.openEvidenceDrilldown", async (runId?: unknown) => {
      try { await openPresentationAction(context, "evidence_drilldown", runId) } catch (error) { showSafeError(error) }
    }),
  )
}

export function deactivate(): void {}
