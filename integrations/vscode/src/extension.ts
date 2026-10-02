import * as fs from "node:fs"
import * as path from "node:path"
import * as vscode from "vscode"
import {EngineTarget, invokeDoctor, invokePrepare, invokePresentation, invokeRuns} from "./engine"
import {buildHostInvocation, HostSelectionError, HostUri, selectCurrentFileUri, WorkspaceRoot} from "./hostInvocation"
import {SafeKSlideError} from "./safeError"
import {resolveEngineTarget} from "./runtime"
import {progressLabel} from "./runInfo"

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
  const folder = vscode.workspace.workspaceFolders?.find((item) => path.resolve(item.uri.fsPath) === root)
  const configuration = vscode.workspace.getConfiguration("kSlide", folder?.uri)
  return resolveEngineTarget(root, {
    engineRoot: configuration.get<string>("engineRoot", ""),
    pythonPath: configuration.get<string>("pythonPath", ""),
  })
}

function toUris(values: unknown[]): vscode.Uri[] {
  const result: vscode.Uri[] = []
  for (const value of values) {
    if (value instanceof vscode.Uri) result.push(value)
    else if (Array.isArray(value)) result.push(...value.filter((item): item is vscode.Uri => item instanceof vscode.Uri))
  }
  return result
}

async function pickRunId(context: vscode.ExtensionContext, supplied?: unknown): Promise<string | undefined> {
  const folders = (vscode.workspace.workspaceFolders ?? []).filter((folder) => ["file", "vscode-remote"].includes(folder.uri.scheme))
  if (!folders.length) throw new SafeKSlideError("Open your K-Slide workspace to see saved runs.")
  const groups = await Promise.allSettled(folders.map(async (folder) => {
    const root = path.resolve(folder.uri.fsPath)
    const runs = await invokeRuns(engineTarget(root))
    return runs.map((run) => ({label: run.runId, description: progressLabel(run),
      detail: folder.name + " · " + new Date(run.updatedAt).toLocaleString(),
      runId: run.runId, root, folder}))
  }))
  const choices = groups.flatMap((group) => group.status === "fulfilled" ? group.value : [])
  if (groups.some((group) => group.status === "rejected")) {
    if (!choices.length) throw new SafeKSlideError("Saved runs could not be read. Use K-Slide: Check Runtime in the original workspace.")
    void vscode.window.showWarningMessage("Some workspaces could not be checked. Use K-Slide: Check Runtime for missing runs.")
  }
  const stored = context.workspaceState.get<Record<string, unknown>>(LAST_RUN_CONTEXT_KEY)
  const matched = typeof supplied === "string"
    ? choices.filter((choice) => choice.runId === supplied && (!stored || stored.runId !== supplied || stored.root === choice.root))
    : []
  if (typeof supplied === "string" && !matched.length) throw new SafeKSlideError("This run is unavailable in the open workspace. Reopen its original workspace.")
  if (!choices.length) {
    void vscode.window.showInformationMessage("No saved K-Slide runs in this workspace. Select a file to begin.")
    return undefined
  }
  const chosen = matched.length === 1 ? matched[0] : await vscode.window.showQuickPick(matched.length ? matched : choices, {
    title: "K-Slide · Saved runs",
    placeHolder: "Choose a run to see its progress or open its result",
    matchOnDescription: true, matchOnDetail: true,
  })
  if (!chosen) return undefined
  await Promise.all([
    context.workspaceState.update(LAST_RUN_KEY, chosen.runId),
    context.workspaceState.update(LAST_RUN_CONTEXT_KEY, {
      runId: chosen.runId, root: chosen.root, scheme: chosen.folder.uri.scheme, authority: chosen.folder.uri.authority,
    }),
  ])
  return chosen.runId
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
  let expectedFile = ACTION_FILE[actionId]
  if (!action || action.path !== expectedFile || action.role !== (actionId === "decision_view" ? "first_view" : "follow_on")) {
    throw new SafeKSlideError("K-Slide presentation action does not match the engine-owned artifact contract.")
  }
  if (actionId === "decision_view" && action.html_path === "05_decision_view.html") expectedFile = "05_decision_view.html"
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
  if (expectedFile.endsWith(".html")) {
    const panel = vscode.window.createWebviewPanel("kSlide.decisionView", "K-Slide · Decision View", vscode.ViewColumn.Active, {
      enableScripts: false, localResourceRoots: [vscode.Uri.file(realRunRoot)],
    })
    const html = await fs.promises.readFile(realArtifactPath, "utf8")
    // The engine emits escaped text and relative image references only. Resolve
    // each image independently; symlinks must remain inside the current run.
    const sources = [...html.matchAll(/src="([^"]+)"/g)]
    let rendered = html
    for (const match of sources) {
      const decoded = decodeURIComponent(match[1])
      const mediaPath = await fs.promises.realpath(path.resolve(realRunRoot, decoded))
      const relativeMedia = path.relative(realRunRoot, mediaPath)
      if (relativeMedia.startsWith(`..${path.sep}`) || relativeMedia === ".." || path.isAbsolute(relativeMedia)) {
        panel.dispose()
        throw new SafeKSlideError("K-Slide source image is outside this run.")
      }
      rendered = rendered.replaceAll(match[0], `src="${panel.webview.asWebviewUri(vscode.Uri.file(mediaPath))}"`)
    }
    rendered = rendered.replace("img-src 'self' data:", `img-src ${panel.webview.cspSource} data:`)
    panel.webview.html = rendered
    context.subscriptions.push(panel)
    return
  }
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
  const status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 30)
  status.command = "kSlide.recentRuns"
  status.name = "K-Slide saved progress"
  status.text = "$(files) K-Slide"
  status.tooltip = "Open saved K-Slide runs"
  status.show()
  context.subscriptions.push(status)
  let refreshing = false
  const refreshStatus = async (): Promise<void> => {
    if (refreshing) return
    const stored = context.workspaceState.get<{root: string; runId: string}>(LAST_RUN_CONTEXT_KEY)
    if (!stored || !vscode.workspace.workspaceFolders?.some((folder) => path.resolve(folder.uri.fsPath) === stored.root)) {
      status.text = "$(files) K-Slide"
      status.tooltip = "Open saved K-Slide runs"
      return
    }
    refreshing = true
    try {
      const run = (await invokeRuns(engineTarget(stored.root))).find((item) => item.runId === stored.runId)
      status.text = run ? "$(files) K-Slide · " + progressLabel(run) : "$(files) K-Slide"
      status.tooltip = "Saved progress from the K-Slide engine. Click to reopen a run."
    } catch {
      status.text = "$(warning) K-Slide"
      status.tooltip = "Runtime unavailable. Use K-Slide: Check Runtime for recovery."
    } finally { refreshing = false }
  }
  const timer = setInterval(() => { void refreshStatus() }, 30_000)
  context.subscriptions.push({dispose: () => clearInterval(timer)})
  void refreshStatus()

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
      {location: vscode.ProgressLocation.Notification, title: "K-Slide is preparing the selected files", cancellable: true},
      async (_progress, token) => {
        const controller = new AbortController()
        const subscription = token.onCancellationRequested(() => controller.abort())
        if (token.isCancellationRequested) controller.abort()
        try { return await invokePrepare(target, built, controller.signal) }
        finally { subscription.dispose() }
      },
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
    void refreshStatus()
    if (summary.semanticOutcome === "NEEDS_REVIEW") {
      void vscode.window.showInformationMessage(`K-Slide run ${summary.runId ?? ""} needs review. The engine has not marked it DONE.`)
    } else {
      void vscode.window.showInformationMessage(`K-Slide run ${summary.runId ?? ""} prepared. Your workspace needs its managed translation connection to continue.`)
    }
  }

  context.subscriptions.push(
    vscode.commands.registerCommand("kSlide.recentRuns", async (supplied?: unknown) => {
      try {
        const runId = await pickRunId(context, supplied)
        if (!runId) return
        const stored = context.workspaceState.get<{root: string}>(LAST_RUN_CONTEXT_KEY)
        if (!stored) return
        const run = (await invokeRuns(engineTarget(stored.root))).find((item) => item.runId === runId)
        if (!run) throw new SafeKSlideError("This saved run is unavailable. Refresh the run list.")
        void refreshStatus()
        const canOpen = run.progressAvailable && ["COMPLETE", "VERIFIED", "NEEDS_REVIEW"].includes(run.phase)
        const actions = canOpen ? ["Open result", "Refresh"] : ["Refresh", "Check runtime"]
        const action = await vscode.window.showInformationMessage(progressLabel(run) + ". Saved progress is retained in this workspace.", ...actions)
        if (action === "Open result") await openPresentationAction(context, "decision_view", runId)
        else if (action === "Refresh") await vscode.commands.executeCommand("kSlide.recentRuns", runId)
        else if (action === "Check runtime") await vscode.commands.executeCommand("kSlide.checkRuntime")
      } catch (error) { showSafeError(error) }
    }),
    vscode.commands.registerCommand("kSlide.checkRuntime", async () => {
      try {
        const folders = vscode.workspace.workspaceFolders ?? []
        const folder = folders.length === 1 ? folders[0] : await vscode.window.showWorkspaceFolderPick({placeHolder: "Choose the K-Slide workspace to check"})
        if (!folder) return
        const lines = await vscode.window.withProgress(
          {location: vscode.ProgressLocation.Notification, title: "Checking K-Slide runtime", cancellable: true},
          async (_progress, token) => {
            const controller = new AbortController()
            const subscription = token.onCancellationRequested(() => controller.abort())
            if (token.isCancellationRequested) controller.abort()
            try { return await invokeDoctor(engineTarget(path.resolve(folder.uri.fsPath)), controller.signal) }
            finally { subscription.dispose() }
          },
        )
        output.clear()
        for (const line of lines) output.appendLine(line)
        output.show(true)
      } catch (error) { showSafeError(error) }
    }),
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
