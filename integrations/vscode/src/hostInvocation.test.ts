import assert from "node:assert/strict"
import {test} from "node:test"
import path from "node:path"
import {buildHostInvocation, HostSelectionError, HostUri, selectCurrentFileUri, serializeHostInvocation, summarizeEngineResponse} from "./hostInvocation"
import {buildPrepareArguments} from "./engine"

function uri(filePath: string, scheme = "file", authority = ""): HostUri {
  return {
    scheme,
    authority,
    path: filePath,
    fsPath: filePath,
    toString: () => `${scheme}://${authority}${filePath}`,
  }
}

test("active current file creates exactly one shared HostInputReference", () => {
  const root = path.resolve("/workspace/project")
  const file = uri(path.join(root, "deck.png"))
  const built = buildHostInvocation(file, [{uri: uri(root)}])
  assert.deepEqual(built.invocation.input_refs, [{
    source_kind: "workspace_file",
    logical_name: "deck.png",
    locator: path.join(root, "deck.png"),
  }])
  assert.equal(built.root, root)
})

test("current custom editor file works without a TextEditor, including VS Code diff tabs", () => {
  const pdf = uri("/workspace/project/review.pdf")
  const pptx = uri("/workspace/project/plan.pptx")
  assert.equal(selectCurrentFileUri(undefined, {viewType: "vscode.pdf", uri: pdf}), pdf)
  assert.equal(selectCurrentFileUri(undefined, {original: uri("/workspace/project/old.pptx"), modified: pptx}), pptx)
  assert.equal(selectCurrentFileUri(undefined, {viewType: "webview", viewColumn: 1}), undefined)
})

test("multiple Explorer or picker files receive deterministic order and exact refs", () => {
  const root = path.resolve("/workspace/project")
  const selected = [uri(path.join(root, "b.pdf")), uri(path.join(root, "a.pptx")), uri(path.join(root, "a.png"))]
  const first = buildHostInvocation(selected, [{uri: uri(root)}])
  const second = buildHostInvocation([...selected].reverse(), [{uri: uri(root)}])
  assert.deepEqual(first.invocation.input_refs.map((item) => item.logical_name), ["a.png", "a.pptx", "b.pdf"])
  assert.deepEqual(first.invocation, second.invocation)
  assert.deepEqual(JSON.parse(serializeHostInvocation(first.invocation)), {
    schema_version: "1.0",
    adapter_version: "1.0",
    input_refs: first.invocation.input_refs,
  })
})

test("workspace remote URIs are accepted only from the current remote authority", () => {
  const root = uri("/workspaces/project", "vscode-remote", "cloud-container")
  const file = uri("/workspaces/project/deck.png", "vscode-remote", "cloud-container")
  assert.equal(buildHostInvocation(file, [{uri: root}]).invocation.input_refs[0].source_kind, "workspace_file")
  assert.throws(() => buildHostInvocation(uri("/workspaces/project/deck.png", "vscode-remote", "other-container"), [{uri: root}]), HostSelectionError)
})

test("remote paths preserve literal percent escapes and spaces through fsPath", () => {
  const root = uri("/workspaces/My Project 100%", "vscode-remote", "cloud-container")
  const file = uri("/workspaces/My Project 100%/deck 50%.png", "vscode-remote", "cloud-container")
  const built = buildHostInvocation(file, [{uri: root}])
  assert.equal(built.root, root.fsPath)
  assert.equal(built.invocation.input_refs[0].locator, file.fsPath)
})

test("unsupported, non-local, UNC and traversal inputs fail without echoing their names", () => {
  const root = path.resolve("/workspace/project")
  const folder = [{uri: uri(root)}]
  for (const unsafe of [
    uri("https://example.invalid/private.png", "https"),
    uri("/workspace/project/../private.png"),
    uri("//server/share/private.png"),
    uri("/workspace/project/private.png\0secret"),
  ]) {
    assert.throws(() => buildHostInvocation(unsafe, folder), (error: unknown) => {
      assert(error instanceof HostSelectionError)
      assert.doesNotMatch(error.message, /private|secret|example/i)
      return true
    })
  }
  const unsupported = buildHostInvocation(uri(path.join(root, "private.exe")), folder)
  assert.equal(unsupported.invocation.input_refs[0].logical_name, "private.exe")
})

test("distinct workspace roots cannot be combined into a single invocation", () => {
  const first = path.resolve("/workspace/first")
  const second = path.resolve("/workspace/second")
  assert.throws(() => buildHostInvocation([uri(path.join(first, "a.png")), uri(path.join(second, "b.png"))], [{uri: uri(first)}, {uri: uri(second)}]), HostSelectionError)
})

test("engine request contains only the existing prepare lifecycle and cannot override policy", () => {
  const root = path.resolve("/workspace/project")
  const args = buildPrepareArguments(root)
  assert.deepEqual(args, ["-m", "k_slide.cli", "prepare", "--root", root, "--json", "--host-adapter", "cloud_vscode", "--host-worktree", root, "--host-inputs-stdin"])
  assert.equal(args.some((value) => ["--model", "--provider", "--ocr", "--policy", "--verify", "--finalize"].includes(value)), false)
})

test("response summaries discard access keys, source text, file names and arbitrary error details", () => {
  const summary = summarizeEngineResponse({
    run_id: "run-123",
    status: "NEEDS_REVIEW",
    semantic_outcome: "NEEDS_REVIEW",
    AccessKey: "secret-access-key",
    source_text: "private source words",
    error: {message: "/workspace/private.png"},
  })
  assert.deepEqual(summary, {runId: "run-123", status: "NEEDS_REVIEW", semanticOutcome: "NEEDS_REVIEW"})
  assert.doesNotMatch(JSON.stringify(summary), /secret-access-key|private source words|private\.png/)
})
