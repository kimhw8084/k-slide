import type { Part } from "@opencode-ai/sdk"
import type { Plugin } from "@opencode-ai/plugin"
import path from "node:path"

type HostInputReference = {
  source_kind: "attachment" | "workspace_file"
  logical_name: string
  locator: string
}

function isFilePart(part: Part): part is Extract<Part, { type: "file" }> {
  return part.type === "file"
}

const extensionByMime: Record<string, string> = {
  "image/png": ".png",
  "image/jpeg": ".jpg",
  "image/webp": ".webp",
  "application/pdf": ".pdf",
  "application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx",
}

function referenceFromPart(part: Extract<Part, { type: "file" }>, worktree: string): HostInputReference {
  const sourcePath = part.source && "path" in part.source ? part.source.path : undefined
  const locator = sourcePath || part.url
  const logicalName = part.filename || (sourcePath ? path.basename(sourcePath) : `attachment${extensionByMime[part.mime] || ""}`)
  const sourceKind = sourcePath && path.relative(worktree, sourcePath) && !path.relative(worktree, sourcePath).startsWith("..") && !path.isAbsolute(path.relative(worktree, sourcePath))
    ? "workspace_file"
    : "attachment"
  return { source_kind: sourceKind, logical_name: logicalName, locator }
}

const KSlideHostPlugin: Plugin = async ({ worktree }) => {
  const currentMessageInputs = new Map<string, HostInputReference[]>()
  return {
    "chat.message": async (input, output) => {
      const references = output.parts.filter(isFilePart).map((part) => referenceFromPart(part, worktree))
      currentMessageInputs.set(input.sessionID, references)
    },
    "tool.execute.before": async (input, output) => {
      if (input.tool !== "kslide_prepare") return
      const references = currentMessageInputs.get(input.sessionID) || []
      if (!references.length) return
      const args = output.args && typeof output.args === "object" ? output.args : {}
      if (Array.isArray((args as { explicit_input_paths?: unknown }).explicit_input_paths) && (args as { explicit_input_paths: unknown[] }).explicit_input_paths.length) return
      output.args = { ...args, host_input_refs: references }
    },
    "tool.execute.after": async (input) => {
      if (input.tool === "kslide_prepare") currentMessageInputs.delete(input.sessionID)
    },
  }
}

export default KSlideHostPlugin
