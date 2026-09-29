# K-Slide for VS Code

This extension is a thin Cloud VS Code host adapter. It selects current or Explorer/picker files, sends versioned `HostInvocation` JSON to the installed K-Slide CLI over stdin, and opens the artifacts named by the engine-owned presentation descriptor. It does not implement translation, model selection, OCR, verification, or completion.

Commands are available in the Command Palette. Use **K-Slide: Run on Current File**, **K-Slide: Run on Selected Files…**, or **K-Slide: Run on This File** from Explorer. The multi-file picker and the engine use deterministic filename, source-kind, and locator ordering. Unsupported extensions are rejected by the shared engine contract.

The Decision View is the first presentation action. English Reconstruction, Review Disclosure, and Evidence Drill-down use the same artifact identities exposed by OpenCode. The extension reads lifecycle and semantic outcome fields returned by K-Slide; it cannot mark a run `DONE` or convert review into completion.

## Install and build

Run the repository's `scripts/install_project.sh /path/to/workspace` to install collision-safe K-Slide engine and VS Code adapter source assets into the workspace. Build a VSIX with `scripts/build_vscode_extension.sh /path/to/output.vsix`. Install it into the active VS Code profile with `scripts/install_vscode_extension.sh`; the script requires the `code` CLI and updates only the K-Slide extension identity. In Cloud VS Code without the `code` CLI, use **Extensions: Install from VSIX…** and select the built VSIX.

Builds use Node `22.15.0`, npm `10.9.2`, TypeScript `5.9.3`, VS Code API types `1.96.0`, and VSCE `3.2.1`. Build output is created in a temporary directory and removed when packaging completes.

The extension requires a trusted local or remote workspace with the K-Slide engine installed. `kSlide.pythonPath` and `kSlide.engineRoot` are optional workspace/user settings; installation does not edit VS Code settings or unrelated extensions.
