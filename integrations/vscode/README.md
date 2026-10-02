# K-Slide for VS Code

This extension is a thin Cloud VS Code host adapter. It selects current or Explorer/picker files, sends versioned `HostInvocation` JSON to the installed K-Slide CLI over stdin, and opens the artifacts named by the engine-owned presentation descriptor. It does not implement translation, model selection, OCR, verification, or completion.

Commands are available in the Command Palette. Use **K-Slide: Run on Current File**, **K-Slide: Run on Selected Files…**, or **K-Slide: Run on This File** from Explorer. The multi-file picker and the engine use deterministic filename, source-kind, and locator ordering. Unsupported extensions are rejected by the shared engine contract.

The Decision View is the first presentation action. English Reconstruction, Review Disclosure, and Evidence Drill-down use the same artifact identities exposed by OpenCode. The extension reads lifecycle and semantic outcome fields returned by K-Slide; it cannot mark a run `DONE` or convert review into completion.

**Open Saved Runs** shows the latest 20 runs in each open workspace, including
persisted page counts and review state. The status bar refreshes the selected
run every 30 seconds. Reopening a result verifies its artifacts again.
**Check Runtime** reports capability checks without displaying raw diagnostics,
source content, paths or credentials. These checks do not certify production.
File preparation is cancellable; reopening saved runs also finds preparation
that was interrupted before the host received its run ID. Translation dispatch
depends on the company's managed host/job-service integration.

## Install and build

Run the repository's `scripts/install_project.sh /path/to/workspace` to install collision-safe K-Slide engine and VS Code adapter source assets into the workspace. Build a VSIX with `scripts/build_vscode_extension.sh /path/to/output.vsix`. Install it into the active VS Code profile with `scripts/install_vscode_extension.sh`; the script requires the `code` CLI and updates only the K-Slide extension identity. In Cloud VS Code without the `code` CLI, use **Extensions: Install from VSIX…** and select the built VSIX.

Builds use Node `22.15.0`, npm `10.9.2`, TypeScript `5.9.3`, VS Code API types `1.96.0`, and VSCE `3.2.1`. Build output is created in a temporary directory and removed when packaging completes.

Administrators can install an already-built VSIX with
`scripts/install_vscode_extension.sh /path/to/k-slide.vsix`; this path requires
neither Node nor npm on the employee host.

The extension requires a trusted local or remote workspace and a provisioned
K-Slide runtime. It supports an installed Python wheel as well as a source
installation. Runtime discovery uses administrator settings, `KSLIDE_ENGINE_ROOT`
and `KSLIDE_PYTHON`, then the source/workspace `.venv`, then `python3`.
An explicit unavailable engine fails instead of selecting a different engine.
The optional `kSlide.pythonPath` and `kSlide.engineRoot` settings are
administrator overrides; employees need no runtime configuration or API key.
