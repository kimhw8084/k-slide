from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from k_slide.errors import ErrorCode, KSlideError
from k_slide.opencode_bootstrap import (
    APPROVED_CREDENTIAL_ENV,
    APPROVED_MODEL,
    FORBIDDEN_ENVIRONMENT,
    REQUIRED_ENVIRONMENT,
    bootstrap_environment,
    load_bootstrap_manifest,
    validate_bootstrap_environment,
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_bootstrap(root: Path) -> Path:
    home = root / "managed-home"
    config = home / ".opencode"
    xdg_config = root / "xdg-config"
    xdg_data = root / "xdg-data"
    xdg_cache = root / "xdg-cache"
    xdg_state = root / "xdg-state"
    for path in (home, config, config / "plugin", config / "internal" / "lib", xdg_config, xdg_config / "opencode", xdg_data, xdg_data / "opencode", xdg_cache, xdg_cache / "opencode", xdg_state, xdg_state / "opencode"):
        path.mkdir(parents=True, exist_ok=True)
    plugin = config / "plugin" / "k-slide-host.ts"
    plugin.write_text("export default function KSlideHostPlugin() { return {} }\n", encoding="utf-8")
    helper = config / "internal" / "lib" / "k-slide-access-key.ts"
    helper.write_text("export function trustedAccessKey() { return undefined }\n", encoding="utf-8")
    config_file = config / "opencode.json"
    config_file.write_text(
        json.dumps(
            {
                "plugin": ["./plugin/k-slide-host.ts"],
                "agent": {"k-slide": {"model": APPROVED_MODEL}},
                "autoupdate": False,
                "lsp": False,
            },
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    models = config / "models.json"
    models.write_text(json.dumps({"google": {"models": {"gemma-4-31b-it": {}}}}) + "\n", encoding="utf-8")
    ripgrep = root / "managed-bin" / "rg"
    ripgrep.parent.mkdir()
    ripgrep.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    ripgrep.chmod(0o555)
    for file_path in (config_file, plugin, helper, models):
        file_path.chmod(0o444)
    for path in (config, config / "plugin", config / "internal", config / "internal" / "lib", xdg_config, xdg_config / "opencode"):
        path.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    manifest_dir = root / ".k-slide-config"
    manifest_dir.mkdir()
    manifest = manifest_dir / "opencode-bootstrap.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "opencode_version": "1.3.9",
                "required_environment": REQUIRED_ENVIRONMENT,
                "forbidden_environment": list(FORBIDDEN_ENVIRONMENT),
                "home_dir": str(home),
                "config_dir": str(config),
                "xdg_config_home": str(xdg_config),
                "xdg_data_home": str(xdg_data),
                "xdg_cache_home": str(xdg_cache),
                "xdg_state_home": str(xdg_state),
                "config_file": str(config_file),
                "config_sha256": _sha(config_file),
                "plugin_file": str(plugin),
                "plugin_sha256": _sha(plugin),
                "access_key_helper_file": str(helper),
                "access_key_helper_sha256": _sha(helper),
                "ripgrep_path": str(ripgrep),
                "ripgrep_sha256": _sha(ripgrep),
                "models_catalog": {"mode": "local_path", "path": str(models), "sha256": _sha(models), "version": "test-models-v1"},
                "credential_environment": [APPROVED_CREDENTIAL_ENV],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return manifest


class OpenCodeBootstrapTests(unittest.TestCase):
    def test_manifest_is_source_free_and_bootstrap_sets_controls_before_exec(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _write_bootstrap(root)
            contract = load_bootstrap_manifest(manifest)
            self.assertNotIn("://", manifest.read_text(encoding="utf-8"))
            environment = bootstrap_environment(manifest, {APPROVED_CREDENTIAL_ENV: "provider-key"})
            self.assertEqual(environment["OPENCODE_DISABLE_MODELS_FETCH"], "1")
            self.assertEqual(environment["OPENCODE_DISABLE_AUTOUPDATE"], "1")
            self.assertEqual(environment["OPENCODE_DISABLE_LSP_DOWNLOAD"], "1")
            self.assertEqual(environment["OPENCODE_DISABLE_PROJECT_CONFIG"], "1")
            self.assertEqual(environment["OPENCODE_MODELS_PATH"], contract.models_path)
            self.assertEqual(environment["OPENCODE_CONFIG_DIR"], str(root / "managed-home/.opencode"))
            self.assertTrue(environment["PATH"].split(":", 1)[0].endswith("managed-bin"))
            with self.assertRaises(KSlideError) as missing:
                bootstrap_environment(manifest, {})
            self.assertEqual(missing.exception.code, ErrorCode.OPENCODE_BOOTSTRAP_INVALID)
            with self.assertRaises(KSlideError):
                bootstrap_environment(manifest, {APPROVED_CREDENTIAL_ENV: "provider-key", "OPENCODE_MODELS_URL": "https://models.dev"})
            with self.assertRaises(KSlideError):
                validate_bootstrap_environment(contract, {APPROVED_CREDENTIAL_ENV: "provider-key"})

    def test_pre_module_network_trap_proves_unmanaged_refresh_and_managed_suppression(self) -> None:
        node = subprocess.run(["which", "node"], capture_output=True, text=True, check=False).stdout.strip()
        if not node:
            self.skipTest("Node is unavailable for the OpenCode startup-order harness")
        child = textwrap.dedent(
            """
            const fs = require("node:fs");
            const requests = [];
            globalThis.fetch = async (input) => { requests.push(String(input)); throw new Error("network trap"); };
            const truthy = (name) => ["true", "1"].includes(String(process.env[name] || "").toLowerCase());

            // Exact v1.3.9 provider/models.ts module-initialization gate.
            if (!truthy("OPENCODE_DISABLE_MODELS_FETCH")) {
              void fetch("https://models.dev/api.json").catch(() => {});
            }
            // Exact v1.3.9 upgrade lookup gate (the URL varies by install method;
            // this is the fallback GitHub release path).
            if (!truthy("OPENCODE_DISABLE_AUTOUPDATE")) {
              void fetch("https://api.github.com/repos/anomalyco/opencode/releases/latest").catch(() => {});
            }
            // Exact v1.3.9 Config.needsInstall/BunProc.install boundary.
            if (!truthy("OPENCODE_DISABLE_PROJECT_CONFIG") && !fs.existsSync("/managed/node_modules/@opencode-ai/plugin")) {
              void fetch("https://registry.npmjs.org/@opencode-ai/plugin").catch(() => {});
            }
            // Exact v1.3.9 LSP download gate representative of the download call sites.
            if (!truthy("OPENCODE_DISABLE_LSP_DOWNLOAD")) {
              void fetch("https://github.com/microsoft/vscode-eslint/archive/refs/heads/main.zip").catch(() => {});
            }
            // Exact v1.3.9 file/ripgrep.ts fallback: a missing system rg downloads
            // a release archive into Global.Path.bin.
            const pathEntries = String(process.env.PATH || "").split(require("node:path").delimiter);
            if (!pathEntries.some((entry) => fs.existsSync(require("node:path").join(entry, "rg")))) {
              void fetch("https://github.com/BurntSushi/ripgrep/releases/download/14.1.1/ripgrep-14.1.1-x86_64-unknown-linux-musl.tar.gz").catch(() => {});
            }
            setImmediate(() => process.stdout.write(JSON.stringify(requests)));
            """
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _write_bootstrap(root)
            script = root / "startup-trap.js"
            script.write_text(child, encoding="utf-8")
            empty_path = root / "empty-bin"
            empty_path.mkdir()
            unmanaged_env = dict(os.environ)
            unmanaged_env["PATH"] = str(empty_path)
            unmanaged = subprocess.run([node, str(script)], capture_output=True, text=True, check=False, env=unmanaged_env)
            unmanaged_requests = json.loads(unmanaged.stdout)
            self.assertIn("https://models.dev/api.json", unmanaged_requests)
            self.assertIn("https://api.github.com/repos/anomalyco/opencode/releases/latest", unmanaged_requests)
            self.assertIn("https://registry.npmjs.org/@opencode-ai/plugin", unmanaged_requests)
            self.assertIn("https://github.com/microsoft/vscode-eslint/archive/refs/heads/main.zip", unmanaged_requests)
            self.assertIn("https://github.com/BurntSushi/ripgrep/releases/download/14.1.1/ripgrep-14.1.1-x86_64-unknown-linux-musl.tar.gz", unmanaged_requests)

            launch_env = dict(os.environ)
            launch_env[APPROVED_CREDENTIAL_ENV] = "provider-key"
            launch_env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
            managed = subprocess.run(
                [sys.executable, "-m", "k_slide.opencode_bootstrap", "--manifest", str(manifest), "--", node, str(script)],
                cwd=str(root),
                env=launch_env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(managed.returncode, 0, managed.stderr)
            self.assertEqual(json.loads(managed.stdout), [])


if __name__ == "__main__":
    unittest.main()
