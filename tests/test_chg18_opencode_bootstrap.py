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
    APPROVED_API_ID,
    APPROVED_API_NPM,
    APPROVED_API_URL,
    APPROVED_ROUTE_IDENTITY,
    APPROVED_MODEL,
    APPROVED_MODEL_ID,
    APPROVED_PROVIDER_ID,
    COMPANY_ACCESS_KEY_ENV,
    FORBIDDEN_ENVIRONMENT,
    PROXY_ENVIRONMENT,
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
                "enabled_providers": [APPROVED_PROVIDER_ID],
                "provider": {APPROVED_PROVIDER_ID: {"whitelist": [APPROVED_MODEL_ID]}},
            },
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    models = config / "models.json"
    models.write_text(
        json.dumps(
            {
                APPROVED_PROVIDER_ID: {
                    "id": APPROVED_PROVIDER_ID,
                    "env": [APPROVED_CREDENTIAL_ENV],
                    "npm": APPROVED_API_NPM,
                    "api": APPROVED_API_URL,
                    "models": {APPROVED_MODEL_ID: {"id": APPROVED_API_ID}},
                }
            }
        )
        + "\n",
        encoding="utf-8",
    )
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


def _rewrite_artifact(manifest: Path, *, artifact: str, value: object) -> None:
    raw = json.loads(manifest.read_text(encoding="utf-8"))
    path_key, hash_key = {
        "config": ("config_file", "config_sha256"),
        "models": ("models_catalog", None),
    }[artifact]
    if artifact == "config":
        target = Path(raw[path_key])
        target.chmod(0o644)
        target.write_text(json.dumps(value, separators=(",", ":")) + "\n", encoding="utf-8")
        target.chmod(0o444)
        raw[hash_key] = _sha(target)
    else:
        target = Path(raw["models_catalog"]["path"])
        target.chmod(0o644)
        target.write_text(json.dumps(value, separators=(",", ":")) + "\n", encoding="utf-8")
        target.chmod(0o444)
        raw["models_catalog"]["sha256"] = _sha(target)
    manifest.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")


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

    def test_provider_surface_catalog_route_and_environment_sanitization(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _write_bootstrap(root)
            catalog = json.loads((root / "managed-home/.opencode/models.json").read_text(encoding="utf-8"))
            catalog["gitlab"] = {"id": "gitlab", "env": ["GITLAB_TOKEN"], "models": {"duo-workflow": {"id": "duo-workflow"}}}
            _rewrite_artifact(manifest, artifact="models", value=catalog)
            contract = load_bootstrap_manifest(manifest)
            self.assertEqual(contract.models_identity["provider"], APPROVED_PROVIDER_ID)
            self.assertEqual(contract.models_identity["model"], APPROVED_MODEL_ID)
            self.assertEqual(contract.models_identity["api_id"], APPROVED_API_ID)
            self.assertEqual(contract.models_identity["api_npm"], APPROVED_API_NPM)
            self.assertEqual(contract.models_identity["credential_environment"], APPROVED_CREDENTIAL_ENV)
            self.assertEqual(contract.models_identity["route_identity"], APPROVED_ROUTE_IDENTITY)
            self.assertIn("GITLAB_TOKEN", contract.catalog_environment)

            ambient = {
                APPROVED_CREDENTIAL_ENV: "google-key",
                COMPANY_ACCESS_KEY_ENV: "company-key",
                "ordinary_host_setting": "retained",
                "GITLAB_TOKEN": "gitlab-token",
                "AWS_ACCESS_KEY_ID": "aws-id",
                "AWS_SECRET_ACCESS_KEY": "aws-secret",
                "AWS_PROFILE": "developer",
                "GOOGLE_CLOUD_PROJECT": "vertex-project",
                "GOOGLE_VERTEX_LOCATION": "global",
                "CLOUDFLARE_API_TOKEN": "cloudflare-token",
                "CLOUDFLARE_ACCOUNT_ID": "cloudflare-account",
                "AICORE_SERVICE_KEY": "sap-key",
                "AICORE_DEPLOYMENT_ID": "sap-deployment",
                "OPENAI_API_KEY": "openai-key",
                "ANTHROPIC_API_KEY": "anthropic-key",
            }
            sanitized = bootstrap_environment(manifest, ambient)
            self.assertEqual(sanitized[APPROVED_CREDENTIAL_ENV], "google-key")
            self.assertEqual(sanitized[COMPANY_ACCESS_KEY_ENV], "company-key")
            self.assertEqual(sanitized["ordinary_host_setting"], "retained")
            for name in ambient:
                if name not in {APPROVED_CREDENTIAL_ENV, COMPANY_ACCESS_KEY_ENV, "ordinary_host_setting"}:
                    self.assertNotIn(name, sanitized)
            validate_bootstrap_environment(contract, sanitized)
            with self.assertRaises(KSlideError):
                validate_bootstrap_environment(contract, {**sanitized, "GITLAB_TOKEN": "ambient"})

    def test_managed_child_does_not_inherit_company_access_key_or_provider_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _write_bootstrap(root)
            node = subprocess.run(["which", "node"], capture_output=True, text=True, check=False).stdout.strip()
            if not node:
                self.skipTest("Node is unavailable for the provider-state boundary harness")
            child = """
                const fs = require("node:fs");
                const config = JSON.parse(fs.readFileSync(`${process.env.OPENCODE_CONFIG_DIR}/opencode.json`, "utf8"));
                const catalog = JSON.parse(fs.readFileSync(process.env.OPENCODE_MODELS_PATH, "utf8"));
                const discoveryCalls = [];
                const alternateNetworkCalls = [];
                const customLoaders = {
                  gitlab: () => { if (process.env.GITLAB_TOKEN) discoveryCalls.push("gitlab.discoverWorkflowModels"); },
                  "google-vertex": () => { if (process.env.GOOGLE_CLOUD_PROJECT) alternateNetworkCalls.push("google-vertex"); },
                  "cloudflare-workers-ai": () => { if (process.env.CLOUDFLARE_API_TOKEN) alternateNetworkCalls.push("cloudflare"); },
                  openai: () => { if (process.env.OPENAI_API_KEY) alternateNetworkCalls.push("openai"); },
                  anthropic: () => { if (process.env.ANTHROPIC_API_KEY) alternateNetworkCalls.push("anthropic"); },
                };
                for (const [providerID, loader] of Object.entries(customLoaders)) {
                  if (!config.enabled_providers.includes(providerID)) continue;
                  loader();
                }
                const providers = config.enabled_providers.filter((providerID) => Object.hasOwn(catalog, providerID));
                const models = config.provider.google.whitelist.filter((modelID) => Object.hasOwn(catalog.google.models, modelID));
                const route = catalog.google.api === "https://generativelanguage.googleapis.com/v1beta" && catalog.google.npm === "@ai-sdk/google" && models.length === 1 && models[0] === "gemma-4-31b-it";
                process.stdout.write(JSON.stringify({ providers, models, discoveryCalls, alternateNetworkCalls, googleCredential: Boolean(process.env.GOOGLE_GENERATIVE_AI_API_KEY), route, accessKey: process.env.AccessKey ?? null, gitlabToken: process.env.GITLAB_TOKEN ?? null, awsKey: process.env.AWS_ACCESS_KEY_ID ?? null, openaiKey: process.env.OPENAI_API_KEY ?? null }));
            """
            launch_env = {
                APPROVED_CREDENTIAL_ENV: "google-key",
                COMPANY_ACCESS_KEY_ENV: "company-key",
                "GITLAB_TOKEN": "gitlab-token",
                "AWS_ACCESS_KEY_ID": "aws-id",
                "GOOGLE_CLOUD_PROJECT": "vertex-project",
                "CLOUDFLARE_API_TOKEN": "cloudflare-token",
                "OPENAI_API_KEY": "openai-key",
                "ANTHROPIC_API_KEY": "anthropic-key",
                "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
                "PATH": os.environ.get("PATH", os.defpath),
            }
            managed = subprocess.run(
                [sys.executable, "-m", "k_slide.opencode_bootstrap", "--manifest", str(manifest), "--", node, "-e", child],
                cwd=str(root),
                env=launch_env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(managed.returncode, 0, managed.stderr)
            observed = json.loads(managed.stdout)
            self.assertEqual(observed["providers"], ["google"])
            self.assertEqual(observed["models"], ["gemma-4-31b-it"])
            self.assertEqual(observed["discoveryCalls"], [])
            self.assertEqual(observed["alternateNetworkCalls"], [])
            self.assertTrue(observed["googleCredential"])
            self.assertTrue(observed["route"])
            self.assertIsNone(observed["accessKey"])
            self.assertIsNone(observed["gitlabToken"])
            self.assertIsNone(observed["awsKey"])
            self.assertIsNone(observed["openaiKey"])

    def test_config_provider_surface_and_catalog_route_fail_closed(self) -> None:
        config_cases = []
        config_cases.append(lambda config: config.pop("enabled_providers"))
        config_cases.append(lambda config: config.__setitem__("enabled_providers", ["google", "openai"]))
        config_cases.append(lambda config: config.__setitem__("provider", {"google": {"whitelist": ["gemma-4-31b-it", "gemini-2.5-pro"]}}))
        config_cases.append(lambda config: config.__setitem__("disabled_providers", ["google"]))
        for mutate in config_cases:
            with self.subTest(kind="config"):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    manifest = _write_bootstrap(root)
                    config = json.loads((root / "managed-home/.opencode/opencode.json").read_text(encoding="utf-8"))
                    mutate(config)
                    _rewrite_artifact(manifest, artifact="config", value=config)
                    with self.assertRaises(KSlideError):
                        load_bootstrap_manifest(manifest)

        catalog_cases = []
        catalog_cases.append(lambda catalog: catalog[APPROVED_PROVIDER_ID].__setitem__("id", "google-vertex"))
        catalog_cases.append(lambda catalog: catalog[APPROVED_PROVIDER_ID].__setitem__("env", ["GOOGLE_API_KEY"]))
        catalog_cases.append(lambda catalog: catalog[APPROVED_PROVIDER_ID].__setitem__("api", "https://attacker.invalid"))
        catalog_cases.append(lambda catalog: catalog[APPROVED_PROVIDER_ID].__setitem__("npm", "@ai-sdk/openai"))
        catalog_cases.append(lambda catalog: catalog[APPROVED_PROVIDER_ID].__setitem__("options", {"apiKey": "alternate"}))
        catalog_cases.append(lambda catalog: catalog[APPROVED_PROVIDER_ID]["models"][APPROVED_MODEL_ID].__setitem__("provider", {"npm": "@ai-sdk/openai", "api": "https://attacker.invalid"}))
        catalog_cases.append(lambda catalog: catalog[APPROVED_PROVIDER_ID]["models"][APPROVED_MODEL_ID].__setitem__("api", "https://attacker.invalid"))
        catalog_cases.append(lambda catalog: catalog[APPROVED_PROVIDER_ID]["models"][APPROVED_MODEL_ID].__setitem__("env", ["GOOGLE_API_KEY"]))
        for mutate in catalog_cases:
            with self.subTest(kind="catalog"):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    manifest = _write_bootstrap(root)
                    catalog = json.loads((root / "managed-home/.opencode/models.json").read_text(encoding="utf-8"))
                    mutate(catalog)
                    _rewrite_artifact(manifest, artifact="models", value=catalog)
                    with self.assertRaises(KSlideError):
                        load_bootstrap_manifest(manifest)

    def test_proxy_environment_is_rejected_before_managed_launch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _write_bootstrap(root)
            for name in PROXY_ENVIRONMENT:
                with self.subTest(name=name), self.assertRaises(KSlideError):
                    bootstrap_environment(manifest, {APPROVED_CREDENTIAL_ENV: "provider-key", name: "http://proxy.invalid"})

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
