"""Managed, pre-start OpenCode bootstrap for the production K-Slide host.

OpenCode reads several egress-affecting flags while importing modules.  This
module is intentionally dependency-free so a deployment can run it before the
OpenCode executable is imported and then replace itself with ``exec``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import signal
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .egress_policy import opencode_route_identity
from .errors import ErrorCode, KSlideError
from .access_key_handoff import AccessKeyBoundaryError, AccessKeyHandoff


BOOTSTRAP_SCHEMA_VERSION = "1.0"
OPENCODE_VERSION = "1.3.9"
APPROVED_MODEL = "google/gemma-4-31b-it"
APPROVED_PROVIDER_ID = "google"
APPROVED_MODEL_ID = "gemma-4-31b-it"
APPROVED_API_ID = "gemma-4-31b-it"
APPROVED_API_NPM = "@ai-sdk/google"
APPROVED_API_URL = "https://generativelanguage.googleapis.com/v1beta"
APPROVED_PLUGIN = "./plugin/k-slide-host.ts"
APPROVED_CREDENTIAL_ENV = "GOOGLE_GENERATIVE_AI_API_KEY"
COMPANY_ACCESS_KEY_ENV = "AccessKey"
REQUIRED_ENVIRONMENT = {
    "OPENCODE_DISABLE_MODELS_FETCH": "1",
    "OPENCODE_DISABLE_AUTOUPDATE": "1",
    "OPENCODE_DISABLE_LSP_DOWNLOAD": "1",
    "OPENCODE_DISABLE_PROJECT_CONFIG": "1",
}
FORBIDDEN_ENVIRONMENT = (
    "OPENCODE_MODELS_URL",
    "OPENCODE_CONFIG",
    "OPENCODE_CONFIG_CONTENT",
    "OPENCODE_PURE",
    "OPENCODE_TEST_MANAGED_CONFIG_DIR",
)
PROXY_ENVIRONMENT = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
)
_PROVIDER_ENVIRONMENT_NAMES = frozenset({
    "GITLAB_TOKEN",
    "GITLAB_INSTANCE_URL",
    "GITLAB_HOST",
    "GITLAB_TOKEN_OPENCODE",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_PROFILE",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_BEARER_TOKEN_BEDROCK",
    "AWS_REGION",
    "AWS_DEFAULT_REGION",
    "AWS_ROLE_ARN",
    "AWS_ROLE_SESSION_NAME",
    "AWS_SDK_LOAD_CONFIG",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_CONFIG_FILE",
    "AWS_CA_BUNDLE",
    "AWS_EC2_METADATA_SERVICE_ENDPOINT",
    "AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE",
    "AWS_EC2_METADATA_DISABLED",
    "AWS_ENDPOINT_URL",
    "AWS_ENDPOINT_URL_S3",
    "AWS_STS_ENDPOINT",
    "AWS_USE_FIPS_ENDPOINT",
    "GOOGLE_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GOOGLE_APPLICATION_CREDENTIALS_JSON",
    "GOOGLE_AUTHENTICATION_CREDENTIALS",
    "GOOGLE_CLOUD_PROJECT",
    "GOOGLE_CLOUD_LOCATION",
    "GOOGLE_CLOUD_QUOTA_PROJECT",
    "GCP_PROJECT",
    "GCLOUD_PROJECT",
    "GOOGLE_VERTEX_PROJECT",
    "GOOGLE_VERTEX_LOCATION",
    "GOOGLE_VERTEX_ENDPOINT",
    "VERTEX_LOCATION",
    "OPENAI_API_KEY",
    "OPENAI_BASE_URL",
    "OPENAI_API_BASE",
    "OPENAI_ORG_ID",
    "OPENAI_PROJECT_ID",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_API_URL",
    "CLOUDFLARE_ACCOUNT_ID",
    "CLOUDFLARE_API_KEY",
    "CLOUDFLARE_API_TOKEN",
    "CLOUDFLARE_GATEWAY_ID",
    "CF_AIG_TOKEN",
    "AICORE_SERVICE_KEY",
    "AICORE_AUTH_URL",
    "AICORE_CLIENT_ID",
    "AICORE_CLIENT_SECRET",
    "AICORE_BASE_URL",
    "AICORE_DEPLOYMENT_ID",
    "AICORE_RESOURCE_GROUP",
    "AICORE_URL",
})
_PROVIDER_ENVIRONMENT_PREFIXES = (
    "AWS_",
    "GITLAB_",
    "CLOUDFLARE_",
    "AICORE_",
    "OPENAI_",
    "ANTHROPIC_",
    "GOOGLE_",
    "GEMINI_",
    "GOOGLE_VERTEX_",
    "GOOGLE_CLOUD_",
    "GOOGLE_APPLICATION_",
    "GOOGLE_AUTHENTICATION_",
    "GCP_",
    "GCLOUD_",
    "VERTEX_",
)
_CATALOG_ROUTE_KEYS = frozenset({
    "api",
    "api_url",
    "base_url",
    "endpoint",
    "headers",
    "npm",
    "options",
    "package",
    "provider",
    "proxy",
    "url",
})
_NORMALIZED_CATALOG_ROUTE_KEYS = frozenset(item.replace("_", "") for item in _CATALOG_ROUTE_KEYS)
_CATALOG_CREDENTIAL_KEYS = frozenset({"auth", "apikey", "credential", "credentials", "env", "key", "token"})
_SHA256 = set("0123456789abcdef")


APPROVED_ROUTE_IDENTITY = opencode_route_identity(
    provider_id=APPROVED_PROVIDER_ID,
    model_id=APPROVED_MODEL_ID,
    api_id=APPROVED_API_ID,
    api_npm=APPROVED_API_NPM,
    api_url=APPROVED_API_URL,
)


def _invalid(message: str, **details: Any) -> KSlideError:
    return KSlideError(ErrorCode.OPENCODE_BOOTSTRAP_INVALID, message, details)


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise _invalid("OpenCode bootstrap identity is not canonical.") from exc


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()
    except (OSError, UnicodeError) as exc:
        raise _invalid("OpenCode bootstrap artifact is unreadable.", artifact=path.name) from exc


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and not (set(value.lower()) - _SHA256)


def _resolved_path(raw: Any, *, label: str) -> Path:
    if not isinstance(raw, str) or not raw.strip():
        raise _invalid(f"OpenCode bootstrap {label} is missing.")
    value = Path(raw).expanduser()
    if not value.is_absolute():
        raise _invalid(f"OpenCode bootstrap {label} must be absolute.")
    return value


def _require_directory(path: Path, *, label: str, read_only: bool = False) -> None:
    try:
        mode = path.lstat()
    except OSError as exc:
        raise _invalid(f"OpenCode bootstrap {label} is missing.", path=str(path)) from exc
    if stat.S_ISLNK(mode.st_mode) or not stat.S_ISDIR(mode.st_mode):
        raise _invalid(f"OpenCode bootstrap {label} must be a real directory.", path=str(path))
    if read_only and mode.st_mode & 0o222:
        raise _invalid(f"OpenCode bootstrap {label} must be read-only.", path=str(path))


def _require_file(path: Path, *, label: str, expected_hash: str | None = None) -> str:
    try:
        mode = path.lstat()
    except OSError as exc:
        raise _invalid(f"OpenCode bootstrap {label} is missing.", path=str(path)) from exc
    if stat.S_ISLNK(mode.st_mode) or not stat.S_ISREG(mode.st_mode):
        raise _invalid(f"OpenCode bootstrap {label} must be a real file.", path=str(path))
    actual = _sha256_file(path)
    if expected_hash is not None and actual != expected_hash.lower():
        raise _invalid(f"OpenCode bootstrap {label} hash drifted.", path=path.name)
    return actual


def _require_empty_directory(path: Path, *, label: str, read_only: bool = False) -> None:
    _require_directory(path, label=label, read_only=read_only)
    try:
        entries = tuple(path.iterdir())
    except OSError as exc:
        raise _invalid(f"OpenCode bootstrap {label} is unreadable.", path=str(path)) from exc
    if entries:
        raise _invalid(f"OpenCode bootstrap {label} must be empty.", path=str(path))


def _require_absent(path: Path, *, label: str) -> None:
    if path.exists() or path.is_symlink():
        raise _invalid(f"OpenCode bootstrap {label} must not exist.", path=str(path))


def _system_managed_config_dir() -> Path:
    if sys.platform == "darwin":
        return Path("/Library/Application Support/opencode")
    if sys.platform == "win32":
        return Path(os.environ.get("ProgramData", "C:/ProgramData")) / "opencode"
    return Path("/etc/opencode")


def _validate_system_managed_config() -> None:
    system_dir = _system_managed_config_dir()
    if not system_dir.exists() and not system_dir.is_symlink():
        return
    _require_empty_directory(system_dir, label="system-managed config", read_only=True)


def _reject_urls(value: Any) -> None:
    if isinstance(value, str) and "://" in value:
        raise _invalid("OpenCode bootstrap must not persist remote URLs.")
    if isinstance(value, dict):
        for child in value.values():
            _reject_urls(child)
    elif isinstance(value, list):
        for child in value:
            _reject_urls(child)


def _config_identity(config: Mapping[str, Any]) -> dict[str, Any]:
    plugin = config.get("plugin")
    if plugin != [APPROVED_PLUGIN]:
        raise _invalid("Managed OpenCode config must load only the shipped local K-Slide plugin.")
    agent = config.get("agent")
    kslide = agent.get("k-slide") if isinstance(agent, dict) else None
    if not isinstance(kslide, dict) or kslide.get("model") != APPROVED_MODEL:
        raise _invalid("Managed OpenCode config must pin the K-Slide agent model.")
    if set(kslide) != {"model"} or set(agent) != {"k-slide"}:
        raise _invalid("Managed OpenCode config contains unapproved agent settings.")
    if config.get("enabled_providers") != [APPROVED_PROVIDER_ID]:
        raise _invalid("Managed OpenCode config must allowlist only the approved Google provider.")
    provider = config.get("provider")
    if not isinstance(provider, dict) or set(provider) != {APPROVED_PROVIDER_ID}:
        raise _invalid("Managed OpenCode config must declare only the approved Google provider.")
    google = provider.get(APPROVED_PROVIDER_ID)
    if not isinstance(google, dict) or set(google) != {"whitelist"} or google.get("whitelist") != [APPROVED_MODEL_ID]:
        raise _invalid("Managed OpenCode config must whitelist only the approved Gemma model.")
    disabled = config.get("disabled_providers", [])
    if not isinstance(disabled, list) or any(not isinstance(item, str) for item in disabled) or len(set(disabled)) != len(disabled):
        raise _invalid("Managed OpenCode config disabled provider policy is malformed.")
    if APPROVED_PROVIDER_ID in disabled:
        raise _invalid("Managed OpenCode config cannot disable the approved Google provider.")
    if config.get("autoupdate") is not False or config.get("lsp") is not False:
        raise _invalid("Managed OpenCode config must disable update and LSP activation.")
    allowed_keys = {"plugin", "agent", "autoupdate", "lsp", "enabled_providers", "disabled_providers", "provider"}
    if set(config) - allowed_keys:
        raise _invalid("Managed OpenCode config contains unapproved ambient settings.")
    return {
        "plugin": [APPROVED_PLUGIN],
        "agent_model": APPROVED_MODEL,
        "autoupdate": False,
        "lsp": False,
        "enabled_providers": [APPROVED_PROVIDER_ID],
        "disabled_providers": list(disabled),
        "provider_google_whitelist": [APPROVED_MODEL_ID],
    }


def _catalog_environment_names(catalog: Mapping[str, Any]) -> tuple[str, ...]:
    names: set[str] = set()
    for provider in catalog.values():
        if not isinstance(provider, Mapping):
            continue
        environment = provider.get("env")
        if isinstance(environment, list):
            names.update(item for item in environment if isinstance(item, str) and item)
    return tuple(sorted(names))


def _validate_models_catalog(catalog: Any) -> tuple[dict[str, str], tuple[str, ...]]:
    if not isinstance(catalog, Mapping):
        raise _invalid("OpenCode model catalog must be a JSON object.")
    provider = catalog.get(APPROVED_PROVIDER_ID)
    if not isinstance(provider, Mapping):
        raise _invalid("OpenCode model catalog is missing the approved Google provider.")
    if set(provider) - {"id", "name", "env", "npm", "api", "models"}:
        raise _invalid("OpenCode model catalog Google provider contains unsupported authority fields.")
    if provider.get("id") != APPROVED_PROVIDER_ID:
        raise _invalid("OpenCode model catalog Google provider identity is not exact.")
    if provider.get("env") != [APPROVED_CREDENTIAL_ENV]:
        raise _invalid("OpenCode model catalog Google credential route is not the approved seam.")
    if provider.get("npm") != APPROVED_API_NPM or provider.get("api") != APPROVED_API_URL:
        raise _invalid("OpenCode model catalog Google API/package/endpoint route is not exact.")
    models = provider.get("models")
    if not isinstance(models, Mapping):
        raise _invalid("OpenCode model catalog Google models are unresolved.")
    model = models.get(APPROVED_MODEL_ID)
    if not isinstance(model, Mapping) or model.get("id") != APPROVED_API_ID:
        raise _invalid("OpenCode model catalog is missing the exact approved Gemma model.")
    model_provider = model.get("provider")
    if model_provider is not None:
        if not isinstance(model_provider, Mapping) or set(model_provider) - {"npm", "api"}:
            raise _invalid("OpenCode model catalog approved model provider metadata is unsupported.")
        if model_provider.get("npm", APPROVED_API_NPM) != APPROVED_API_NPM or model_provider.get("api", APPROVED_API_URL) != APPROVED_API_URL:
            raise _invalid("OpenCode model catalog approved model route metadata is not exact.")
    for key in model:
        normalized = str(key).casefold().replace("-", "_").replace("_", "")
        if normalized in _NORMALIZED_CATALOG_ROUTE_KEYS and key not in {"provider"}:
            raise _invalid("OpenCode model catalog approved model contains alternate route authority.")
        if normalized in _CATALOG_CREDENTIAL_KEYS:
            raise _invalid("OpenCode model catalog approved model contains alternate route authority.")
    route_identity = opencode_route_identity(
        provider_id=APPROVED_PROVIDER_ID,
        model_id=APPROVED_MODEL_ID,
        api_id=APPROVED_API_ID,
        api_npm=APPROVED_API_NPM,
        api_url=APPROVED_API_URL,
    )
    return (
        {
            "provider": APPROVED_PROVIDER_ID,
            "model": APPROVED_MODEL_ID,
            "api_id": APPROVED_API_ID,
            "api_npm": APPROVED_API_NPM,
            "credential_environment": APPROVED_CREDENTIAL_ENV,
            "route_identity": route_identity,
        },
        _catalog_environment_names(catalog),
    )


def _models_identity(value: Mapping[str, Any]) -> tuple[dict[str, Any], str | None, tuple[str, ...]]:
    if not isinstance(value, Mapping):
        raise _invalid("OpenCode model catalog identity must be an object.")
    allowed = {"mode", "path", "sha256", "version"}
    if set(value) - allowed:
        raise _invalid("OpenCode model catalog identity contains unsupported fields.")
    mode = value.get("mode")
    if mode not in {"local_path", "bundled_snapshot"}:
        raise _invalid("OpenCode model catalog must be a verified local or bundled snapshot.")
    digest = value.get("sha256")
    version = value.get("version")
    if not _is_sha256(digest) or not isinstance(version, str) or not version.strip() or "://" in version:
        raise _invalid("OpenCode model catalog requires a source-free hash and version.")
    path_value: str | None = None
    catalog_path: Path
    if mode == "local_path":
        catalog_path = _resolved_path(value.get("path"), label="models catalog path")
        actual = _require_file(catalog_path, label="models catalog", expected_hash=str(digest))
        path_value = str(catalog_path)
        if actual != str(digest).lower():
            raise _invalid("OpenCode model catalog hash drifted.")
    else:
        catalog_path = _resolved_path(value.get("path"), label="bundled model snapshot")
        _require_file(catalog_path, label="bundled model snapshot", expected_hash=str(digest))
    try:
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise _invalid("OpenCode model catalog is unreadable or malformed.") from exc
    route_identity, catalog_environment = _validate_models_catalog(catalog)
    identity = {
        "mode": str(mode),
        "sha256": str(digest).lower(),
        "version": version,
        **route_identity,
        "catalog_environment": ",".join(catalog_environment),
    }
    return identity, path_value, catalog_environment


@dataclass(frozen=True)
class OpenCodeBootstrap:
    manifest_path: Path
    opencode_version: str
    home_dir: Path
    config_dir: Path
    xdg_config_home: Path
    xdg_data_home: Path
    xdg_cache_home: Path
    xdg_state_home: Path
    config_file: Path
    plugin_file: Path
    config_sha256: str
    plugin_sha256: str
    access_key_helper_sha256: str
    ripgrep_path: Path
    ripgrep_sha256: str
    models_identity: dict[str, Any]
    models_path: str | None
    catalog_environment: tuple[str, ...]
    credential_environment: tuple[str, ...]
    identity: str

    @property
    def environment_identity(self) -> str:
        return self.identity


def load_bootstrap_manifest(path: Path) -> OpenCodeBootstrap:
    path = path.expanduser().resolve()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise _invalid("OpenCode bootstrap manifest is missing or malformed.", path=str(path)) from exc
    if not isinstance(raw, dict):
        raise _invalid("OpenCode bootstrap manifest must be an object.")
    if raw.get("schema_version") != BOOTSTRAP_SCHEMA_VERSION or raw.get("opencode_version") != OPENCODE_VERSION:
        raise _invalid("OpenCode bootstrap manifest version is unsupported or unresolved.")
    expected_keys = {
        "schema_version", "opencode_version", "required_environment", "forbidden_environment",
        "home_dir", "config_dir", "xdg_config_home", "xdg_data_home", "xdg_cache_home",
        "xdg_state_home", "config_file", "config_sha256", "plugin_file", "plugin_sha256",
        "access_key_helper_file", "access_key_helper_sha256", "ripgrep_path", "ripgrep_sha256",
        "models_catalog", "credential_environment",
    }
    if set(raw) != expected_keys:
        raise _invalid("OpenCode bootstrap manifest contains unsupported or missing fields.")
    _reject_urls(raw)
    if not isinstance(raw["required_environment"], dict) or not isinstance(raw["forbidden_environment"], list):
        raise _invalid("OpenCode bootstrap environment controls are malformed.")
    if raw["required_environment"] != REQUIRED_ENVIRONMENT or tuple(raw["forbidden_environment"]) != FORBIDDEN_ENVIRONMENT:
        raise _invalid("OpenCode bootstrap environment controls are incomplete or inconsistent.")
    credential_environment = raw.get("credential_environment")
    if credential_environment != [APPROVED_CREDENTIAL_ENV]:
        raise _invalid("OpenCode bootstrap credential environment is not the approved provider seam.")

    home_dir = _resolved_path(raw.get("home_dir"), label="managed home")
    config_dir = _resolved_path(raw.get("config_dir"), label="config directory")
    xdg_config_home = _resolved_path(raw.get("xdg_config_home"), label="XDG config home")
    xdg_data_home = _resolved_path(raw.get("xdg_data_home"), label="XDG data home")
    xdg_cache_home = _resolved_path(raw.get("xdg_cache_home"), label="XDG cache home")
    xdg_state_home = _resolved_path(raw.get("xdg_state_home"), label="XDG state home")
    for item, label in (
        (home_dir, "managed home"),
        (config_dir, "managed config directory"),
        (xdg_config_home, "XDG config home"),
        (xdg_data_home, "XDG data home"),
        (xdg_cache_home, "XDG cache home"),
        (xdg_state_home, "XDG state home"),
    ):
        _require_directory(item, label=label, read_only=label in {"managed config directory", "XDG config home"})
    global_config_dir = xdg_config_home / "opencode"
    _require_empty_directory(global_config_dir, label="isolated global config", read_only=True)
    for item, label in (
        (xdg_data_home / "opencode", "isolated data directory"),
        (xdg_cache_home / "opencode", "isolated cache directory"),
        (xdg_state_home / "opencode", "isolated state directory"),
    ):
        _require_directory(item, label=label)
    _require_absent(xdg_data_home / "opencode" / "auth.json", label="ambient provider auth state")
    _require_absent(xdg_data_home / "opencode" / "mcp-auth.json", label="ambient MCP auth state")
    _validate_system_managed_config()
    if config_dir.parent != home_dir or config_dir.name != ".opencode":
        raise _invalid("Managed OpenCode config must be the isolated home .opencode directory.")
    if home_dir / ".opencode" != config_dir:
        raise _invalid("Managed OpenCode home/config isolation is inconsistent.")
    if (home_dir / ".opencode").is_symlink():
        raise _invalid("Managed OpenCode home config must not be symlinked.")
    ambient_home_config = home_dir / ".config"
    if ambient_home_config.exists() or ambient_home_config.is_symlink():
        raise _invalid("Managed OpenCode home contains an ambient .config directory.")
    config_file = _resolved_path(raw.get("config_file"), label="config file")
    plugin_file = _resolved_path(raw.get("plugin_file"), label="plugin file")
    if config_file.parent != config_dir or plugin_file != config_dir / "plugin" / "k-slide-host.ts":
        raise _invalid("Managed OpenCode config/plugin paths are inconsistent.")
    _require_directory(config_dir / "plugin", label="managed plugin directory", read_only=True)
    _require_directory(config_dir / "internal" / "lib", label="managed K-Slide helper directory", read_only=True)
    helper_file = _resolved_path(raw.get("access_key_helper_file"), label="K-Slide access-key helper")
    if helper_file != config_dir / "internal" / "lib" / "k-slide-access-key.ts":
        raise _invalid("Managed K-Slide helper path is inconsistent.")
    if not _is_sha256(raw.get("config_sha256")) or not _is_sha256(raw.get("plugin_sha256")):
        raise _invalid("OpenCode bootstrap config/plugin hashes are unresolved.")
    if not _is_sha256(raw.get("access_key_helper_sha256")):
        raise _invalid("OpenCode bootstrap K-Slide helper hash is unresolved.")
    config_sha256 = _require_file(config_file, label="config file", expected_hash=str(raw["config_sha256"]))
    plugin_sha256 = _require_file(plugin_file, label="K-Slide plugin", expected_hash=str(raw["plugin_sha256"]))
    access_key_helper_sha256 = _require_file(helper_file, label="K-Slide access-key helper", expected_hash=str(raw["access_key_helper_sha256"]))
    ripgrep_path = _resolved_path(raw.get("ripgrep_path"), label="ripgrep binary")
    try:
        ripgrep_mode = ripgrep_path.lstat().st_mode
    except OSError as exc:
        raise _invalid("OpenCode bootstrap ripgrep binary is missing.", path=str(ripgrep_path)) from exc
    if not (ripgrep_mode & 0o111):
        raise _invalid("OpenCode bootstrap ripgrep binary is not executable.", path=str(ripgrep_path))
    ripgrep_sha256 = _require_file(ripgrep_path, label="ripgrep binary", expected_hash=str(raw["ripgrep_sha256"]))
    try:
        config = json.loads(config_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise _invalid("Managed OpenCode config is unreadable or malformed.") from exc
    if not isinstance(config, dict):
        raise _invalid("Managed OpenCode config must be an object.")
    config_identity = _config_identity(config)
    models_identity, models_path, catalog_environment = _models_identity(raw["models_catalog"])

    identity_payload = {
        "schema_version": BOOTSTRAP_SCHEMA_VERSION,
        "opencode_version": OPENCODE_VERSION,
        "required_environment": REQUIRED_ENVIRONMENT,
        "forbidden_environment": list(FORBIDDEN_ENVIRONMENT),
        "config_sha256": config_sha256,
        "plugin_sha256": plugin_sha256,
        "access_key_helper_sha256": access_key_helper_sha256,
        "ripgrep_sha256": ripgrep_sha256,
        "config_identity": config_identity,
        "models_catalog": models_identity,
        "catalog_environment": list(catalog_environment),
        "credential_environment": list(credential_environment),
    }
    return OpenCodeBootstrap(
        manifest_path=path,
        opencode_version=OPENCODE_VERSION,
        home_dir=home_dir,
        config_dir=config_dir,
        xdg_config_home=xdg_config_home,
        xdg_data_home=xdg_data_home,
        xdg_cache_home=xdg_cache_home,
        xdg_state_home=xdg_state_home,
        config_file=config_file,
        plugin_file=plugin_file,
        config_sha256=config_sha256,
        plugin_sha256=plugin_sha256,
        access_key_helper_sha256=access_key_helper_sha256,
        ripgrep_path=ripgrep_path,
        ripgrep_sha256=ripgrep_sha256,
        models_identity=models_identity,
        models_path=models_path,
        catalog_environment=catalog_environment,
        credential_environment=tuple(credential_environment),
        identity=_sha256_bytes(_canonical(identity_payload)),
    )


def _is_provider_environment_name(name: str, catalog_environment: tuple[str, ...] = ()) -> bool:
    if name in {APPROVED_CREDENTIAL_ENV, COMPANY_ACCESS_KEY_ENV}:
        return False
    if name in catalog_environment or name in _PROVIDER_ENVIRONMENT_NAMES:
        return True
    if any(name.startswith(prefix) for prefix in _PROVIDER_ENVIRONMENT_PREFIXES):
        return True
    return name.startswith("GOOGLE_GENERATIVE_AI_")


def _ambient_provider_environment(current: Mapping[str, str], catalog_environment: tuple[str, ...]) -> list[str]:
    return sorted(name for name in current if _is_provider_environment_name(name, catalog_environment))


def _reject_proxy_environment(current: Mapping[str, str]) -> None:
    present = [name for name in PROXY_ENVIRONMENT if name in current]
    if present:
        raise _invalid("Managed OpenCode bootstrap rejects ambient proxy route overrides.", fields=present)


def validate_bootstrap_environment(
    contract: OpenCodeBootstrap,
    environ: Mapping[str, str] | None = None,
    *,
    require_credentials: bool = True,
    require_bootstrap_flags: bool = True,
    require_managed_paths: bool = True,
    reject_ambient_provider_state: bool = True,
) -> None:
    current = dict(os.environ if environ is None else environ)
    _reject_proxy_environment(current)
    forbidden = [name for name in FORBIDDEN_ENVIRONMENT if name in current]
    if forbidden:
        raise _invalid("OpenCode bootstrap rejects ambient config/plugin overrides.", fields=forbidden)
    if require_bootstrap_flags:
        mismatched = [name for name, value in REQUIRED_ENVIRONMENT.items() if current.get(name) != value]
        if mismatched:
            raise _invalid("Required OpenCode pre-start flags are missing or inconsistent.", fields=mismatched)
    if require_managed_paths:
        expected_paths = {
            "HOME": str(contract.home_dir),
            "USERPROFILE": str(contract.home_dir),
            "XDG_CONFIG_HOME": str(contract.xdg_config_home),
            "XDG_DATA_HOME": str(contract.xdg_data_home),
            "XDG_CACHE_HOME": str(contract.xdg_cache_home),
            "XDG_STATE_HOME": str(contract.xdg_state_home),
            "OPENCODE_CONFIG_DIR": str(contract.config_dir),
        }
        mismatched_paths = [name for name, value in expected_paths.items() if current.get(name) != value]
        if mismatched_paths:
            raise _invalid("Managed OpenCode home/config paths are missing or inconsistent.", fields=mismatched_paths)
        path_entries = current.get("PATH", "").split(os.pathsep)
        if not path_entries or path_entries[0] != str(contract.ripgrep_path.parent):
            raise _invalid("Managed OpenCode PATH does not pin the verified ripgrep binary.")
    if current.get("OPENCODE_MODELS_PATH") not in (None, contract.models_path):
        raise _invalid("OpenCode model catalog path is inconsistent with the managed bootstrap.")
    if reject_ambient_provider_state:
        ambient = _ambient_provider_environment(current, contract.catalog_environment)
        if ambient:
            raise _invalid("Managed OpenCode environment contains unapproved provider credentials or selectors.", fields=ambient)
    if require_credentials:
        missing = [name for name in contract.credential_environment if not current.get(name)]
        if missing:
            raise _invalid("Required provider credential environment is missing.", fields=missing)


def bootstrap_environment(path: Path, environ: Mapping[str, str] | None = None, *, require_credentials: bool = True) -> dict[str, str]:
    contract = load_bootstrap_manifest(path)
    validate_bootstrap_environment(
        contract,
        environ,
        require_credentials=require_credentials,
        require_bootstrap_flags=False,
        require_managed_paths=False,
        reject_ambient_provider_state=False,
    )
    result = dict(os.environ if environ is None else environ)
    for name in _ambient_provider_environment(result, contract.catalog_environment):
        result.pop(name, None)
    result.update(REQUIRED_ENVIRONMENT)
    result.update({
        "HOME": str(contract.home_dir),
        "USERPROFILE": str(contract.home_dir),
        "XDG_CONFIG_HOME": str(contract.xdg_config_home),
        "XDG_DATA_HOME": str(contract.xdg_data_home),
        "XDG_CACHE_HOME": str(contract.xdg_cache_home),
        "XDG_STATE_HOME": str(contract.xdg_state_home),
        "OPENCODE_CONFIG_DIR": str(contract.config_dir),
    })
    existing_path = result.get("PATH", os.defpath)
    path_entries = [str(contract.ripgrep_path.parent)] + [entry for entry in existing_path.split(os.pathsep) if entry and entry != str(contract.ripgrep_path.parent)]
    result["PATH"] = os.pathsep.join(path_entries)
    if contract.models_path is not None:
        result["OPENCODE_MODELS_PATH"] = contract.models_path
    else:
        result.pop("OPENCODE_MODELS_PATH", None)
    validate_bootstrap_environment(
        contract,
        result,
        require_credentials=require_credentials,
        require_bootstrap_flags=True,
        require_managed_paths=True,
        reject_ambient_provider_state=True,
    )
    return result


def bootstrap_readiness(root: Path, *, expected_identity: str | None = None, expected_models_identity: str | None = None, check_environment: bool = False) -> tuple[bool, str]:
    manifest = root.expanduser().resolve() / ".k-slide-config" / "opencode-bootstrap.json"
    try:
        contract = load_bootstrap_manifest(manifest)
        if expected_identity not in (None, "", "UNSET") and contract.identity != expected_identity:
            return False, "bootstrap identity disagrees with the candidate"
        if expected_models_identity not in (None, "", "UNSET"):
            models_identity = _sha256_bytes(_canonical(contract.models_identity))
            if models_identity != expected_models_identity:
                return False, "model catalog identity disagrees with the candidate"
        if check_environment:
            validate_bootstrap_environment(contract)
        return True, f"managed OpenCode {contract.opencode_version}; bootstrap={contract.identity}"
    except KSlideError as exc:
        return False, exc.message


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Launch OpenCode through the managed K-Slide production bootstrap.")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        parser.error("a managed OpenCode command is required after --")
    access_key = os.environ.get(COMPANY_ACCESS_KEY_ENV)
    try:
        environment = bootstrap_environment(args.manifest)
    except KSlideError as exc:
        print(f"{exc.code.value}: {exc.message}", file=sys.stderr)
        return 78
    # AccessKey remains available only to this trusted launcher long enough to
    # cross the private host/tool boundary; it is never inherited in the
    # OpenCode/model/provider environment.
    environment.pop(COMPANY_ACCESS_KEY_ENV, None)
    handoff: AccessKeyHandoff | None = None
    process: subprocess.Popen[bytes] | None = None
    try:
        handoff = AccessKeyHandoff(access_key)
        process = subprocess.Popen(command, env=environment, pass_fds=handoff.pass_fds, start_new_session=True)
        handoff.send()
        return process.wait()
    except AccessKeyBoundaryError as exc:
        if process is not None and process.poll() is None:
            _terminate_child(process)
        print(f"KSLIDE_OPENCODE_BOOTSTRAP_HANDOFF_FAILED: {exc}", file=sys.stderr)
        return 78
    except (OSError, ValueError):
        if process is not None and process.poll() is None:
            _terminate_child(process)
        print("KSLIDE_OPENCODE_BOOTSTRAP_EXEC_FAILED", file=sys.stderr)
        return 127
    finally:
        if handoff is not None:
            handoff.close()


def _terminate_child(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except OSError:
        try:
            process.terminate()
        except OSError:
            pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            try:
                process.kill()
            except OSError:
                pass
        process.wait()


if __name__ == "__main__":  # pragma: no cover - exercised through subprocess tests
    raise SystemExit(main())
