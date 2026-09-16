"""Canonical, source-free identity for the K-Slide production runtime.

The runtime artifact is intentionally separate from candidate and certification
state.  This module owns only facts that can be inspected from a built image:
the checked-out K-Slide subject, exact Python/system subjects, local OCR asset
identity, and the SBOM bound to those subjects.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import platform
import re
import shutil
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Iterable

from . import __version__
from .certification import (
    EvidenceValidationError,
    canonical_exact_version,
    dependency_inventory_hash,
    installed_dependency_inventory,
    load_dependency_inventory,
    load_dependency_lock,
    parse_libreoffice_version,
    sha256_file,
    validate_cyclonedx_1_5,
    validate_ocr_asset_manifest,
)


RUNTIME_ARTIFACT_SCHEMA_VERSION = "1.0"
RUNTIME_ARTIFACT_NAME = "k-slide-runtime"
SUPPORTED_PLATFORM = "linux/amd64"
BASE_IMAGE_NAME = "docker.io/library/python"
BASE_IMAGE_TAG = "3.11-slim"
BASE_IMAGE_DIGEST = "sha256:d1053354624536b044162aaab1e418bd000ea35184fb1ae098ab3166b1072e72"
BASE_IMAGE_REF = f"{BASE_IMAGE_NAME}:{BASE_IMAGE_TAG}@{BASE_IMAGE_DIGEST}"
_HEX64 = set("0123456789abcdef")
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_FORBIDDEN_METADATA_KEYS = frozenset(
    {
        "accesskey",
        "access_key",
        "api_key",
        "apikey",
        "authorization",
        "credential",
        "password",
        "secret",
        "source_text",
        "translation",
        "ocr_text",
        "prompt",
        "termbase",
        "local_path",
    }
)


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _require_sha(value: Any, label: str) -> str:
    text = str(value or "").lower()
    if len(text) != 64 or set(text) - _HEX64:
        raise EvidenceValidationError(f"{label} must be a SHA-256 hex digest")
    return text


def _require_revision(value: Any, label: str = "source_revision") -> str:
    text = str(value or "")
    if not _REVISION.fullmatch(text):
        raise EvidenceValidationError(f"{label} must be a 40-character lowercase Git SHA")
    return text


def _require_version(value: Any, label: str) -> str:
    try:
        return canonical_exact_version(value, label)
    except EvidenceValidationError:
        raise


def _canonical_system_packages(packages: Iterable[dict[str, Any]]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in packages:
        if not isinstance(item, dict):
            raise EvidenceValidationError("system package manifest contains a non-object package")
        name = str(item.get("name") or "").strip()
        version = str(item.get("version") or "").strip()
        if not name or not version or name in seen:
            raise EvidenceValidationError("system package manifest contains an invalid or duplicate package")
        seen.add(name)
        rows.append({"name": name, "version": version})
    if not rows:
        raise EvidenceValidationError("system package manifest is empty")
    return sorted(rows, key=lambda item: item["name"])


def load_system_package_manifest(path: Path, *, expected_platform: str = SUPPORTED_PLATFORM) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise EvidenceValidationError("system package manifest is missing or symlinked")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceValidationError("system package manifest is malformed") from exc
    if not isinstance(value, dict) or set(value) - {"schema_version", "platform", "snapshot", "packages"}:
        raise EvidenceValidationError("system package manifest has unknown fields")
    if value.get("schema_version") != RUNTIME_ARTIFACT_SCHEMA_VERSION or value.get("platform") != expected_platform:
        raise EvidenceValidationError("system package manifest schema or platform is invalid")
    snapshot = value.get("snapshot")
    timestamp = snapshot.get("timestamp") if isinstance(snapshot, dict) else None
    uri = snapshot.get("uri") if isinstance(snapshot, dict) else None
    if (
        not isinstance(snapshot, dict)
        or set(snapshot) - {"uri", "timestamp"}
        or not isinstance(uri, str)
        or not uri.startswith("https://snapshot.debian.org/")
        or not isinstance(timestamp, str)
        or not re.fullmatch(r"[0-9]{8}T[0-9]{6}Z", timestamp)
        or timestamp not in uri
    ):
        raise EvidenceValidationError("system package manifest must name an immutable Debian snapshot")
    packages = _canonical_system_packages(value.get("packages", []))
    if value.get("packages") != packages:
        raise EvidenceValidationError("system package manifest is not canonically ordered")
    return {"schema_version": value["schema_version"], "platform": value["platform"], "snapshot": dict(snapshot), "packages": packages}


def system_package_manifest_hash(value: dict[str, Any]) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def _metadata_version(name: str) -> str:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError as exc:
        raise EvidenceValidationError(f"required Python package is not installed: {name}") from exc


def _command_version(command: str) -> str | None:
    path = shutil.which(command)
    if not path:
        return None
    try:
        result = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return parse_libreoffice_version((result.stdout or "") + "\n" + (result.stderr or "")) if result.returncode == 0 else None


def installed_system_package_versions(names: Iterable[str]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for name in names:
        try:
            result = subprocess.run(["dpkg-query", "-W", "-f=${Version}", name], capture_output=True, text=True, timeout=10, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise EvidenceValidationError(f"cannot inspect system package: {name}") from exc
        version = result.stdout.strip()
        if result.returncode != 0 or not version:
            raise EvidenceValidationError(f"system package is not installed: {name}")
        rows.append({"name": name, "version": version})
    return _canonical_system_packages(rows)


def build_runtime_sbom(*, inventory: dict[str, Any], system_packages: list[dict[str, str]], kslide_version: str, source_revision: str, system_package_hash: str) -> dict[str, Any]:
    """Use the repository's CycloneDX shape with an explicit OS-package boundary."""

    dependency_hash = dependency_inventory_hash(inventory)
    properties = [
        {"name": "k-slide:dependency-set-sha256", "value": dependency_hash},
        {"name": "k-slide:system-package-set-sha256", "value": system_package_hash},
        {"name": "k-slide:source-revision", "value": source_revision},
        {"name": "k-slide:coverage", "value": "python-and-declared-system-packages"},
    ]
    components = [
        {"type": "library", "name": item["name"], "version": item["version"]}
        for item in inventory["packages"]
    ]
    components.extend(
        {"type": "operating-system", "name": item["name"], "version": item["version"]}
        for item in system_packages
    )
    value = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, f'k-slide-runtime:{dependency_hash}:{system_package_hash}:{source_revision}')}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": RUNTIME_ARTIFACT_NAME,
                "version": kslide_version,
                "properties": properties,
            }
        },
        "components": components,
    }
    validate_cyclonedx_1_5(value)
    return value


def _manifest_identity_payload(value: dict[str, Any]) -> dict[str, Any]:
    payload = dict(value)
    payload.pop("artifact_identity", None)
    payload.pop("image_identity", None)
    return payload


def _manifest_build_input_payload(value: dict[str, Any]) -> dict[str, Any]:
    payload = _manifest_identity_payload(value)
    payload.pop("build_inputs_sha256", None)
    return payload


def build_runtime_manifest(
    *,
    source_revision: str,
    source_tree_sha256: str,
    python_version: str,
    kslide_version: str,
    base_image_digest: str,
    system_manifest: dict[str, Any],
    system_packages: list[dict[str, str]],
    lock_sha256: str,
    inventory_sha256: str,
    package_count: int,
    paddle_version: str,
    paddleocr_version: str,
    ocr_identity: dict[str, Any],
    sbom_sha256: str,
    sbom_dependency_sha256: str,
) -> dict[str, Any]:
    source_revision = _require_revision(source_revision)
    source_tree_sha256 = _require_sha(source_tree_sha256, "source_tree_sha256")
    base_image_digest = _require_sha(base_image_digest.removeprefix("sha256:"), "base_image_digest")
    lock_sha256 = _require_sha(lock_sha256, "python_dependency_lock_sha256")
    inventory_sha256 = _require_sha(inventory_sha256, "python_dependency_inventory_sha256")
    sbom_sha256 = _require_sha(sbom_sha256, "sbom.sha256")
    sbom_dependency_sha256 = _require_sha(sbom_dependency_sha256, "sbom.dependency_set_sha256")
    if sbom_dependency_sha256 != inventory_sha256:
        raise EvidenceValidationError("runtime SBOM dependency subject does not match the runtime inventory")
    python_version = _require_version(python_version, "python_version")
    kslide_version = _require_version(kslide_version, "kslide_version")
    paddle_version = _require_version(paddle_version, "paddle_version")
    paddleocr_version = _require_version(paddleocr_version, "paddleocr_version")
    expected_system = system_manifest
    if system_packages != expected_system["packages"]:
        raise EvidenceValidationError("verified system package facts differ from the expected manifest")
    ocr_manifest_sha = _require_sha(ocr_identity.get("sha256"), "ocr_asset_manifest.sha256")
    ocr_config_sha = _require_sha(ocr_identity.get("paddlex_config_sha256"), "ocr_asset_manifest.paddlex_config_sha256")
    provenance = str(ocr_identity.get("asset_provenance") or "certifying-bundle")
    status = "CANDIDATE" if provenance == "certifying-bundle" else "DEVELOPMENT_ONLY"
    manifest: dict[str, Any] = {
        "schema_version": RUNTIME_ARTIFACT_SCHEMA_VERSION,
        "artifact_name": RUNTIME_ARTIFACT_NAME,
        "artifact_status": status,
        "kslide_version": kslide_version,
        "source_revision": source_revision,
        "source_tree_sha256": source_tree_sha256,
        "supported_platform": SUPPORTED_PLATFORM,
        "base_image": {"name": BASE_IMAGE_NAME, "tag": BASE_IMAGE_TAG, "digest": f"sha256:{base_image_digest}", "ref": f"{BASE_IMAGE_NAME}:{BASE_IMAGE_TAG}@sha256:{base_image_digest}"},
        "python_version": python_version,
        "libreoffice_version": _require_version(ocr_identity.get("libreoffice_version"), "libreoffice_version"),
        "system_packages": system_packages,
        "font_packages": [item for item in system_packages if item["name"].startswith("fonts-")],
        "python_dependency_inventory_sha256": inventory_sha256,
        "python_dependency_lock_sha256": lock_sha256,
        "dependency_package_count": package_count,
        "paddle_version": paddle_version,
        "paddleocr_version": paddleocr_version,
        "ocr_asset_manifest": {
            "sha256": ocr_manifest_sha,
            "file_count": int(ocr_identity["file_count"]),
            "paddlex_config": str(ocr_identity["paddlex_config"]),
            "paddlex_config_sha256": ocr_config_sha,
            "asset_provenance": provenance,
        },
        "sbom": {
            "format": "CycloneDX",
            "spec_version": "1.5",
            "sha256": sbom_sha256,
            "dependency_set_sha256": sbom_dependency_sha256,
            "system_package_set_sha256": system_package_manifest_hash(expected_system),
        },
        "product_runtime": {
            "entrypoint": ["k-slide"],
            "default_command": ["doctor", "--json"],
            "heavy_doctor_command": ["python", "-m", "evals.heavy.doctor"],
            "networkless_local_prerequisite": True,
            "run_as_non_root": True,
        },
    }
    manifest["build_inputs_sha256"] = sha256_bytes(canonical_json_bytes(_manifest_build_input_payload(manifest)))
    manifest["artifact_identity"] = {"kind": "canonical-build-inputs", "sha256": sha256_bytes(canonical_json_bytes(_manifest_identity_payload(manifest)))}
    return manifest


_MANIFEST_FIELDS = frozenset(
    {
        "schema_version", "artifact_name", "artifact_status", "kslide_version", "source_revision", "source_tree_sha256",
        "supported_platform", "base_image", "python_version", "libreoffice_version", "system_packages", "font_packages",
        "python_dependency_inventory_sha256", "python_dependency_lock_sha256", "dependency_package_count", "paddle_version",
        "paddleocr_version", "ocr_asset_manifest", "sbom", "product_runtime", "build_inputs_sha256", "artifact_identity",
        "image_identity",
    }
)


def _reject_metadata_content(value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).lower().replace("-", "_")
            if normalized in _FORBIDDEN_METADATA_KEYS:
                raise EvidenceValidationError(f"runtime metadata contains forbidden field: {key}")
            _reject_metadata_content(item)
    elif isinstance(value, list):
        for item in value:
            _reject_metadata_content(item)


def validate_runtime_manifest(
    value: dict[str, Any],
    *,
    expected_source_revision: str | None = None,
    expected_inventory_sha256: str | None = None,
    expected_lock_sha256: str | None = None,
    expected_ocr_manifest_sha256: str | None = None,
    expected_sbom_sha256: str | None = None,
    expected_system_manifest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    required_fields = _MANIFEST_FIELDS - {"image_identity"}
    if not isinstance(value, dict) or set(value) - _MANIFEST_FIELDS or not required_fields.issubset(value):
        raise EvidenceValidationError("runtime manifest has unknown fields")
    _reject_metadata_content(value)
    if value.get("schema_version") != RUNTIME_ARTIFACT_SCHEMA_VERSION or value.get("artifact_name") != RUNTIME_ARTIFACT_NAME:
        raise EvidenceValidationError("runtime manifest schema or artifact name is invalid")
    if value.get("artifact_status") not in {"CANDIDATE", "DEVELOPMENT_ONLY"}:
        raise EvidenceValidationError("runtime manifest artifact status is invalid")
    source_revision = _require_revision(value.get("source_revision"))
    if expected_source_revision is not None and source_revision != _require_revision(expected_source_revision, "expected_source_revision"):
        raise EvidenceValidationError("runtime manifest source subject does not match the checked-out source")
    _require_sha(value.get("source_tree_sha256"), "source_tree_sha256")
    if value.get("supported_platform") != SUPPORTED_PLATFORM:
        raise EvidenceValidationError("runtime manifest platform is unsupported")
    base = value.get("base_image")
    if not isinstance(base, dict) or set(base) != {"name", "tag", "digest", "ref"} or base.get("name") != BASE_IMAGE_NAME or base.get("tag") != BASE_IMAGE_TAG:
        raise EvidenceValidationError("runtime manifest base image identity is invalid")
    base_digest = _require_sha(str(base.get("digest")).removeprefix("sha256:"), "base_image.digest")
    if f"sha256:{base_digest}" != BASE_IMAGE_DIGEST:
        raise EvidenceValidationError("runtime manifest base image digest is not the supported immutable subject")
    if base.get("ref") != f"{BASE_IMAGE_NAME}:{BASE_IMAGE_TAG}@sha256:{base_digest}":
        raise EvidenceValidationError("runtime manifest base image ref is not digest-qualified")
    for field in ("kslide_version", "python_version", "libreoffice_version", "paddle_version", "paddleocr_version"):
        _require_version(value.get(field), field)
    packages = _canonical_system_packages(value.get("system_packages", []))
    if value.get("system_packages") != packages or value.get("font_packages") != [item for item in packages if item["name"].startswith("fonts-")]:
        raise EvidenceValidationError("runtime manifest system/font package facts are not canonical")
    if expected_system_manifest is not None:
        if packages != expected_system_manifest["packages"]:
            raise EvidenceValidationError("runtime manifest system packages do not match the expected pinned manifest")
        if value["sbom"].get("system_package_set_sha256") != system_package_manifest_hash(expected_system_manifest):
            raise EvidenceValidationError("runtime manifest system package identity does not match the expected manifest")
    inventory_hash = _require_sha(value.get("python_dependency_inventory_sha256"), "python_dependency_inventory_sha256")
    lock_hash = _require_sha(value.get("python_dependency_lock_sha256"), "python_dependency_lock_sha256")
    if expected_inventory_sha256 is not None and inventory_hash != _require_sha(expected_inventory_sha256, "expected_inventory_sha256"):
        raise EvidenceValidationError("runtime manifest dependency inventory does not match the expected subject")
    if expected_lock_sha256 is not None and lock_hash != _require_sha(expected_lock_sha256, "expected_lock_sha256"):
        raise EvidenceValidationError("runtime manifest dependency lock does not match the expected subject")
    if isinstance(value.get("dependency_package_count"), bool) or not isinstance(value.get("dependency_package_count"), int) or value["dependency_package_count"] <= 0:
        raise EvidenceValidationError("runtime manifest dependency package count is invalid")
    ocr = value.get("ocr_asset_manifest")
    if not isinstance(ocr, dict) or set(ocr) != {"sha256", "file_count", "paddlex_config", "paddlex_config_sha256", "asset_provenance"}:
        raise EvidenceValidationError("runtime manifest OCR identity is invalid")
    ocr_hash = _require_sha(ocr.get("sha256"), "ocr_asset_manifest.sha256")
    _require_sha(ocr.get("paddlex_config_sha256"), "ocr_asset_manifest.paddlex_config_sha256")
    if ocr.get("paddlex_config") != "PaddleOCR.yaml" or ocr.get("asset_provenance") not in {"certifying-bundle", "development-prefetch"}:
        raise EvidenceValidationError("runtime manifest OCR configuration identity is invalid")
    if isinstance(ocr.get("file_count"), bool) or not isinstance(ocr.get("file_count"), int) or ocr["file_count"] <= 0:
        raise EvidenceValidationError("runtime manifest OCR file count is invalid")
    if expected_ocr_manifest_sha256 is not None and ocr_hash != _require_sha(expected_ocr_manifest_sha256, "expected_ocr_manifest_sha256"):
        raise EvidenceValidationError("runtime manifest OCR asset identity does not match the expected manifest")
    sbom = value.get("sbom")
    if not isinstance(sbom, dict) or set(sbom) != {"format", "spec_version", "sha256", "dependency_set_sha256", "system_package_set_sha256"} or sbom.get("format") != "CycloneDX" or sbom.get("spec_version") != "1.5":
        raise EvidenceValidationError("runtime manifest SBOM identity is invalid")
    sbom_hash = _require_sha(sbom.get("sha256"), "sbom.sha256")
    if sbom.get("dependency_set_sha256") != inventory_hash:
        raise EvidenceValidationError("runtime manifest SBOM dependency identity does not match the inventory")
    _require_sha(sbom.get("system_package_set_sha256"), "sbom.system_package_set_sha256")
    if expected_sbom_sha256 is not None and sbom_hash != _require_sha(expected_sbom_sha256, "expected_sbom_sha256"):
        raise EvidenceValidationError("runtime manifest SBOM identity does not match the inspected SBOM")
    product_runtime = value.get("product_runtime")
    if not isinstance(product_runtime, dict) or set(product_runtime) != {"entrypoint", "default_command", "heavy_doctor_command", "networkless_local_prerequisite", "run_as_non_root"}:
        raise EvidenceValidationError("runtime manifest product runtime contract is invalid")
    if product_runtime.get("entrypoint") != ["k-slide"] or product_runtime.get("heavy_doctor_command") != ["python", "-m", "evals.heavy.doctor"] or product_runtime.get("default_command") != ["doctor", "--json"] or product_runtime.get("networkless_local_prerequisite") is not True or product_runtime.get("run_as_non_root") is not True:
        raise EvidenceValidationError("runtime manifest product runtime contract is not canonical")
    artifact = value.get("artifact_identity")
    if not isinstance(artifact, dict) or set(artifact) != {"kind", "sha256"} or artifact.get("kind") != "canonical-build-inputs":
        raise EvidenceValidationError("runtime manifest artifact identity is invalid")
    artifact_hash = _require_sha(artifact.get("sha256"), "artifact_identity.sha256")
    if value.get("build_inputs_sha256") != sha256_bytes(canonical_json_bytes(_manifest_build_input_payload(value))) or sha256_bytes(canonical_json_bytes(_manifest_identity_payload(value))) != artifact_hash:
        raise EvidenceValidationError("runtime manifest artifact identity cannot be rederived")
    if "image_identity" in value:
        image = value["image_identity"]
        if not isinstance(image, dict) or set(image) != {"kind", "value"} or image.get("kind") not in {"local-image-id", "registry-digest"} or not isinstance(image.get("value"), str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image["value"]):
            raise EvidenceValidationError("runtime manifest image identity is invalid")
    return value


def source_tree_sha256(root: Path, *, paths: Iterable[str] | None = None) -> str:
    """Hash source/build files by relative name and bytes, without .git data."""

    root = root.expanduser().resolve()
    selected = [root / item for item in paths] if paths is not None else [path for path in root.rglob("*") if path.is_file()]
    digest = hashlib.sha256()
    for path in sorted(selected, key=lambda item: item.relative_to(root).as_posix()):
        if path.is_symlink() or ".git" in path.relative_to(root).parts:
            continue
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode("utf-8") + b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _runtime_paths(root: Path) -> tuple[Path, Path, Path, Path, Path]:
    return (root / "runtime-manifest.json", root / "runtime-sbom.json", root / "inputs" / "production.lock", root / "inputs" / "production-inventory.json", root / "system-packages.json")


def emit_runtime_artifact(*, output_root: Path, lock_path: Path, inventory_path: Path, system_manifest_path: Path, ocr_root: Path, source_revision: str, source_tree_sha256_value: str) -> dict[str, Any]:
    output_root = output_root.expanduser().resolve()
    inventory = load_dependency_inventory(inventory_path.expanduser().resolve())
    lock_inventory = load_dependency_lock(lock_path.expanduser().resolve())
    if lock_inventory != inventory:
        raise EvidenceValidationError("runtime lock does not equal the runtime dependency inventory")
    installed = installed_dependency_inventory()
    if installed != inventory:
        raise EvidenceValidationError("installed Python environment does not equal the runtime dependency inventory")
    system_manifest = load_system_package_manifest(system_manifest_path.expanduser().resolve())
    system_packages = installed_system_package_versions(item["name"] for item in system_manifest["packages"])
    if system_packages != system_manifest["packages"]:
        raise EvidenceValidationError("installed system package versions drifted from the pinned manifest")
    libreoffice_version = _command_version("libreoffice") or _command_version("soffice")
    if libreoffice_version is None:
        raise EvidenceValidationError("verified LibreOffice is unavailable")
    ocr_manifest = ocr_root.expanduser().resolve() / "manifest.json"
    ocr_identity = validate_ocr_asset_manifest(ocr_manifest, asset_root=ocr_root.expanduser().resolve())
    raw_ocr = json.loads(ocr_manifest.read_text(encoding="utf-8"))
    ocr_identity["asset_provenance"] = str(raw_ocr.get("asset_provenance") or "certifying-bundle")
    ocr_identity["libreoffice_version"] = libreoffice_version
    paddle_version = _metadata_version("paddlepaddle")
    paddleocr_version = _metadata_version("paddleocr")
    sbom = build_runtime_sbom(inventory=inventory, system_packages=system_packages, kslide_version=__version__, source_revision=source_revision, system_package_hash=system_package_manifest_hash(system_manifest))
    output_root.mkdir(parents=True, exist_ok=True)
    sbom_path = output_root / "runtime-sbom.json"
    sbom_path.write_bytes(canonical_json_bytes(sbom))
    manifest = build_runtime_manifest(
        source_revision=source_revision,
        source_tree_sha256=source_tree_sha256_value,
        python_version=platform.python_version(),
        kslide_version=__version__,
        base_image_digest=BASE_IMAGE_DIGEST,
        system_manifest=system_manifest,
        system_packages=system_packages,
        lock_sha256=sha256_file(lock_path),
        inventory_sha256=dependency_inventory_hash(inventory),
        package_count=len(inventory["packages"]),
        paddle_version=paddle_version,
        paddleocr_version=paddleocr_version,
        ocr_identity=ocr_identity,
        sbom_sha256=sha256_file(sbom_path),
        sbom_dependency_sha256=dependency_inventory_hash(inventory),
    )
    validate_runtime_manifest(manifest, expected_source_revision=source_revision, expected_inventory_sha256=dependency_inventory_hash(inventory), expected_lock_sha256=sha256_file(lock_path), expected_ocr_manifest_sha256=ocr_identity["sha256"], expected_sbom_sha256=sha256_file(sbom_path), expected_system_manifest=system_manifest)
    (output_root / "runtime-manifest.json").write_bytes(canonical_json_bytes(manifest))
    return manifest


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceValidationError(f"JSON artifact is unreadable: {path.name}") from exc
    if not isinstance(value, dict):
        raise EvidenceValidationError(f"JSON artifact is not an object: {path.name}")
    return value


def verify_runtime_artifact(*, runtime_root: Path, expected_source_revision: str | None = None) -> dict[str, Any]:
    manifest_path, sbom_path, lock_path, inventory_path, system_path = _runtime_paths(runtime_root.expanduser().resolve())
    manifest = _load_json(manifest_path)
    sbom = _load_json(sbom_path)
    validate_cyclonedx_1_5(sbom)
    inventory = load_dependency_inventory(inventory_path)
    lock_inventory = load_dependency_lock(lock_path)
    expected_inventory_hash = dependency_inventory_hash(inventory)
    if lock_inventory != inventory or installed_dependency_inventory() != inventory:
        raise EvidenceValidationError("runtime dependency subject is not exact")
    system_manifest = load_system_package_manifest(system_path)
    identity = validate_ocr_asset_manifest(runtime_root.expanduser().resolve().parent / "ocr" / "manifest.json", asset_root=runtime_root.expanduser().resolve().parent / "ocr")
    validate_runtime_manifest(manifest, expected_source_revision=expected_source_revision, expected_inventory_sha256=expected_inventory_hash, expected_lock_sha256=sha256_file(lock_path), expected_ocr_manifest_sha256=identity["sha256"], expected_sbom_sha256=sha256_file(sbom_path), expected_system_manifest=system_manifest)
    if sbom.get("metadata", {}).get("component", {}).get("properties", [{}])[0].get("value") != expected_inventory_hash:
        raise EvidenceValidationError("runtime SBOM is not bound to the runtime inventory")
    return {"status": "PASS", "artifact_identity": manifest["artifact_identity"], "sbom_sha256": sha256_file(sbom_path), "runtime_manifest_sha256": sha256_file(manifest_path)}


def verify_dependency_subject(*, lock_path: Path, inventory_path: Path) -> dict[str, Any]:
    inventory = load_dependency_inventory(inventory_path.expanduser().resolve())
    lock_inventory = load_dependency_lock(lock_path.expanduser().resolve())
    actual = installed_dependency_inventory()
    if lock_inventory != inventory:
        raise EvidenceValidationError("runtime lock does not equal the runtime dependency inventory")
    if actual != inventory:
        raise EvidenceValidationError("installed Python environment does not equal the runtime dependency inventory")
    return {"status": "PASS", "dependency_set_sha256": dependency_inventory_hash(inventory), "package_count": len(inventory["packages"])}


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect or emit the canonical K-Slide runtime artifact identity")
    sub = parser.add_subparsers(dest="command", required=True)
    emit = sub.add_parser("emit")
    emit.add_argument("--output-root", type=Path, required=True)
    emit.add_argument("--lock", type=Path, required=True)
    emit.add_argument("--inventory", type=Path, required=True)
    emit.add_argument("--system-manifest", type=Path, required=True)
    emit.add_argument("--ocr-root", type=Path, required=True)
    emit.add_argument("--source-revision", required=True)
    emit.add_argument("--source-tree-sha256", required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("--runtime-root", type=Path, required=True)
    verify.add_argument("--source-revision")
    dependencies = sub.add_parser("verify-dependencies")
    dependencies.add_argument("--lock", type=Path, required=True)
    dependencies.add_argument("--inventory", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "emit":
            value = emit_runtime_artifact(output_root=args.output_root, lock_path=args.lock, inventory_path=args.inventory, system_manifest_path=args.system_manifest, ocr_root=args.ocr_root, source_revision=args.source_revision, source_tree_sha256_value=args.source_tree_sha256)
        elif args.command == "verify":
            value = verify_runtime_artifact(runtime_root=args.runtime_root, expected_source_revision=args.source_revision)
        else:
            value = verify_dependency_subject(lock_path=args.lock, inventory_path=args.inventory)
    except (EvidenceValidationError, OSError, UnicodeError, ValueError) as exc:
        print(json.dumps({"status": "FAIL", "reason": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(value, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
