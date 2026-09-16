"""Build and independently verify the canonical K-Slide runtime image.

This is the single CI/PaaS build surface.  It creates a source-only Docker
context, accepts an exact dependency subject and an explicit OCR overlay, and
emits inspectable runtime/SBOM identities without pushing to a registry.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from k_slide.certification import EvidenceValidationError, dependency_inventory_hash, load_dependency_inventory, load_dependency_lock, sha256_file
from k_slide.runtime_artifact import (
    BASE_IMAGE_DIGEST,
    RUNTIME_ARTIFACT_NAME,
    SUPPORTED_PLATFORM,
    canonical_json_bytes,
    load_system_package_manifest,
    source_tree_sha256,
    validate_runtime_manifest,
)


_SECRET_PATTERNS = (
    re.compile(r"(?i)aws_access_key_id|aws_secret_access_key|openai_api_key|github_token|private_certification_token"),
    re.compile(r"(?i)(?:access[_-]?key|api[_-]?key|password|secret|credential|authorization)\s*[:=]"),
)
_EXCLUDED_CONTEXT_ROOTS = frozenset({".git", ".k-slide-config", ".k-slide-runs", ".k-slide-engine", "ocr"})


def _run(command: list[str], *, cwd: Path | None = None, capture: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=str(cwd) if cwd else None, text=True, capture_output=capture, check=True)


def _git_output(root: Path, *args: str) -> str:
    return _run(["git", *args], cwd=root, capture=True).stdout.strip()


def _source_files(root: Path) -> list[Path]:
    raw = _run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=root, capture=True).stdout
    relative_paths = [Path(item) for item in raw.split("\0") if item]
    selected: list[Path] = []
    for relative in relative_paths:
        if not relative.parts or relative.parts[0] in _EXCLUDED_CONTEXT_ROOTS:
            continue
        path = root / relative
        if path.is_symlink():
            raise EvidenceValidationError(f"runtime build context contains a symlink: {relative}")
        if path.is_file():
            selected.append(relative)
    return sorted(selected, key=lambda path: path.as_posix())


def _copy_source_context(root: Path, context: Path, files: list[Path]) -> None:
    for relative in files:
        target = context / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(root / relative, target)
    for directory in (context / "deploy/runtime/ocr-context", context / "evals/heavy"):
        directory.mkdir(parents=True, exist_ok=True)


def _copy_overlay(source: Path, target: Path) -> None:
    source = source.expanduser().resolve()
    if source.is_symlink() or not source.is_dir():
        raise EvidenceValidationError(f"runtime OCR overlay is missing or symlinked: {source}")
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        if path.is_symlink():
            raise EvidenceValidationError(f"runtime OCR overlay contains a symlink: {relative}")
        if path.is_file():
            if re.search(r"(?i)(access[_-]?key|api[_-]?key|password|secret|credential|token|archive|bundle)", relative.name):
                raise EvidenceValidationError(f"runtime OCR overlay has a prohibited secret/transport filename: {relative}")
            if path.suffix.lower() in {".json", ".yaml", ".yml", ".txt", ".cfg", ".ini"}:
                try:
                    text = path.read_text(encoding="utf-8")
                except UnicodeDecodeError as exc:
                    raise EvidenceValidationError(f"runtime OCR overlay text input is not UTF-8: {relative}") from exc
                for pattern in _SECRET_PATTERNS:
                    if pattern.search(text):
                        raise EvidenceValidationError(f"runtime OCR overlay text contains a prohibited secret field: {relative}")
            destination = target / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, destination)


def _image_inspect(image: str) -> dict[str, Any]:
    result = _run(["docker", "image", "inspect", image], capture=True)
    value = json.loads(result.stdout)
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise EvidenceValidationError("Docker image inspect did not return one image")
    return value[0]


def _container_file(image: str, path: str) -> bytes:
    result = subprocess.run(["docker", "run", "--rm", "--network", "none", "--entrypoint", "cat", image, path], capture_output=True, check=True)
    return result.stdout


def _verify_inside_image(image: str, source_revision: str) -> None:
    subprocess.run(
        [
            "docker", "run", "--rm", "--network", "none", "--entrypoint", "python", image,
            "-m", "k_slide.runtime_artifact", "verify",
            "--runtime-root", "/opt/k-slide/runtime", "--source-revision", source_revision,
        ],
        check=True,
    )


def _verify_image(*, root: Path, image: str, output: Path, source_revision: str, source_tree_hash: str | None, inventory_path: Path, lock_path: Path, system_manifest_path: Path) -> dict[str, Any]:
    inspect = _image_inspect(image)
    if inspect.get("Os") != "linux" or inspect.get("Architecture") != "amd64":
        raise EvidenceValidationError("built runtime image is not the supported linux/amd64 subject")
    image_id = str(inspect.get("Id") or "")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise EvidenceValidationError("Docker did not expose a content-addressed local image ID")
    repo_digests = inspect.get("RepoDigests") or []
    if repo_digests and any("@sha256:" not in str(item) for item in repo_digests):
        raise EvidenceValidationError("Docker returned a malformed repository digest")
    image_identity = {"kind": "registry-digest", "value": str(repo_digests[0].rsplit("@", 1)[1])} if repo_digests else {"kind": "local-image-id", "value": image_id}
    _verify_inside_image(image, source_revision)
    manifest_bytes = _container_file(image, "/opt/k-slide/runtime/runtime-manifest.json")
    sbom_bytes = _container_file(image, "/opt/k-slide/runtime/runtime-sbom.json")
    manifest = json.loads(manifest_bytes.decode("utf-8"))
    sbom = json.loads(sbom_bytes.decode("utf-8"))
    expected_inventory = load_dependency_inventory(inventory_path)
    expected_inventory_hash = dependency_inventory_hash(expected_inventory)
    expected_system_manifest = load_system_package_manifest(system_manifest_path)
    validate_runtime_manifest(
        manifest,
        expected_source_revision=source_revision,
        expected_inventory_sha256=expected_inventory_hash,
        expected_lock_sha256=sha256_file(lock_path),
        expected_ocr_manifest_sha256=str(manifest.get("ocr_asset_manifest", {}).get("sha256")),
        expected_sbom_sha256=sha256_file_from_bytes(sbom_bytes),
        expected_system_manifest=expected_system_manifest,
    )
    if source_tree_hash is not None and manifest.get("source_tree_sha256") != source_tree_hash:
        raise EvidenceValidationError("runtime manifest source tree identity does not match the build context")
    if sha256_file_from_bytes(sbom_bytes) != manifest["sbom"]["sha256"]:
        raise EvidenceValidationError("runtime SBOM bytes do not match the runtime manifest")
    if load_dependency_lock(lock_path) != expected_inventory:
        raise EvidenceValidationError("runtime lock and inventory inputs differ")
    _verify_metadata_is_secret_free(inspect, image)
    external_manifest = dict(manifest)
    external_manifest["image_identity"] = image_identity
    output.mkdir(parents=True, exist_ok=True)
    validate_runtime_manifest(
        external_manifest,
        expected_source_revision=source_revision,
        expected_inventory_sha256=expected_inventory_hash,
        expected_lock_sha256=sha256_file(lock_path),
        expected_ocr_manifest_sha256=str(manifest["ocr_asset_manifest"]["sha256"]),
        expected_sbom_sha256=sha256_file_from_bytes(sbom_bytes),
        expected_system_manifest=expected_system_manifest,
    )
    (output / "runtime-manifest.json").write_bytes(canonical_json_bytes(external_manifest))
    (output / "runtime-sbom.json").write_bytes(sbom_bytes)
    identity = {
        "schema_version": "1.0",
        "artifact_name": RUNTIME_ARTIFACT_NAME,
        "artifact_identity": manifest["artifact_identity"],
        "image_identity": image_identity,
        "runtime_manifest_sha256": sha256_file(output / "runtime-manifest.json"),
        "sbom_sha256": sha256_file(output / "runtime-sbom.json"),
        "source_revision": source_revision,
        "supported_platform": SUPPORTED_PLATFORM,
        "base_image_digest": BASE_IMAGE_DIGEST,
    }
    (output / "artifact-identity.json").write_bytes(canonical_json_bytes(identity))
    return identity


def sha256_file_from_bytes(value: bytes) -> str:
    import hashlib

    return hashlib.sha256(value).hexdigest()


def _verify_metadata_is_secret_free(inspect: dict[str, Any], image: str) -> None:
    config = inspect.get("Config") if isinstance(inspect.get("Config"), dict) else {}
    history = _run(["docker", "history", "--no-trunc", "--format", "{{.CreatedBy}}", image], capture=True).stdout
    metadata = json.dumps({"config": config, "history": history}, ensure_ascii=False)
    for pattern in _SECRET_PATTERNS:
        if pattern.search(metadata):
            raise EvidenceValidationError("runtime image config/history contains a prohibited secret field")
    for key in config:
        if str(key).lower() in {"source_text", "translation", "ocr_text", "prompt"}:
            raise EvidenceValidationError(f"runtime image config contains prohibited metadata field: {key}")


def build(args: argparse.Namespace) -> dict[str, Any]:
    root = args.root.expanduser().resolve()
    source_revision = args.source_revision or _git_output(root, "rev-parse", "HEAD")
    if not re.fullmatch(r"[0-9a-f]{40}", source_revision):
        raise EvidenceValidationError("checked-out source revision is not a full Git SHA")
    files = _source_files(root)
    source_hash = source_tree_sha256(root, paths=[item.as_posix() for item in files])
    lock_path = args.lock.expanduser().resolve()
    inventory_path = args.inventory.expanduser().resolve()
    system_manifest_path = (root / "deploy/runtime/system-packages-linux-amd64.json").resolve()
    load_dependency_inventory(inventory_path)
    if load_dependency_lock(lock_path) != load_dependency_inventory(inventory_path):
        raise EvidenceValidationError("provided runtime lock and inventory differ")
    if not system_manifest_path.is_file():
        raise EvidenceValidationError("canonical system package manifest is missing")
    with tempfile.TemporaryDirectory(prefix="k-slide-runtime-build-") as temporary:
        context = Path(temporary)
        _copy_source_context(root, context, files)
        runtime_inputs = context / ".runtime-inputs"
        runtime_inputs.mkdir()
        shutil.copy2(lock_path, runtime_inputs / "production.lock")
        shutil.copy2(inventory_path, runtime_inputs / "production-inventory.json")
        ocr_target = context / "deploy/runtime/ocr-context"
        if args.ocr_root:
            _copy_overlay(args.ocr_root, ocr_target)
        command = [
            "docker", "build", "--platform", SUPPORTED_PLATFORM, "--file", "deploy/runtime/Dockerfile",
            "--tag", args.image,
            "--build-arg", "PRODUCTION_LOCK=.runtime-inputs/production.lock",
            "--build-arg", "PRODUCTION_INVENTORY=.runtime-inputs/production-inventory.json",
            "--build-arg", f"OCR_ASSET_MODE={'development' if args.allow_development_ocr_prefetch else 'certifying'}",
            "--build-arg", f"ALLOW_DEVELOPMENT_OCR_PREFETCH={'1' if args.allow_development_ocr_prefetch else '0'}",
            "--build-arg", f"KSLIDE_SOURCE_REVISION={source_revision}",
            "--build-arg", f"KSLIDE_SOURCE_TREE_SHA256={source_hash}",
        ]
        if args.no_cache:
            command.append("--no-cache")
        command.append(str(context))
        _run(command)
    return _verify_image(root=root, image=args.image, output=args.output.expanduser().resolve(), source_revision=source_revision, source_tree_hash=source_hash, inventory_path=inventory_path, lock_path=lock_path, system_manifest_path=system_manifest_path)


def verify(args: argparse.Namespace) -> dict[str, Any]:
    root = args.root.expanduser().resolve()
    source_revision = args.source_revision or _git_output(root, "rev-parse", "HEAD")
    lock_path = args.lock.expanduser().resolve()
    inventory_path = args.inventory.expanduser().resolve()
    system_manifest_path = (root / "deploy/runtime/system-packages-linux-amd64.json").resolve()
    return _verify_image(root=root, image=args.image, output=args.output.expanduser().resolve(), source_revision=source_revision, source_tree_hash=args.source_tree_sha256, inventory_path=inventory_path, lock_path=lock_path, system_manifest_path=system_manifest_path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build and verify the canonical K-Slide runtime artifact")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("build", "verify"):
        command = sub.add_parser(name)
        command.add_argument("--root", type=Path, default=ROOT)
        command.add_argument("--image", default="k-slide-runtime:local")
        command.add_argument("--output", type=Path, required=True)
        command.add_argument("--lock", type=Path, default=ROOT / "deploy/runtime/production-requirements.lock")
        command.add_argument("--inventory", type=Path, default=ROOT / "deploy/runtime/production-dependency-inventory.json")
        command.add_argument("--source-revision")
        command.add_argument("--source-tree-sha256")
    build_parser = sub.choices["build"]
    build_parser.add_argument("--ocr-root", type=Path)
    build_parser.add_argument("--allow-development-ocr-prefetch", action="store_true")
    build_parser.add_argument("--no-cache", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            value = build(args)
        else:
            value = verify(args)
    except (EvidenceValidationError, OSError, UnicodeError, ValueError, subprocess.CalledProcessError) as exc:
        print(json.dumps({"status": "BLOCKED", "reason": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps({"status": "PASS", **value}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
