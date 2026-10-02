"""Collision-safe project/global installation."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

from . import __version__
from .errors import ErrorCode, KSlideError
from .io import atomic_write_bytes, atomic_write_json


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _files(source: Path) -> list[Path]:
    if source.is_file():
        return [source]
    return sorted(path for path in source.rglob("*") if path.is_file()
                  and not any(part == "__pycache__" or part.endswith((".egg-info", ".dist-info")) for part in path.parts)
                  and path.suffix != ".pyc")


def _load_manifest(path: Path) -> dict[str, Any]:
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise KSlideError(ErrorCode.INSTALL_INVALID, "K-Slide install manifest must be a regular file.")
    if not path.is_file():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise KSlideError(ErrorCode.INSTALL_INVALID, "Existing K-Slide install manifest is unreadable.", {"path": str(path)}) from exc
    if not isinstance(value, dict) or not isinstance(value.get("files"), dict):
        raise KSlideError(ErrorCode.INSTALL_INVALID, "Existing K-Slide install manifest has an invalid shape.")
    for name, digest in value["files"].items():
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts or not relative.parts or not isinstance(digest, str) or len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise KSlideError(ErrorCode.INSTALL_INVALID, "Existing K-Slide install manifest contains an invalid file entry.")
    return value


def _source_git_sha(source_root: Path) -> str:
    try:
        result = subprocess.run(["git", "-C", str(source_root), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return "UNSET"
    return result.stdout.strip() if result.returncode == 0 else "UNSET"


def _copy_owned(source: Path, destination: Path, *, target_root: Path, previous: dict[str, str]) -> dict[str, str]:
    installed: dict[str, str] = {}
    for source_file in _files(source):
        relative = source_file.relative_to(source.parent if source.is_file() else source)
        if source.is_file():
            relative = Path(source.name)
        destination_file = destination / relative
        destination_file.parent.mkdir(parents=True, exist_ok=True)
        destination_key = str(destination_file.relative_to(target_root))
        source_hash = _sha(source_file)
        if destination_file.exists():
            existing_hash = _sha(destination_file)
            if existing_hash != source_hash and destination_key not in previous:
                raise KSlideError(
                    ErrorCode.INSTALL_COLLISION,
                    "K-Slide refused to overwrite an unrelated existing file.",
                    {"path": destination_key, "guidance": "Back up or remove the conflicting K-Slide-owned file, then retry."},
                )
            if existing_hash != source_hash and destination_key in previous and existing_hash != previous[destination_key]:
                raise KSlideError(
                    ErrorCode.INSTALL_LOCAL_MODIFICATION,
                    "K-Slide refused to overwrite a locally modified owned file.",
                    {"path": destination_key, "guidance": "Restore the installed version or review the change before upgrading."},
                )
            if existing_hash == source_hash:
                installed[destination_key] = source_hash
                continue
        atomic_write_bytes(destination_file, source_file.read_bytes(), mode=source_file.stat().st_mode & 0o777)
        installed[destination_key] = source_hash
    return installed


def _preflight_owned(source: Path, destination: Path, *, target_root: Path, previous: dict[str, str]) -> None:
    """Reject every collision and symlink before changing installed assets."""

    for source_file in _files(source):
        relative = source_file.relative_to(source.parent if source.is_file() else source)
        if source.is_file():
            relative = Path(source.name)
        destination_file = destination / relative
        current = target_root
        for component in destination_file.relative_to(target_root).parts[:-1]:
            current = current / component
            if current.is_symlink():
                raise KSlideError(
                    ErrorCode.INSTALL_COLLISION,
                    "K-Slide refused to install through a symbolic-link path.",
                    {"path": str(current.relative_to(target_root)), "guidance": "Review the symbolic link and retry with a normal project folder."},
                )
            if current.exists() and not current.is_dir():
                raise KSlideError(
                    ErrorCode.INSTALL_COLLISION,
                    "K-Slide refused to install through a non-directory path.",
                    {"path": str(current.relative_to(target_root)), "guidance": "Review the conflicting path and retry with a normal project folder."},
                )
        if not destination_file.exists() and not destination_file.is_symlink():
            continue
        key = str(destination_file.relative_to(target_root))
        if destination_file.is_symlink() or not destination_file.is_file():
            raise KSlideError(
                ErrorCode.INSTALL_COLLISION,
                "K-Slide refused to replace a non-file path.",
                {"path": key, "guidance": "Review and remove the conflicting installation path, then retry."},
            )
        existing_hash = _sha(destination_file)
        source_hash = _sha(source_file)
        if existing_hash == source_hash:
            continue
        if key not in previous:
            raise KSlideError(
                ErrorCode.INSTALL_COLLISION,
                "K-Slide refused to overwrite an unrelated existing file.",
                {"path": key, "guidance": "Back up or remove the conflicting K-Slide-owned file, then retry."},
            )
        if existing_hash != previous[key]:
            raise KSlideError(
                ErrorCode.INSTALL_LOCAL_MODIFICATION,
                "K-Slide refused to overwrite a locally modified owned file.",
                {"path": key, "guidance": "Restore the installed version or review the change before upgrading."},
            )


def _vscode_owned_parts(source: Path, destination: Path) -> tuple[tuple[Path, Path], ...]:
    """Select auditable adapter source assets and exclude local build output."""

    return tuple(
        [(source / name, destination) for name in ("package.json", "package-lock.json", "tsconfig.json", "README.md", ".vscodeignore", ".nvmrc")]
        + [(source / "src", destination / "src")]
    )


def _remove_legacy_owned_file(path: Path, *, target_root: Path, previous: dict[str, str]) -> None:
    key = str(path.relative_to(target_root))
    expected_hash = previous.get(key)
    if expected_hash is None or not path.exists():
        return
    if path.is_symlink() or not path.is_file() or _sha(path) != expected_hash:
        raise KSlideError(
            ErrorCode.INSTALL_LOCAL_MODIFICATION,
            "K-Slide refused to remove a locally modified legacy file.",
            {"path": key, "guidance": "Remove the legacy K-Slide helper after reviewing the local change, then retry."},
        )
    path.unlink()


def install(source_root: Path, target: Path, *, scope: str = "project") -> Path:
    if scope not in {"project", "global"}:
        raise KSlideError(ErrorCode.INSTALL_INVALID, "Installation scope must be project or global.")
    source_root = source_root.resolve()
    target = target.expanduser().resolve()
    if not (source_root / ".opencode" / "commands").is_dir() or not (source_root / "src" / "k_slide").is_dir():
        raise KSlideError(ErrorCode.INSTALL_INVALID, "K-Slide source tree is incomplete.")
    target.mkdir(parents=True, exist_ok=True)
    previous_path = target / (".k-slide-install.json" if scope == "project" else "k-slide-install.json")
    previous_manifest = _load_manifest(previous_path)
    previous_files = previous_manifest.get("files", {})
    previous = {str(key): str(value) for key, value in previous_files.items()} if isinstance(previous_files, dict) else {}
    vscode_source = source_root / "integrations" / "vscode"
    vscode_destination = target / ".vscode" / "k-slide-extension"
    if scope == "project":
        if not (vscode_source / "package.json").is_file() or not (vscode_source / "src" / "extension.ts").is_file():
            raise KSlideError(ErrorCode.INSTALL_INVALID, "K-Slide VS Code adapter source package is incomplete.")
    files: dict[str, str] = {}

    # Project installs live under <project>/.opencode. Global OpenCode installs
    # already target the OpenCode config directory itself.
    opencode_root = target / ".opencode" if scope == "project" else target
    engine_root = target / (".k-slide-engine" if scope == "project" else "k-slide-engine")
    parts = [(source_root / ".opencode" / name, opencode_root / name) for name in ("commands", "agents", "skills/k-slide", "internal/lib", "plugin", "tools")]
    parts.append((source_root / ".opencode" / "package.json", opencode_root))
    parts.append((source_root / ".opencode" / "package-lock.json", opencode_root))
    parts.extend((source_root / name, engine_root / name) for name in ("src", "schemas", "prompts", "termbase", "security"))
    parts.extend((source_root / name, engine_root) for name in ("constraints-production.txt", "pyproject.toml", "README.md", "setup.py", "MANIFEST.in"))
    if scope == "project":
        parts.extend(_vscode_owned_parts(vscode_source, vscode_destination))
        for name in (".k-slide-input", ".k-slide-runs", ".k-slide-config"):
            directory = target / name
            if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
                raise KSlideError(ErrorCode.INSTALL_COLLISION, "K-Slide workspace directories must be ordinary directories.", {"path": name})
    for source, destination in parts:
        if not source.exists():
            raise KSlideError(ErrorCode.INSTALL_INVALID, "K-Slide source package is incomplete.")
        _preflight_owned(source, destination, target_root=target, previous=previous)

    _remove_legacy_owned_file(opencode_root / "plugin" / "k-slide-access-key.ts", target_root=target, previous=previous)
    for source, destination in parts:
        files.update(_copy_owned(source, destination, target_root=target, previous=previous))

    if scope == "project":
        for directory in (target / ".k-slide-input", target / ".k-slide-runs", target / ".k-slide-config"):
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)

    manifest = {
        "schema_version": "1.0",
        "installer_version": __version__,
        "source_git_sha": _source_git_sha(source_root),
        "scope": scope,
        "source_root": str(source_root),
        "files": files,
        "host_instructions_policy": "never_overwrite_AGENTS.md",
    }
    atomic_write_json(previous_path, manifest, mode=0o600)
    return previous_path


def verify_install(target: Path, *, scope: str = "project") -> list[tuple[str, bool]]:
    target = target.expanduser().resolve()
    checks = [
        ("main command", (target / ".opencode" if scope == "project" else target) / "commands" / "k-slide.md"),
        ("agent", (target / ".opencode" if scope == "project" else target) / "agents" / "k-slide.md"),
        ("skill", (target / ".opencode" if scope == "project" else target) / "skills" / "k-slide" / "SKILL.md"),
        ("access-key handoff module", (target / ".opencode" if scope == "project" else target) / "internal" / "lib" / "k-slide-access-key.ts"),
        ("host adapter plugin", (target / ".opencode" if scope == "project" else target) / "plugin" / "k-slide-host.ts"),
        ("custom tools", (target / ".opencode" if scope == "project" else target) / "tools" / "kslide.ts"),
        ("core", target / (".k-slide-engine" if scope == "project" else "k-slide-engine") / "src" / "k_slide" / "cli.py"),
    ]
    if scope == "project":
        checks.extend([
            ("VS Code adapter source", target / ".vscode" / "k-slide-extension" / "package.json"),
            ("input folder", target / ".k-slide-input"),
            ("run folder", target / ".k-slide-runs"),
        ])
    results = [(label, path.exists() and not path.is_symlink()) for label, path in checks]
    try:
        manifest = _load_manifest(target / (".k-slide-install.json" if scope == "project" else "k-slide-install.json"))
        owned = manifest.get("files", {})
        intact = bool(owned) and manifest.get("scope") == scope
        for name, digest in owned.items():
            candidate = target / name
            current = target
            for component in Path(name).parts:
                current = current / component
                if current.is_symlink():
                    intact = False
                    break
            else:
                if not candidate.is_file() or _sha(candidate) != digest:
                    intact = False
        results.append(("installed file integrity", intact))
    except (KSlideError, OSError, ValueError):
        results.append(("installed file integrity", False))
    return results
