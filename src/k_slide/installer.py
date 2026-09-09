"""Collision-safe project/global installation."""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

from . import __version__
from .errors import ErrorCode, KSlideError
from .io import atomic_write_json


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _files(source: Path) -> list[Path]:
    if source.is_file():
        return [source]
    return sorted(path for path in source.rglob("*") if path.is_file())


def _load_manifest(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise KSlideError(ErrorCode.INSTALL_INVALID, "Existing K-Slide install manifest is unreadable.", {"path": str(path)}) from exc
    return value if isinstance(value, dict) else {}


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
        shutil.copy2(source_file, destination_file)
        installed[destination_key] = source_hash
    return installed


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
    files: dict[str, str] = {}

    # Project installs live under <project>/.opencode. Global OpenCode installs
    # already target the OpenCode config directory itself.
    opencode_root = target / ".opencode" if scope == "project" else target
    files.update(_copy_owned(source_root / ".opencode" / "commands", opencode_root / "commands", target_root=target, previous=previous))
    files.update(_copy_owned(source_root / ".opencode" / "agents", opencode_root / "agents", target_root=target, previous=previous))
    files.update(_copy_owned(source_root / ".opencode" / "skills" / "k-slide", opencode_root / "skills" / "k-slide", target_root=target, previous=previous))
    files.update(_copy_owned(source_root / ".opencode" / "tools", opencode_root / "tools", target_root=target, previous=previous))
    files.update(_copy_owned(source_root / ".opencode" / "package.json", opencode_root, target_root=target, previous=previous))

    engine_root = target / (".k-slide-engine" if scope == "project" else "k-slide-engine")
    files.update(_copy_owned(source_root / "src", engine_root / "src", target_root=target, previous=previous))
    files.update(_copy_owned(source_root / "schemas", engine_root / "schemas", target_root=target, previous=previous))
    files.update(_copy_owned(source_root / "termbase", engine_root / "termbase", target_root=target, previous=previous))
    files.update(_copy_owned(source_root / "pyproject.toml", engine_root, target_root=target, previous=previous))

    if scope == "project":
        for directory in (target / ".k-slide-input", target / ".k-slide-runs", target / ".k-slide-config"):
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)

    manifest = {
        "schema_version": "1.0",
        "installer_version": __version__,
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
        ("custom tools", (target / ".opencode" if scope == "project" else target) / "tools" / "kslide.ts"),
        ("core", target / (".k-slide-engine" if scope == "project" else "k-slide-engine") / "src" / "k_slide" / "cli.py"),
    ]
    if scope == "project":
        checks.extend([("input folder", target / ".k-slide-input"), ("run folder", target / ".k-slide-runs")])
    return [(label, path.exists()) for label, path in checks]
