"""Use the real shipped host files inside synthetic managed deployments."""

import shutil
from pathlib import Path


def install_readonly_host_bundle(destination: Path) -> None:
    source = Path(__file__).resolve().parents[1] / ".opencode"
    for directory in ("commands", "agents", "tools", "skills", "internal"):
        shutil.copytree(source / directory, destination / directory, dirs_exist_ok=True)
    for name in ("package.json", "package-lock.json"):
        shutil.copy2(source / name, destination / name)
    for path in destination.rglob("*"):
        path.chmod(0o555 if path.is_dir() or path.suffix == ".sh" else 0o444)
