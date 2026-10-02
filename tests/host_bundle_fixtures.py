"""Use the real shipped host files inside synthetic managed deployments."""

import shutil
import json
from pathlib import Path


def install_readonly_host_bundle(destination: Path) -> None:
    source = Path(__file__).resolve().parents[1] / ".opencode"
    for directory in ("commands", "agents", "tools", "skills", "internal"):
        shutil.copytree(source / directory, destination / directory, dirs_exist_ok=True)
    for name in ("package.json", "package-lock.json"):
        shutil.copy2(source / name, destination / name)
    # Synthetic dependency contents keep unit tests offline. The independent
    # package build imports the real SDK installed with npm ci.
    lock = json.loads((source / "package-lock.json").read_text())
    for relative, metadata in lock["packages"].items():
        if not relative:
            continue
        dependency = destination / relative
        dependency.mkdir(parents=True)
        (dependency / "package.json").write_text(json.dumps({"version": metadata["version"]}))
        (dependency / "index.js").write_text("// synthetic fixture; never production runtime evidence\n")
    for path in destination.rglob("*"):
        path.chmod(0o555 if path.is_dir() or path.suffix == ".sh" else 0o444)
