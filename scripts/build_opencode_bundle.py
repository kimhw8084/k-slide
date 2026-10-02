"""Build a preinstalled, read-only OpenCode host bundle for managed images."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from k_slide.opencode_bootstrap import OPENCODE_VERSION, _host_bundle_identity


def build(output: Path) -> None:
    for binary, expected in (("node", "v22.15.0"), ("npm", "10.9.2")):
        actual = subprocess.check_output([binary, "--version"], text=True).strip()
        if actual != expected:
            raise ValueError(f"Host bundle build requires {binary} {expected}.")
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="k-slide-opencode-build-") as directory:
        stage = Path(directory) / "host"
        stage.mkdir()
        source = ROOT / ".opencode"
        for name in ("commands", "agents", "skills", "tools", "plugin", "internal"):
            shutil.copytree(source / name, stage / name)
        for name in ("package.json", "package-lock.json"):
            shutil.copy2(source / name, stage / name)
        subprocess.run(["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund", "--omit=dev"], cwd=stage, check=True)
        files = sorted(stage.rglob("*"))
        for file in files:
            if file.is_symlink() or not (file.is_file() or file.is_dir()):
                raise ValueError("Host bundle contains an unsupported filesystem entry.")
            file.chmod(0o555 if file.is_dir() or file.stat().st_mode & 0o111 else 0o444)
        host_identity = _host_bundle_identity(stage)
        # Import the installed SDK to catch incomplete/broken dependency packing.
        subprocess.run(["node", "--input-type=module", "-e", 'import {tool} from "@opencode-ai/plugin"; if(typeof tool !== "function") process.exit(2)'], cwd=stage, check=True)
        archive = Path(directory) / "host.tar.gz"
        with archive.open("wb") as stream, gzip.GzipFile(filename="", mode="wb", fileobj=stream, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as tar:
                for file in files:
                    info = tar.gettarinfo(str(file), arcname=file.relative_to(stage).as_posix())
                    info.uid = info.gid = info.mtime = 0
                    info.uname = info.gname = ""
                    if file.is_file():
                        with file.open("rb") as contents:
                            tar.addfile(info, contents)
                    else:
                        tar.addfile(info)
        # Verify the archive itself, including that the dependencies were included.
        with tarfile.open(archive) as tar:
            names = set(tar.getnames())
            for required in ("agents/k-slide.md", "commands/k-slide.md", "tools/kslide.ts", "node_modules/@opencode-ai/plugin/package.json"):
                if required not in names:
                    raise ValueError("Built host archive is incomplete.")
        manifest = {
            "schema_version": "1.0", "status": "HOST_PACKAGE_ONLY_NOT_PRODUCTION_CERTIFIED",
            "opencode_version": OPENCODE_VERSION, "host_bundle_sha256": host_identity,
            "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
            "files": {file.relative_to(stage).as_posix(): hashlib.sha256(file.read_bytes()).hexdigest() for file in files if file.is_file()},
        }
        shutil.copyfile(archive, output)
        output.with_suffix(output.suffix + ".json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("OpenCode host bundle built and verified; managed runtime/configuration still required.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    try:
        build(parser.parse_args().output)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        raise SystemExit(f"OpenCode host bundle build failed: {type(exc).__name__}") from None
