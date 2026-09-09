"""Bounded OpenCode diagnostic ladder for separating provider from K-Slide failures."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from .opencode_events import normalize_events, parse_json_events


def _run_level(name: str, command: list[str], workspace: Path, timeout: int) -> dict[str, Any]:
    started = time.monotonic()
    try:
        process = subprocess.Popen(command, cwd=workspace, env=dict(os.environ), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            os.killpg(process.pid, 15)
            stdout, stderr = process.communicate(timeout=5)
            timed_out = True
            exit_code = process.returncode
        else:
            timed_out = False
            exit_code = process.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout = str(exc.stdout or "")
        stderr = str(exc.stderr or "")
        exit_code = None
    except OSError as exc:
        return {"level": name, "command": command, "status": "BLOCKED", "exit_code": None, "duration_seconds": round(time.monotonic() - started, 3), "event_count": 0, "last_event": None, "last_tool": None, "stdout": "", "stderr": str(exc)}
    raw_events = parse_json_events(f"{stdout}\n{stderr}")
    normalized = normalize_events(raw_events)
    result = {
        "level": name,
        "command": command,
        "status": "TIMEOUT" if timed_out else ("PASS" if exit_code == 0 else "FAIL"),
        "exit_code": exit_code,
        "duration_seconds": round(time.monotonic() - started, 3),
        "event_count": len(raw_events),
        "last_event": normalized[-1].as_dict() if normalized else None,
        "last_tool": normalized[-1].tool_name if normalized else None,
        "stdout": stdout[-4000:],
        "stderr": stderr[-4000:],
    }
    (workspace / f"{name}.stdout.log").write_text(stdout, encoding="utf-8")
    (workspace / f"{name}.stderr.log").write_text(stderr, encoding="utf-8")
    (workspace / f"{name}.events.json").write_text(json.dumps([item.as_dict() for item in normalized], ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return result


def run_diagnostic_ladder(*, model: str, output: Path, opencode: str | None = None, cold_timeout: int = 300, warm_timeout: int = 60) -> dict[str, Any]:
    executable = opencode or shutil.which("opencode")
    output.mkdir(parents=True, exist_ok=True)
    if not executable or (opencode is not None and not Path(executable).is_file()):
        result = {"status": "BLOCKED", "reason": "OpenCode executable is unavailable.", "levels": []}
        (output / "diagnostics.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        return result
    with tempfile.TemporaryDirectory(prefix="k-slide-opencode-diagnostics-") as directory:
        workspace = Path(directory)
        try:
            from k_slide.installer import install

            install(Path(__file__).resolve().parents[1], workspace, scope="project")
        except Exception as exc:
            result = {"status": "BLOCKED", "model": model, "reason": f"K-Slide diagnostic install failed: {exc}", "levels": []}
            (output / "diagnostics.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            return result
        provider_command = shutil.which("ollama")
        provider = {"status": "BLOCKED", "model": model, "reason": "ollama executable is unavailable"}
        if provider_command:
            try:
                health = subprocess.run([provider_command, "list"], capture_output=True, text=True, timeout=15, check=False)
                provider = {"status": "PASS" if health.returncode == 0 else "FAIL", "model": model, "exit_code": health.returncode, "stdout": health.stdout[-4000:], "stderr": health.stderr[-4000:]}
            except subprocess.TimeoutExpired:
                provider = {"status": "TIMEOUT", "model": model}
        levels: list[dict[str, Any]] = []
        levels.append(_run_level("level1_plain_opencode", [executable, "run", "--format", "json", "--dir", str(workspace), "Reply only with OK."], workspace, cold_timeout))
        levels.append(_run_level("level2_explicit_model", [executable, "run", "--format", "json", "--dir", str(workspace), "--model", model, "Reply only with OK."], workspace, cold_timeout))
        levels.append(_run_level("level3_k_slide_agent", [executable, "run", "--format", "json", "--dir", str(workspace), "--agent", "k-slide", "Reply only with OK."], workspace, warm_timeout))
        try:
            from PIL import Image

            source = workspace / "simple.png"
            Image.new("RGB", (1280, 720), "white").save(source)
            from .opencode_runner import OpenCodeEvalRunner

            runner = OpenCodeEvalRunner(model=model, timeout_seconds=warm_timeout, opencode=executable)
            level4 = runner.run(source=source, workspace=workspace / "level4", mode="protocol")
            levels.append({"level": "level4_k_slide_command", "status": level4.status, "exit_code": None, "duration_seconds": level4.duration_seconds, "event_count": len(level4.events), "last_event": (level4.normalized_events[-1] if level4.normalized_events else None), "reason": level4.reason, "diagnostics": level4.diagnostics})
        except Exception as exc:
            levels.append({"level": "level4_k_slide_command", "status": "BLOCKED", "reason": str(exc)})
        result = {"status": "PASS" if levels and levels[-1].get("status") == "PASS" else "BLOCKED_OR_FAILED", "model": model, "provider": provider, "levels": levels}
        (output / "diagnostics.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return result
