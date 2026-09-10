"""Isolated, version-aware OpenCode diagnostic ladder."""

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
from .process_control import terminate_process_group
from k_slide.certification import build_deployment_factors, deployment_fingerprint
from k_slide.model_policy import load_model_policy
from k_slide.runtime import discover_runtime
from k_slide.redaction import redact_text, redact_value


def _persist_level(output: Path, name: str, result: dict[str, Any]) -> None:
    output.mkdir(parents=True, exist_ok=True)
    safe = redact_value(result, roots=(output,))
    (output / f"{name}.json").write_text(json.dumps(safe, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (output / f"{name}.stdout").write_text(redact_text(str(result.get("stdout", "")), roots=(output,)), encoding="utf-8")
    (output / f"{name}.stderr").write_text(redact_text(str(result.get("stderr", "")), roots=(output,)), encoding="utf-8")
    (output / f"{name}.events.json").write_text(json.dumps(redact_value(result.get("events", []), roots=(output,)), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _run_command(name: str, command: list[str], workspace: Path, output: Path, timeout: int, *, parse_events: bool = False) -> dict[str, Any]:
    started = time.monotonic()
    cleanup = {"sigterm_sent": False, "sigkill_sent": False, "reaped": True}
    try:
        process = subprocess.Popen(command, cwd=workspace, env=dict(os.environ), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            timed_out = False
        except subprocess.TimeoutExpired:
            cleanup = terminate_process_group(process, grace_seconds=5)
            stdout, stderr = process.communicate(timeout=5)
            timed_out = True
        exit_code = process.returncode
    except OSError as exc:
        result = {"level": name, "command": command, "status": "BLOCKED", "exit_code": None, "duration_seconds": round(time.monotonic() - started, 3), "event_count": 0, "last_event": None, "last_tool": None, "stdout": "", "stderr": str(exc), "events": [], "process_cleanup": cleanup}
        _persist_level(output, name, result)
        return result
    raw_events = parse_json_events(f"{stdout}\n{stderr}") if parse_events else []
    normalized = normalize_events(raw_events) if raw_events else []
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
        "events": [item.as_dict() for item in normalized],
        "process_cleanup": cleanup,
    }
    _persist_level(output, name, result)
    return result


def _classification(levels: list[dict[str, Any]]) -> tuple[str | None, str]:
    failures = {
        "level0_opencode": "OPENCODE_EXECUTABLE_UNAVAILABLE",
        "level0a_config": "OPENCODE_CONFIG_BLOCKED",
        "level0b_models": "OPENCODE_MODEL_INVENTORY_BLOCKED",
        "level1a_pure_opencode": "OPENCODE_PROVIDER_RUNTIME_BLOCKED",
        "level1_plain_opencode": "OPENCODE_PROVIDER_RUNTIME_BLOCKED",
        "level2_explicit_model": "REQUESTED_MODEL_OR_PROVIDER_BLOCKED",
        "level3_k_slide_agent": "KSLIDE_PROJECT_LAYER_BLOCKED",
        "level4_k_slide_command": "KSLIDE_ORCHESTRATION_BLOCKED",
    }
    for level in levels:
        if level.get("status") in {"FAIL", "TIMEOUT", "BLOCKED"}:
            name = str(level.get("level"))
            return name, failures.get(name, "OPENCODE_RUNTIME_BLOCKED")
    return None, "PASS"


def _provider_health(model: str, config: dict[str, Any], workspace: Path, output: Path) -> dict[str, Any]:
    """Run a provider check only when the effective model exposes a provider."""

    raw = json.dumps(config, ensure_ascii=False).lower()
    provider_name = "ollama" if "ollama/" in model.lower() or "ollama" in raw else None
    if provider_name == "ollama":
        executable = shutil.which("ollama")
        if not executable:
            result = {"status": "NOT_AVAILABLE", "provider": "ollama", "reason": "ollama executable is unavailable; OpenCode remains authoritative."}
        else:
            result = _run_command("level0c_ollama", [executable, "list"], workspace, output, 30)
            result["provider"] = "ollama"
        _persist_level(output, "level0c_provider", result)
        return result
    result = {"status": "NOT_RUN", "provider": provider_name, "reason": "No provider-specific health command was identified from effective configuration."}
    _persist_level(output, "level0c_provider", result)
    return result


def run_diagnostic_ladder(*, model: str, output: Path, opencode: str | None = None, cold_timeout: int = 300, warm_timeout: int = 60) -> dict[str, Any]:
    """Run clean-provider levels before installing any K-Slide project files."""

    output.mkdir(parents=True, exist_ok=True)
    repo_root = Path(__file__).resolve().parents[1]
    try:
        git = subprocess.run(["git", "-C", str(repo_root), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=5, check=False)
        subject_sha = git.stdout.strip() if git.returncode == 0 else "UNSET"
    except (OSError, subprocess.TimeoutExpired):
        subject_sha = "UNSET"
    deployment = deployment_fingerprint(build_deployment_factors(repo_root, subject_git_sha=subject_sha, runtime={**discover_runtime().as_dict(), "reported_model_id": model}, profile={}, model_policy=load_model_policy(repo_root), corpus={}))
    executable = opencode or shutil.which("opencode")
    if not executable or (opencode is not None and not Path(executable).is_file()):
        result = {"status": "BLOCKED", "model": model, "subject_git_sha": subject_sha, "deployment_fingerprint": deployment, "reason": "OpenCode executable is unavailable.", "levels": [], "first_failed_level": "level0_opencode", "conclusion": "OPENCODE_EXECUTABLE_UNAVAILABLE"}
        (output / "diagnostics.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return result

    with tempfile.TemporaryDirectory(prefix="k-slide-opencode-diagnostics-") as directory:
        root = Path(directory)
        clean_workspace = root / "workspace-clean"
        kslide_workspace = root / "workspace-kslide"
        clean_workspace.mkdir()
        kslide_workspace.mkdir()
        levels: list[dict[str, Any]] = []
        provider_result: dict[str, Any] = {"status": "NOT_RUN", "reason": "OpenCode executable check has not completed."}

        version = _run_command("level0_opencode", [executable, "--version"], clean_workspace, output, 15)
        levels.append(version)
        if version["status"] == "PASS":
            config = _run_command("level0a_config", [executable, "debug", "config"], clean_workspace, output, 30)
            levels.append(config)
            provider_result = _provider_health(model, config, clean_workspace, output)
            help_result = _run_command("level0b_help", [executable, "--help"], clean_workspace, output, 30)
            help_text = (str(help_result.get("stdout", "")) + str(help_result.get("stderr", ""))).lower()
            models_supported = "models" in help_text
            if models_supported:
                models = _run_command("level0b_models", [executable, "models"], clean_workspace, output, 60)
            else:
                models = {"level": "level0b_models", "command": [executable, "models"], "status": "NOT_SUPPORTED", "exit_code": None, "duration_seconds": help_result.get("duration_seconds", 0), "event_count": 0, "last_event": None, "last_tool": None, "stdout": "", "stderr": "OpenCode help does not advertise a models command.", "events": [], "process_cleanup": {"sigterm_sent": False, "sigkill_sent": False, "reaped": True}}
                _persist_level(output, "level0b_models", models)
            levels.append(models)
            if "--pure" in help_text:
                levels.append(_run_command("level1a_pure_opencode", [executable, "--pure", "--print-logs", "--log-level", "DEBUG", "run", "--format", "json", "--dir", str(clean_workspace), "Reply only with OK."], clean_workspace, output, cold_timeout, parse_events=True))
            else:
                unsupported = {"level": "level1a_pure_opencode", "command": [executable, "--pure", "run"], "status": "NOT_SUPPORTED", "exit_code": None, "duration_seconds": 0, "event_count": 0, "last_event": None, "last_tool": None, "stdout": "", "stderr": "OpenCode help does not advertise --pure.", "events": [], "process_cleanup": {"sigterm_sent": False, "sigkill_sent": False, "reaped": True}}
                _persist_level(output, "level1a_pure_opencode", unsupported)
                levels.append(unsupported)
            levels.append(_run_command("level1_plain_opencode", [executable, "--print-logs", "--log-level", "DEBUG", "run", "--format", "json", "--dir", str(clean_workspace), "Reply only with OK."], clean_workspace, output, cold_timeout, parse_events=True))
            levels.append(_run_command("level2_explicit_model", [executable, "run", "--format", "json", "--dir", str(clean_workspace), "--model", model, "Reply only with OK."], clean_workspace, output, cold_timeout, parse_events=True))

        install_result: dict[str, Any] = {"status": "SKIPPED_UPSTREAM_BLOCKED"}
        if levels and levels[-1].get("status") == "PASS":
            try:
                from k_slide.installer import install

                install(Path(__file__).resolve().parents[1], kslide_workspace, scope="project")
                install_result = {"status": "PASS", "workspace": str(kslide_workspace)}
            except Exception as exc:
                install_result = {"status": "FAIL", "reason": str(exc), "workspace": str(kslide_workspace)}
        _persist_level(output, "kslide_install", install_result)

        if install_result.get("status") == "PASS":
            levels.append(_run_command("level3_k_slide_agent", [executable, "run", "--format", "json", "--dir", str(kslide_workspace), "--agent", "k-slide", "--model", model, "Reply only with OK."], kslide_workspace, output, warm_timeout, parse_events=True))
            try:
                from PIL import Image
                from .opencode_runner import OpenCodeEvalRunner

                source = kslide_workspace / "simple.png"
                Image.new("RGB", (1280, 720), "white").save(source)
                runner = OpenCodeEvalRunner(model=model, timeout_seconds=warm_timeout, opencode=executable)
                level4 = runner.run(source=source, workspace=kslide_workspace, mode="protocol")
                level4_result = {"level": "level4_k_slide_command", "status": level4.status, "command": runner.command(kslide_workspace), "exit_code": None, "duration_seconds": level4.duration_seconds, "event_count": len(level4.events), "last_event": (level4.normalized_events[-1] if level4.normalized_events else None), "last_tool": level4.normalized_events[-1].get("tool_name") if level4.normalized_events else None, "stdout": "", "stderr": level4.reason or "", "events": list(level4.normalized_events), "process_cleanup": level4.diagnostics.get("process_cleanup", {}), "reason": level4.reason, "diagnostics": level4.diagnostics}
                levels.append(level4_result)
                _persist_level(output, "level4_k_slide_command", level4_result)
            except Exception as exc:
                level4_result = {"level": "level4_k_slide_command", "status": "BLOCKED", "reason": str(exc), "event_count": 0, "last_event": None, "last_tool": None, "stdout": "", "stderr": str(exc), "events": [], "process_cleanup": {"sigterm_sent": False, "sigkill_sent": False, "reaped": True}}
                levels.append(level4_result)
                _persist_level(output, "level4_k_slide_command", level4_result)

        first_failed, conclusion = _classification(levels)
        result = {
            "status": "PASS" if conclusion == "PASS" else "BLOCKED_OR_FAILED",
            "model": model,
            "requested_model": model,
            "subject_git_sha": subject_sha,
            "deployment_fingerprint": deployment,
            "provider": provider_result,
            "workspace_paths": {"clean": "workspace-clean", "k_slide": "workspace-kslide"},
            "workspace_assertions": {
                "clean_has_project_opencode": (clean_workspace / ".opencode").exists(),
                "clean_has_engine": (clean_workspace / ".k-slide-engine").exists(),
                "clean_has_k_slide_config": (clean_workspace / ".k-slide-config").exists(),
                "kslide_has_project_opencode": (kslide_workspace / ".opencode").exists(),
                "kslide_has_engine": (kslide_workspace / ".k-slide-engine").exists(),
            },
            "install": install_result,
            "levels": redact_value(levels, roots=(output,)),
            "first_failed_level": first_failed,
            "conclusion": conclusion,
        }
        (output / "diagnostics.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return result
