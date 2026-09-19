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
from k_slide import __version__
from k_slide.certification import CANDIDATE_SPEC_SCHEMA_VERSION, candidate_deployment_fingerprint, canonical_candidate_factors, canonical_corpus_identity, load_candidate_spec, resolve_candidate_spec
from k_slide.model_policy import load_model_policy
from k_slide.runtime import discover_runtime
from k_slide.authentication import ACCESS_KEY_ENV
from k_slide.redaction import CredentialExposureError, redact_value, safe_credential_json, safe_diagnostic_text_or_placeholder
from .scenarios import split_manifest


def _persist_level(output: Path, name: str, result: dict[str, Any], *, secret_values: tuple[str, ...] = ()) -> None:
    output.mkdir(parents=True, exist_ok=True)
    try:
        safe_json = safe_credential_json(result, roots=(output,), secret_values=secret_values)
    except CredentialExposureError:
        safe_json = json.dumps({"status": "REDACTED_UNSAFE_DIAGNOSTIC", "artifact": f"{name}.json"}, ensure_ascii=False, indent=2) + "\n"
    (output / f"{name}.json").write_text(safe_json, encoding="utf-8")
    for suffix, field in (("stdout", "stdout"), ("stderr", "stderr")):
        text = safe_diagnostic_text_or_placeholder(str(result.get(field, "")), roots=(output,), secret_values=secret_values)
        (output / f"{name}.{suffix}").write_text(text, encoding="utf-8")
    try:
        events = safe_credential_json(result.get("events", []), roots=(output,), secret_values=secret_values)
    except CredentialExposureError:
        events = json.dumps({"status": "REDACTED_UNSAFE_DIAGNOSTIC", "artifact": f"{name}.events.json"}, ensure_ascii=False, indent=2) + "\n"
    (output / f"{name}.events.json").write_text(events, encoding="utf-8")


def _process_environment() -> dict[str, str]:
    environment = dict(os.environ)
    environment.pop(ACCESS_KEY_ENV, None)
    return environment


def _persist_diagnostics(output: Path, result: dict[str, Any], *, secret_values: tuple[str, ...] = ()) -> None:
    try:
        text = safe_credential_json(result, roots=(output,), secret_values=secret_values)
    except CredentialExposureError:
        text = json.dumps({"status": "REDACTED_UNSAFE_DIAGNOSTIC", "artifact": "diagnostics.json"}, ensure_ascii=False, indent=2) + "\n"
    (output / "diagnostics.json").write_text(text, encoding="utf-8")


def _run_command(name: str, command: list[str], workspace: Path, output: Path, timeout: int, *, parse_events: bool = False) -> dict[str, Any]:
    started = time.monotonic()
    cleanup = {"sigterm_sent": False, "sigkill_sent": False, "reaped": True}
    try:
        process = subprocess.Popen(command, cwd=workspace, env=_process_environment(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            timed_out = False
        except subprocess.TimeoutExpired:
            cleanup = terminate_process_group(process, grace_seconds=5)
            stdout, stderr = process.communicate(timeout=5)
            timed_out = True
        exit_code = process.returncode
    except OSError as exc:
        result = {"level": name, "command": command, "status": "BLOCKED", "exit_code": None, "duration_seconds": round(time.monotonic() - started, 3), "event_count": 0, "last_event": None, "last_tool": None, "stdout": "", "stderr": f"{type(exc).__name__}", "events": [], "process_cleanup": cleanup}
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


def run_diagnostic_ladder(*, model: str, output: Path, opencode: str | None = None, cold_timeout: int = 300, warm_timeout: int = 60, candidate_profile: Path | None = None) -> dict[str, Any]:
    """Run clean-provider levels before installing any K-Slide project files."""

    output.mkdir(parents=True, exist_ok=True)
    repo_root = Path(__file__).resolve().parents[1]
    try:
        git = subprocess.run(["git", "-C", str(repo_root), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=5, check=False)
        subject_sha = git.stdout.strip() if git.returncode == 0 else "UNSET"
    except (OSError, subprocess.TimeoutExpired):
        subject_sha = "UNSET"
    corpus = canonical_corpus_identity(split_manifest())
    if candidate_profile is not None:
        try:
            candidate = load_candidate_spec(candidate_profile, root=repo_root, require_identity=False, strict=True)
        except Exception as exc:
            result = {"status": "BLOCKED", "model": model, "subject_git_sha": subject_sha, "reason": f"Candidate profile could not be loaded ({type(exc).__name__}).", "levels": [], "first_failed_level": "candidate_profile", "conclusion": "CANDIDATE_PROFILE_INVALID"}
            _persist_diagnostics(output, result)
            return result
    else:
        candidate = {"schema_version": CANDIDATE_SPEC_SCHEMA_VERSION, "subject_git_sha": subject_sha, "kslide_version": __version__, "requested_model": model, "effective_model": "UNSET"}
    declared_model = str(candidate.get("requested_model") or "")
    if declared_model and declared_model.upper() != "UNSET" and declared_model != model:
        result = {"status": "BLOCKED", "model": model, "subject_git_sha": subject_sha, "reason": "candidate requested_model does not match diagnostic model", "levels": [], "first_failed_level": "candidate_profile", "conclusion": "CANDIDATE_PROFILE_INVALID"}
        _persist_diagnostics(output, result)
        return result
    declared_subject = str(candidate.get("subject_git_sha") or "")
    if declared_subject and declared_subject.upper() != "UNSET" and declared_subject != subject_sha:
        result = {"status": "BLOCKED", "model": model, "subject_git_sha": subject_sha, "reason": "candidate subject_git_sha does not match diagnostic subject", "levels": [], "first_failed_level": "candidate_profile", "conclusion": "CANDIDATE_PROFILE_INVALID"}
        _persist_diagnostics(output, result)
        return result
    candidate["subject_git_sha"] = subject_sha
    candidate["requested_model"] = model
    policy = load_model_policy(repo_root)
    candidate = resolve_candidate_spec(candidate, root=repo_root, subject_git_sha=subject_sha, model_policy=policy, corpus=corpus, require_sources=candidate_profile is not None)
    deployment = candidate_deployment_fingerprint(candidate)
    executable = opencode or shutil.which("opencode")
    if not executable or (opencode is not None and not Path(executable).is_file()):
        result = {"status": "BLOCKED", "model": model, "subject_git_sha": subject_sha, "deployment_fingerprint": deployment, "candidate_spec": canonical_candidate_factors(candidate), "runtime_provenance": discover_runtime(repo_root).as_dict(), "reason": "OpenCode executable is unavailable.", "levels": [], "first_failed_level": "level0_opencode", "conclusion": "OPENCODE_EXECUTABLE_UNAVAILABLE"}
        _persist_diagnostics(output, result)
        return result

    with tempfile.TemporaryDirectory(prefix="k-slide-opencode-diagnostics-") as directory:
        root = Path(directory)
        clean_workspace = root / "workspace-clean"
        kslide_workspace = root / "workspace-kslide"
        clean_workspace.mkdir()
        kslide_workspace.mkdir()
        levels: list[dict[str, Any]] = []
        runtime_secret_values: tuple[str, ...] = ()
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
                install_result = {"status": "FAIL", "reason": f"Project installation failed ({type(exc).__name__}).", "workspace": str(kslide_workspace)}
        _persist_level(output, "kslide_install", install_result)

        if install_result.get("status") == "PASS":
            levels.append(_run_command("level3_k_slide_agent", [executable, "run", "--format", "json", "--dir", str(kslide_workspace), "--agent", "k-slide", "--model", model, "Reply only with OK."], kslide_workspace, output, warm_timeout, parse_events=True))
            try:
                from PIL import Image
                from .opencode_runner import OpenCodeEvalRunner

                source = kslide_workspace / "simple.png"
                Image.new("RGB", (1280, 720), "white").save(source)
                runner = OpenCodeEvalRunner(model=model, timeout_seconds=warm_timeout, opencode=executable, policy=policy, policy_root=repo_root, candidate_spec=candidate if candidate_profile is not None else None, candidate_root=repo_root)
                level4 = runner.run(source=source, workspace=kslide_workspace, mode="protocol")
                level4_secret_values = level4._secret_values
                level4_events = json.loads(safe_credential_json(list(level4.normalized_events), roots=(output,), secret_values=level4_secret_values))
                level4_result = {"level": "level4_k_slide_command", "status": level4.status, "command": runner.command(kslide_workspace), "exit_code": None, "duration_seconds": level4.duration_seconds, "event_count": len(level4.events), "last_event": (level4_events[-1] if level4_events else None), "last_tool": level4_events[-1].get("tool_name") if level4_events else None, "stdout": "", "stderr": level4.reason or "", "events": level4_events, "process_cleanup": level4.diagnostics.get("process_cleanup", {}), "reason": level4.reason, "diagnostics": level4.diagnostics}
                levels.append(level4_result)
                _persist_level(output, "level4_k_slide_command", level4_result, secret_values=level4_secret_values)
                runtime_secret_values = level4_secret_values
            except Exception as exc:
                level4_result = {"level": "level4_k_slide_command", "status": "BLOCKED", "reason": f"K-Slide command diagnostic failed ({type(exc).__name__}).", "event_count": 0, "last_event": None, "last_tool": None, "stdout": "", "stderr": f"{type(exc).__name__}", "events": [], "process_cleanup": {"sigterm_sent": False, "sigkill_sent": False, "reaped": True}}
                levels.append(level4_result)
                _persist_level(output, "level4_k_slide_command", level4_result)

        first_failed, conclusion = _classification(levels)
        result = {
            "status": "PASS" if conclusion == "PASS" else "BLOCKED_OR_FAILED",
            "model": model,
            "requested_model": model,
            "subject_git_sha": subject_sha,
            "deployment_fingerprint": deployment,
            "candidate_spec": canonical_candidate_factors(candidate),
            "runtime_provenance": discover_runtime(repo_root).as_dict(),
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
            "levels": redact_value(levels, roots=(output,), secret_values=runtime_secret_values),
            "first_failed_level": first_failed,
            "conclusion": conclusion,
        }
        _persist_diagnostics(output, result, secret_values=runtime_secret_values)
        return result
