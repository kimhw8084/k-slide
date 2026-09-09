"""OpenCode production-surface runner with structured event assertions.

The runner is intentionally conservative: a successful process is not a
successful K-Slide case unless the persisted K-Slide run reaches COMPLETE and
its required artifacts are present. Non-target models remain protocol smoke
only and can never create authoritative quality metrics.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .opencode_events import (
    actual_read_paths,
    forbidden_tool_attempts,
    is_error_event,
    media_compliance,
    normalize_events,
    parse_json_events,
    tool_calls,
)
from .certification import load_model_policy


@dataclass(frozen=True)
class OpenCodeRunResult:
    status: str
    mode: str
    model: str
    runtime_version: str | None
    workspace: str
    duration_seconds: float
    events: tuple[dict[str, Any], ...]
    tool_calls: tuple[str, ...]
    forbidden_attempts: tuple[str, ...]
    media_read_observed: bool | None
    final_text: str | None
    run_artifact_count: int = 0
    reason: str | None = None
    normalized_events: tuple[dict[str, Any], ...] = ()
    media_compliance: dict[str, Any] = field(default_factory=dict)
    kslide_complete: bool = False
    quality_metrics_authoritative: bool = False
    diagnostics: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "mode": self.mode,
            "model": self.model,
            "runtime_version": self.runtime_version,
            "workspace": self.workspace,
            "duration_seconds": self.duration_seconds,
            "event_count": len(self.events),
            "tool_calls": list(self.tool_calls),
            "forbidden_attempts": list(self.forbidden_attempts),
            "media_read_observed": self.media_read_observed,
            "media_compliance": self.media_compliance,
            "final_text": self.final_text,
            "run_artifact_count": self.run_artifact_count,
            "reason": self.reason,
            "kslide_complete": self.kslide_complete,
            "quality_metrics_authoritative": self.quality_metrics_authoritative,
            "diagnostics": self.diagnostics,
        }


def _version(opencode: str) -> str | None:
    try:
        result = subprocess.run([opencode, "--version"], capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return (result.stdout or result.stderr).strip() or None


def _configured_model(opencode: str) -> str | None:
    """Read the effective configured model when OpenCode exposes it."""

    try:
        result = subprocess.run([opencode, "debug", "config"], capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    try:
        payload = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        return None
    model = payload.get("model") if isinstance(payload, dict) else None
    return str(model) if isinstance(model, str) and model else None


def _structured_model(events: list[dict[str, Any]]) -> str | None:
    """Return model identity only from structured event fields."""

    keys = ("model", "model_id", "modelID", "reported_model_id")
    for event in events:
        if not isinstance(event, dict):
            continue
        for key in keys:
            value = event.get(key)
            if isinstance(value, str) and value:
                return value
        for child_key in ("data", "message", "payload", "part"):
            child = event.get(child_key)
            if isinstance(child, dict):
                for key in keys:
                    value = child.get(key)
                    if isinstance(value, str) and value:
                        return value
    return None


def _latest_run(root: Path) -> Path | None:
    run_root = root / ".k-slide-runs"
    if not run_root.is_dir():
        return None
    runs = [item for item in run_root.iterdir() if item.is_dir() and (item / "RUN_STATE.json").is_file()]
    return max(runs, key=lambda item: item.stat().st_mtime, default=None)


def _completion_contract(run_dir: Path | None) -> tuple[bool, dict[str, Any]]:
    if run_dir is None:
        return False, {"reason": "no K-Slide run directory"}
    try:
        state = json.loads((run_dir / "RUN_STATE.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return False, {"reason": f"run state unavailable: {exc.__class__.__name__}"}
    required = ("RUN_COMPLETE.md", "05_executive_brief.md", "05_final_report.md", "06_verification.md", "07_unresolved_items.md")
    missing = [name for name in required if not (run_dir / name).is_file()]
    complete = state.get("phase") == "COMPLETE" and not missing
    return complete, {"run_id": run_dir.name, "phase": state.get("phase"), "missing_artifacts": missing}


def _diagnostics(root: Path, *, events: list[dict[str, Any]] | None = None, timeout: bool = False) -> dict[str, Any]:
    result: dict[str, Any] = {"timeout": timeout, "last_event": events[-1] if events else None}
    run = _latest_run(root)
    if run is None:
        result["run"] = None
        return result
    result["run"] = run.name
    for filename in ("RUN_STATE.json", "WORK_QUEUE.json"):
        path = run / filename
        if path.is_file():
            try:
                result[filename] = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                result[filename] = "CORRUPT_OR_UNREADABLE"
    return result


def _read_policy_violations(root: Path, normalized: tuple[Any, ...]) -> list[str]:
    allowed_roots = ((root / ".k-slide-runs").resolve(), (root / ".opencode" / "skills" / "k-slide").resolve())
    violations: list[str] = []
    for raw_path in actual_read_paths(normalized):
        candidate = Path(raw_path)
        if not candidate.is_absolute():
            candidate = (root / candidate).resolve()
        else:
            candidate = candidate.resolve()
        if not any(candidate == allowed or allowed in candidate.parents for allowed in allowed_roots):
            violations.append(raw_path)
    return violations


class OpenCodeEvalRunner:
    """Run the actual OpenCode CLI slash-command surface in isolation."""

    def __init__(self, *, model: str, timeout_seconds: int = 180, opencode: str | None = None, ocr_policy: str | None = None):
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.opencode = opencode or shutil.which("opencode")
        self.ocr_policy = ocr_policy

    @property
    def runtime_version(self) -> str | None:
        return _version(self.opencode) if self.opencode else None

    def command(self, workspace: Path) -> list[str]:
        if not self.opencode:
            return []
        return [self.opencode, "run", "--format", "json", "--dir", str(workspace), "--agent", "k-slide", "--model", self.model, "--command", "k-slide"]

    def run(self, *, source: Path | None = None, workspace: Path | None = None, mode: str = "protocol") -> OpenCodeRunResult:
        if not self.opencode:
            return OpenCodeRunResult("BLOCKED", mode, self.model, None, str(workspace or ""), 0.0, (), (), (), None, None, reason="OpenCode executable is unavailable.")
        created = workspace is None
        root_context = tempfile.TemporaryDirectory(prefix="k-slide-opencode-eval-") if created else None
        root = Path(root_context.name) if root_context else Path(workspace)
        root.mkdir(parents=True, exist_ok=True)
        if self.ocr_policy:
            config_dir = root / ".k-slide-config"
            config_dir.mkdir(parents=True, exist_ok=True)
            (config_dir / "ocr.local.json").write_text(json.dumps({"ocr_provider": self.ocr_policy}) + "\n", encoding="utf-8")
        input_dir = root / ".k-slide-input"
        input_dir.mkdir(parents=True, exist_ok=True)
        if source is not None:
            shutil.copy2(source, input_dir / source.name)
        try:
            from k_slide.installer import install

            install(Path(__file__).resolve().parents[1], root, scope="project")
        except Exception as exc:
            if root_context is not None:
                root_context.cleanup()
            return OpenCodeRunResult("INSTALL_FAILED", mode, self.model, self.runtime_version, str(root), 0.0, (), (), (), None, None, reason=str(exc))
        env = dict(os.environ)
        env["KSLIDE_MODEL"] = self.model
        started = time.monotonic()
        try:
            process = subprocess.Popen(self.command(root), cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
            timed_out = False
            try:
                stdout, stderr = process.communicate(timeout=self.timeout_seconds)
            except subprocess.TimeoutExpired as exc:
                os.killpg(process.pid, 15)
                stdout, stderr = process.communicate(timeout=5)
                timed_out = True
            completed_returncode = process.returncode
            if timed_out:
                partial = stdout or ""
                partial_stderr = stderr or ""
                raw_events = parse_json_events(f"{partial}\n{partial_stderr}")
                normalized = normalize_events(raw_events)
                diagnostics = _diagnostics(root, events=raw_events, timeout=True)
                diagnostics.update({"process_state": "TIMEOUT", "event_count": len(raw_events), "last_tool_call": normalized[-1].tool_name if normalized else None, "elapsed_seconds": time.monotonic() - started})
                (root / "opencode-timeout-stdout.log").write_text(partial, encoding="utf-8")
                (root / "opencode-timeout-stderr.log").write_text(partial_stderr, encoding="utf-8")
                (root / "opencode-timeout-diagnostics.json").write_text(json.dumps(diagnostics, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
                return OpenCodeRunResult("TIMEOUT", mode, self.model, self.runtime_version, str(root), time.monotonic() - started, tuple(raw_events), tool_calls(normalized), forbidden_tool_attempts(normalized), None, None, reason="OpenCode command exceeded the evaluation timeout.", normalized_events=tuple(event.as_dict() for event in normalized), diagnostics=diagnostics)
            combined = f"{stdout}\n{stderr}"
            raw_events = parse_json_events(combined)
            normalized = normalize_events(raw_events)
            (root / "opencode-stdout.log").write_text(stdout, encoding="utf-8")
            (root / "opencode-stderr.log").write_text(stderr, encoding="utf-8")
            (root / "opencode-events.jsonl").write_text("\n".join(json.dumps(item, ensure_ascii=False) for item in raw_events) + ("\n" if raw_events else ""), encoding="utf-8")
            (root / "opencode-events.normalized.jsonl").write_text("\n".join(json.dumps(item.as_dict(), ensure_ascii=False) for item in normalized) + ("\n" if normalized else ""), encoding="utf-8")
            forbidden = forbidden_tool_attempts(normalized)
            media = media_compliance(normalized)
            read_violations = _read_policy_violations(root, normalized)
            configured_model = _configured_model(self.opencode)
            observed_model = _structured_model(raw_events)
            effective_model = observed_model or (configured_model if configured_model == self.model else None)
            error_events = [event for raw, event in zip(raw_events, normalized) if is_error_event(event, raw)]
            structured_error_text = [json.dumps(raw.get("error"), ensure_ascii=False) for raw in raw_events if isinstance(raw, dict) and "error" in raw]
            latest_run = _latest_run(root)
            kslide_complete, contract = _completion_contract(latest_run)
            final_text = next((event.text for event in reversed(normalized) if event.text), None)
            artifact_count = sum(1 for item in (root / ".k-slide-runs").rglob("*") if item.is_file()) if (root / ".k-slide-runs").is_dir() else 0
            if completed_returncode != 0:
                status = "FAILED"
                reason = f"opencode exit code {completed_returncode}"
            elif error_events:
                status = "FAILED"
                reason = f"OpenCode reported {len(error_events)} structured error event(s)."
            elif forbidden:
                status = "FAILED"
                reason = f"Forbidden tool invocation observed: {', '.join(forbidden)}"
            elif read_violations:
                status = "FAILED"
                reason = "Read tool accessed a path outside the K-Slide runtime allowlist."
            elif not kslide_complete:
                status = "FAILED"
                reason = "OpenCode exited successfully without a complete K-Slide run."
            elif mode == "quality" and not load_model_policy(root).approved(requested=self.model, effective=effective_model):
                status = "PROTOCOL_SMOKE_ONLY"
                reason = "Non-target model execution is protocol smoke only."
            else:
                status = "PASS"
                reason = None
            diagnostics = {
                "completion": contract,
                "structured_error_count": len(error_events),
                "structured_error_text": structured_error_text,
                "last_tool_call": normalized[-1].tool_name if normalized else None,
                "read_policy_violations": read_violations,
                "configured_model": configured_model,
                "observed_model": observed_model,
                "effective_model": effective_model,
                "model_identity_proven": effective_model is not None,
            }
            return OpenCodeRunResult(status, mode, self.model, self.runtime_version, str(root), time.monotonic() - started, tuple(raw_events), tool_calls(normalized), forbidden, bool(media.get("read_count")) if media.get("planned") else None, final_text, artifact_count, reason, tuple(event.as_dict() for event in normalized), media, kslide_complete, False, diagnostics)
        finally:
            if root_context is not None:
                root_context.cleanup()
