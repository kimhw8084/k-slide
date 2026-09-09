"""OpenCode command/session protocol runner for K-Slide evaluation.

The runner deliberately treats a non-Gemma model as protocol smoke only. It
can exercise command discovery, tools, permissions, and artifact lifecycle, but
it never contributes linguistic quality metrics to Gemma certification.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


FORBIDDEN_TOOL_NAMES = ("bash", "edit", "write", "task", "webfetch", "websearch")


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
            "final_text": self.final_text,
            "run_artifact_count": self.run_artifact_count,
            "reason": self.reason,
        }


def _version(opencode: str) -> str | None:
    try:
        result = subprocess.run([opencode, "--version"], capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return (result.stdout or result.stderr).strip() or None


def _json_events(output: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            events.append(value)
    return events


def _walk(value: Any):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


class OpenCodeEvalRunner:
    """Run the real OpenCode CLI command in an isolated evaluation workspace."""

    def __init__(self, *, model: str, timeout_seconds: int = 180, opencode: str | None = None):
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.opencode = opencode or shutil.which("opencode")

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
        input_dir = root / ".k-slide-input"
        input_dir.mkdir(parents=True, exist_ok=True)
        if source is not None:
            shutil.copy2(source, input_dir / source.name)
        try:
            # Install the repository under test into the isolated workspace so
            # command/agent/tool discovery is part of the E2E result.
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
            completed = subprocess.run(self.command(root), cwd=root, env=env, capture_output=True, text=True, timeout=self.timeout_seconds, check=False)
            combined = f"{completed.stdout}\n{completed.stderr}"
            (root / "opencode-stdout.log").write_text(completed.stdout, encoding="utf-8")
            (root / "opencode-stderr.log").write_text(completed.stderr, encoding="utf-8")
            events = _json_events(combined)
            (root / "opencode-events.jsonl").write_text("\n".join(json.dumps(item, ensure_ascii=False) for item in events) + ("\n" if events else ""), encoding="utf-8")
            serialized = combined.lower()
            tool_calls: list[str] = []
            media_read = False
            for event in events:
                for item in _walk(event):
                    for key in ("tool", "tool_name", "name"):
                        if isinstance(item.get(key), str) and item[key] not in {"message", "session"}:
                            value = item[key]
                            if value not in tool_calls:
                                tool_calls.append(value)
                    if any(token in json.dumps(item, ensure_ascii=False).lower() for token in ("context_image", "required_crops", ".k-slide-runs/", "regions/")):
                        media_read = True
            forbidden = tuple(sorted({name for name in FORBIDDEN_TOOL_NAMES if name in serialized}))
            error_events = [item for item in events if item.get("type") == "error" or "error" in item]
            final_text = None
            if events:
                candidates = [item.get("text") for item in events if isinstance(item.get("text"), str)]
                final_text = candidates[-1] if candidates else None
            status = "PASS" if completed.returncode == 0 and not error_events else "FAILED"
            if mode == "quality" and "gemma-4-31b-it" not in self.model.lower():
                status = "PROTOCOL_SMOKE_ONLY"
            reason = None if status == "PASS" else (f"OpenCode reported {len(error_events)} error event(s)." if error_events else f"opencode exit code {completed.returncode}")
            artifact_count = sum(1 for item in (root / ".k-slide-runs").rglob("*") if item.is_file()) if (root / ".k-slide-runs").is_dir() else 0
            return OpenCodeRunResult(status, mode, self.model, self.runtime_version, str(root), time.monotonic() - started, tuple(events), tuple(tool_calls), forbidden, media_read if events else None, final_text, artifact_count, reason)
        except subprocess.TimeoutExpired:
            return OpenCodeRunResult("TIMEOUT", mode, self.model, self.runtime_version, str(root), time.monotonic() - started, (), (), (), None, None, reason="OpenCode command exceeded the evaluation timeout.")
        finally:
            if root_context is not None:
                root_context.cleanup()
