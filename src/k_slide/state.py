"""Validated K-Slide run state and atomic transitions."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from . import RUN_STATE_SCHEMA_VERSION
from .errors import ErrorCode, KSlideError
from .io import atomic_write_json, read_json


class RunPhase(str, Enum):
    CREATED = "CREATED"
    INPUT_VALIDATED = "INPUT_VALIDATED"
    NORMALIZING = "NORMALIZING"
    NORMALIZED = "NORMALIZED"
    EXTRACTING = "EXTRACTING"
    EXTRACTED = "EXTRACTED"
    TRANSLATING = "TRANSLATING"
    TRANSLATED = "TRANSLATED"
    VERIFYING = "VERIFYING"
    FAIL_REPAIRABLE = "FAIL_REPAIRABLE"
    REPAIRING = "REPAIRING"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    VERIFIED = "VERIFIED"
    COMPLETE = "COMPLETE"
    FAILED_INPUT = "FAILED_INPUT"
    FAILED_RUNTIME = "FAILED_RUNTIME"
    FAILED_NORMALIZATION = "FAILED_NORMALIZATION"
    FAILED_EXTRACTION = "FAILED_EXTRACTION"
    FAILED_SCHEMA = "FAILED_SCHEMA"
    FAILED_INTERNAL = "FAILED_INTERNAL"


_ALLOWED: dict[RunPhase, set[RunPhase]] = {
    RunPhase.CREATED: {RunPhase.INPUT_VALIDATED, RunPhase.FAILED_INPUT, RunPhase.FAILED_RUNTIME},
    RunPhase.INPUT_VALIDATED: {RunPhase.NORMALIZING, RunPhase.NORMALIZED, RunPhase.FAILED_NORMALIZATION, RunPhase.FAILED_RUNTIME},
    RunPhase.NORMALIZING: {RunPhase.NORMALIZED, RunPhase.FAILED_NORMALIZATION, RunPhase.FAILED_RUNTIME},
    RunPhase.NORMALIZED: {RunPhase.EXTRACTING, RunPhase.EXTRACTED, RunPhase.FAILED_EXTRACTION, RunPhase.FAILED_RUNTIME},
    RunPhase.EXTRACTING: {RunPhase.EXTRACTED, RunPhase.FAILED_EXTRACTION, RunPhase.FAILED_RUNTIME},
    RunPhase.EXTRACTED: {RunPhase.TRANSLATING, RunPhase.FAILED_RUNTIME},
    RunPhase.TRANSLATING: {RunPhase.TRANSLATING, RunPhase.TRANSLATED, RunPhase.VERIFYING, RunPhase.REPAIRING, RunPhase.FAIL_REPAIRABLE, RunPhase.NEEDS_REVIEW, RunPhase.FAILED_SCHEMA},
    RunPhase.TRANSLATED: {RunPhase.TRANSLATING, RunPhase.VERIFYING, RunPhase.FAILED_SCHEMA},
    RunPhase.VERIFYING: {RunPhase.VERIFIED, RunPhase.FAIL_REPAIRABLE, RunPhase.NEEDS_REVIEW, RunPhase.FAILED_INTERNAL},
    RunPhase.FAIL_REPAIRABLE: {RunPhase.REPAIRING, RunPhase.NEEDS_REVIEW},
    RunPhase.REPAIRING: {RunPhase.TRANSLATING, RunPhase.VERIFYING, RunPhase.NEEDS_REVIEW, RunPhase.FAILED_SCHEMA},
    RunPhase.NEEDS_REVIEW: {RunPhase.REPAIRING, RunPhase.VERIFYING, RunPhase.FAILED_SCHEMA},
    RunPhase.VERIFIED: {RunPhase.COMPLETE, RunPhase.REPAIRING, RunPhase.VERIFYING, RunPhase.NEEDS_REVIEW},
    RunPhase.COMPLETE: {RunPhase.VERIFYING, RunPhase.REPAIRING, RunPhase.COMPLETE},
}

_TERMINAL = {
    RunPhase.COMPLETE,
    RunPhase.FAILED_INPUT,
    RunPhase.FAILED_RUNTIME,
    RunPhase.FAILED_NORMALIZATION,
    RunPhase.FAILED_EXTRACTION,
    RunPhase.FAILED_SCHEMA,
    RunPhase.FAILED_INTERNAL,
}


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass
class RunState:
    run_id: str
    mode: str
    phase: RunPhase = RunPhase.CREATED
    session_key: str | None = None
    input_count: int = 0
    current_work_unit: str | None = None
    next_action: str | None = None
    error_code: str | None = None
    error_message: str | None = None
    repair_attempts: int = 0
    revision: int = 0
    schema_version: str = RUN_STATE_SCHEMA_VERSION
    created_at: str = field(default_factory=now_utc)
    updated_at: str = field(default_factory=now_utc)

    @property
    def terminal(self) -> bool:
        return self.phase in _TERMINAL

    def transition(
        self,
        target: RunPhase,
        *,
        next_action: str | None = None,
        error_code: str | None = None,
        error_message: str | None = None,
    ) -> None:
        if target == self.phase:
            self.updated_at = now_utc()
            return
        if target not in _ALLOWED.get(self.phase, set()):
            raise KSlideError(
                ErrorCode.INVALID_TRANSITION,
                f"Cannot move run from {self.phase.value} to {target.value}.",
                {"run_id": self.run_id, "from": self.phase.value, "to": target.value},
            )
        self.phase = target
        self.next_action = next_action
        self.error_code = error_code
        self.error_message = error_message
        self.updated_at = now_utc()

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "mode": self.mode,
            "phase": self.phase.value,
            "status": self.phase.value,
            "session_key": self.session_key,
            "input_count": self.input_count,
            "current_work_unit": self.current_work_unit,
            "next_action": self.next_action,
            "error_code": self.error_code,
            "error_message": self.error_message,
            "repair_attempts": self.repair_attempts,
            "revision": self.revision,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RunState":
        try:
            return cls(
                run_id=str(data["run_id"]),
                mode=str(data["mode"]),
                phase=RunPhase(str(data.get("phase", data.get("status")))),
                session_key=data.get("session_key"),
                input_count=int(data.get("input_count", 0)),
                current_work_unit=data.get("current_work_unit"),
                next_action=data.get("next_action"),
                error_code=data.get("error_code"),
                error_message=data.get("error_message"),
                repair_attempts=int(data.get("repair_attempts", 0)),
                revision=int(data.get("revision", 0)),
                schema_version=str(data.get("schema_version", RUN_STATE_SCHEMA_VERSION)),
                created_at=str(data.get("created_at", now_utc())),
                updated_at=str(data.get("updated_at", now_utc())),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise KSlideError(ErrorCode.STATE_CORRUPT, "RUN_STATE.json has an invalid shape.") from exc


def state_path(run_dir: Path) -> Path:
    return run_dir / "RUN_STATE.json"


def save_state(run_dir: Path, state: RunState) -> None:
    state.revision += 1
    atomic_write_json(state_path(run_dir), state.as_dict(), mode=0o600)


def load_state(run_dir: Path) -> RunState:
    path = state_path(run_dir)
    if not path.is_file():
        raise KSlideError(ErrorCode.STATE_CORRUPT, "RUN_STATE.json is missing.", {"run_dir": str(run_dir)})
    value = read_json(path)
    if not isinstance(value, dict):
        raise KSlideError(ErrorCode.STATE_CORRUPT, "RUN_STATE.json must contain an object.")
    return RunState.from_dict(value)
