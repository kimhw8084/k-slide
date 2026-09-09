"""Persisted multi-work-unit queue with optimistic per-unit revisions."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from . import RUN_STATE_SCHEMA_VERSION
from .errors import ErrorCode, KSlideError
from .evidence_ir import stable_revision
from .io import atomic_write_json, read_json


class WorkUnitStatus(str, Enum):
    PENDING = "PENDING"
    NORMALIZED = "NORMALIZED"
    EXTRACTED = "EXTRACTED"
    READY = "READY"
    TRANSLATING = "TRANSLATING"
    TRANSLATED = "TRANSLATED"
    VERIFY_FAILED = "VERIFY_FAILED"
    REPAIRING = "REPAIRING"
    VERIFIED = "VERIFIED"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    FAILED = "FAILED"


@dataclass
class WorkUnit:
    work_unit_id: str
    document_id: str
    source_input_id: str
    source_index: int
    kind: str = "slide"
    status: WorkUnitStatus = WorkUnitStatus.PENDING
    evidence_revision: str | None = None
    translation_revision: str | None = None
    canonical_ir_sha256: str | None = None
    translation_attempts: int = 0
    repair_attempts: int = 0
    verification_status: str = "NOT_RUN"
    revision: int = 0
    created_at: str = ""
    updated_at: str = ""

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["status"] = self.status.value
        return value


@dataclass
class WorkQueue:
    run_id: str
    work_units: list[WorkUnit] = field(default_factory=list)
    queue_revision: str = ""
    schema_version: str = RUN_STATE_SCHEMA_VERSION

    def without_revision(self) -> dict[str, Any]:
        return {"schema_version": self.schema_version, "run_id": self.run_id, "work_units": [unit.as_dict() for unit in self.work_units]}

    def computed_revision(self) -> str:
        return stable_revision(self.without_revision())

    def as_dict(self) -> dict[str, Any]:
        value = self.without_revision()
        value["queue_revision"] = self.queue_revision or self.computed_revision()
        return value

    def refresh_revision(self) -> None:
        self.queue_revision = self.computed_revision()

    def get(self, work_unit_id: str) -> WorkUnit:
        for unit in self.work_units:
            if unit.work_unit_id == work_unit_id:
                return unit
        raise KSlideError(ErrorCode.UNKNOWN_WORK_UNIT, "Work unit does not exist.", {"work_unit_id": work_unit_id})

    def next_unit(self) -> tuple[str, WorkUnit | None]:
        for unit in self.work_units:
            if unit.status is WorkUnitStatus.READY:
                return "READY", unit
        for unit in self.work_units:
            if unit.status in {WorkUnitStatus.VERIFY_FAILED, WorkUnitStatus.REPAIRING}:
                return "REPAIR_READY", unit
        if any(unit.status == WorkUnitStatus.NEEDS_REVIEW for unit in self.work_units):
            return "NEEDS_REVIEW", None
        if all(unit.status in {WorkUnitStatus.TRANSLATED, WorkUnitStatus.VERIFIED} for unit in self.work_units) and self.work_units:
            return "ALL_TRANSLATED", None
        return "NOT_READY", None


def queue_path(run_dir: Path) -> Path:
    return run_dir / "WORK_QUEUE.json"


def save_queue(run_dir: Path, queue: WorkQueue) -> None:
    validate_queue(queue)
    queue.refresh_revision()
    atomic_write_json(queue_path(run_dir), queue.as_dict(), mode=0o600)


def validate_queue(queue: WorkQueue) -> None:
    from .errors import ErrorCode

    work_ids = [unit.work_unit_id for unit in queue.work_units]
    if len(work_ids) != len(set(work_ids)):
        raise KSlideError(ErrorCode.DUPLICATE_WORK_UNIT_ID, "Work queue contains duplicate work-unit IDs.", {"work_unit_ids": work_ids})
    if not queue.run_id:
        raise KSlideError(ErrorCode.STATE_CORRUPT, "Work queue has no run ID.")


def load_queue(run_dir: Path) -> WorkQueue:
    value = read_json(queue_path(run_dir))
    if not isinstance(value, dict):
        raise KSlideError(ErrorCode.STATE_CORRUPT, "WORK_QUEUE.json must contain an object.")
    units = []
    for item in value.get("work_units", []):
        item = dict(item)
        item["status"] = WorkUnitStatus(str(item.get("status", "PENDING")))
        units.append(WorkUnit(**item))
    queue = WorkQueue(run_id=str(value["run_id"]), work_units=units, queue_revision=str(value.get("queue_revision", "")), schema_version=str(value.get("schema_version", RUN_STATE_SCHEMA_VERSION)))
    validate_queue(queue)
    if queue.queue_revision and queue.queue_revision != queue.computed_revision():
        raise KSlideError(ErrorCode.STATE_CORRUPT, "WORK_QUEUE.json revision does not match its contents.")
    return queue


def create_queue(run_id: str, *, input_count: int, now: str) -> WorkQueue:
    units = [WorkUnit(work_unit_id=f"doc-{index:03d}-input-{index:04d}", document_id=f"doc-{index:03d}", source_input_id=f"source-{index:03d}", source_index=index - 1, kind="input", created_at=now, updated_at=now) for index in range(1, input_count + 1)]
    queue = WorkQueue(run_id=run_id, work_units=units)
    validate_queue(queue)
    queue.refresh_revision()
    return queue
