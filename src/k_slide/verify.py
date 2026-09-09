"""Deterministic validation, stale-state detection, and completion ownership."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from . import VERIFICATION_SCHEMA_VERSION
from .completion import ensure_completion_artifacts
from .errors import ErrorCode, KSlideError
from .evidence_ir import load_evidence
from .io import atomic_write_json, atomic_write_text, read_json
from .ir import SlideIR
from .locking import run_lock
from .policy import COMPLETION_POLICY
from .queue import WorkQueue, WorkUnitStatus, load_queue, save_queue
from .security import sha256_file
from .state import RunPhase, load_state, save_state


class Severity(str, Enum):
    INFO = "INFO"
    MINOR = "MINOR"
    MAJOR = "MAJOR"
    CRITICAL = "CRITICAL"


@dataclass
class VerificationIssue:
    code: str
    severity: Severity
    message: str
    target: str | None = None
    evidence_ids: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["severity"] = self.severity.value
        return value


@dataclass
class VerificationResult:
    status: str
    run_id: str
    issues: list[VerificationIssue] = field(default_factory=list)
    checked_slides: int = 0
    checked_regions: int = 0
    checked_work_units: int = 0
    critical_count: int = 0
    unaccounted_count: int = 0
    queue_revision: str | None = None

    @property
    def passed(self) -> bool:
        return self.status == "PASS" and self.critical_count == 0 and self.unaccounted_count == 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": VERIFICATION_SCHEMA_VERSION,
            "status": self.status,
            "run_id": self.run_id,
            "issues": [issue.as_dict() for issue in self.issues],
            "checked_slides": self.checked_slides,
            "checked_regions": self.checked_regions,
            "checked_work_units": self.checked_work_units,
            "critical_count": self.critical_count,
            "unaccounted_count": self.unaccounted_count,
            "queue_revision": self.queue_revision,
        }


def _issue(result: VerificationResult, code: str, severity: Severity, message: str, *, target: str | None = None, evidence_ids: list[str] | None = None) -> None:
    result.issues.append(VerificationIssue(code, severity, message, target, evidence_ids or []))
    if severity is Severity.CRITICAL:
        result.critical_count += 1


def _validate_slide(run_dir: Path, work_unit_id: str, result: VerificationResult) -> None:
    path = run_dir / "ir" / f"{work_unit_id}.json"
    try:
        value = read_json(path)
        if not isinstance(value, dict) or value.get("schema_version") != "1.0":
            _issue(result, "KSLIDE_SCHEMA_INVALID", Severity.CRITICAL, "SlideIR schema version is missing or unsupported.", target=work_unit_id)
            return
        slide = SlideIR.from_dict(value)
        evidence = load_evidence(run_dir, work_unit_id)
        result.checked_slides += 1
        result.checked_regions += len(slide.regions)
        if slide.evidence_revision != evidence.evidence_revision:
            _issue(result, ErrorCode.STALE_EVIDENCE.value, Severity.CRITICAL, "SlideIR is linked to a stale EvidenceIR revision.", target=work_unit_id)
        source_regions = {region.region_id for region in evidence.regions}
        translated_regions = {region.region_id for region in slide.regions}
        missing = sorted(source_regions - translated_regions)
        if missing:
            result.unaccounted_count += len(missing)
            _issue(result, "KSLIDE_EVIDENCE_COVERAGE_GAP", Severity.CRITICAL, "Canonical SlideIR omitted engine-defined source regions.", target=work_unit_id, evidence_ids=missing)
        coverage_ids = {entry.source_id for entry in slide.coverage}
        missing_coverage = sorted(set(evidence.required_source_ids) - coverage_ids)
        if missing_coverage:
            result.unaccounted_count += len(missing_coverage)
            _issue(result, "KSLIDE_COVERAGE_GAP", Severity.CRITICAL, "Canonical coverage does not account for required engine evidence.", target=work_unit_id, evidence_ids=missing_coverage)
        for table in slide.tables:
            if table.row_count < 1 or table.column_count < 1:
                _issue(result, "KSLIDE_TABLE_SHAPE_INVALID", Severity.CRITICAL, "Table dimensions must be positive.", target=table.table_id)
            for cell in table.cells:
                if cell.row < 0 or cell.column < 0 or cell.row >= table.row_count or cell.column >= table.column_count:
                    _issue(result, "KSLIDE_TABLE_CELL_OUT_OF_RANGE", Severity.CRITICAL, "Table cell is outside declared dimensions.", target=table.table_id)
        for item in slide.unresolved:
            if not item.get("reason") and not item.get("unresolved_reason"):
                _issue(result, "KSLIDE_UNRESOLVED_UNDISCLOSED", Severity.CRITICAL, "Unresolved evidence lacks a reason.", target=work_unit_id)
    except (KSlideError, KeyError, TypeError, ValueError, json.JSONDecodeError, OSError) as exc:
        _issue(result, "KSLIDE_SCHEMA_INVALID", Severity.CRITICAL, f"Could not validate SlideIR: {exc}", target=work_unit_id)


def _verify_unlocked(run_dir: Path) -> VerificationResult:
    state = load_state(run_dir)
    result = VerificationResult(status="PASS", run_id=state.run_id)
    try:
        queue = load_queue(run_dir)
        result.queue_revision = queue.queue_revision
    except (KSlideError, OSError) as exc:
        _issue(result, "KSLIDE_WORK_QUEUE_INVALID", Severity.CRITICAL, str(exc), target="WORK_QUEUE.json")
        queue = WorkQueue(run_id=state.run_id)
    result.checked_work_units = len(queue.work_units)
    if not queue.work_units:
        _issue(result, "KSLIDE_NO_WORK_UNITS", Severity.CRITICAL, "No engine-defined work units exist.")
    for unit in queue.work_units:
        if unit.status in {WorkUnitStatus.TRANSLATED, WorkUnitStatus.VERIFIED, WorkUnitStatus.NEEDS_REVIEW}:
            if not (run_dir / "ir" / f"{unit.work_unit_id}.json").is_file():
                _issue(result, "KSLIDE_IR_MISSING", Severity.CRITICAL, "Translated work unit has no canonical SlideIR.", target=unit.work_unit_id)
            else:
                if unit.canonical_ir_sha256 and sha256_file(run_dir / "ir" / f"{unit.work_unit_id}.json") != unit.canonical_ir_sha256:
                    _issue(result, "KSLIDE_CANONICAL_IR_CHANGED", Severity.CRITICAL, "Canonical SlideIR changed after engine merge.", target=unit.work_unit_id)
                _validate_slide(run_dir, unit.work_unit_id, result)
        elif unit.status not in {WorkUnitStatus.PENDING, WorkUnitStatus.NORMALIZED, WorkUnitStatus.EXTRACTED}:
            _issue(result, "KSLIDE_WORK_UNIT_INCOMPLETE", Severity.CRITICAL, "Work unit is not translated or explicitly reviewable.", target=unit.work_unit_id)
    # 06_verification.md is generated by this verifier, so it cannot be a
    # prerequisite for the verifier that writes it. The remaining artifacts
    # must already exist before a run can pass.
    missing = [name for name in COMPLETION_POLICY.precompletion_artifacts if name != "06_verification.md" and not (run_dir / name).is_file()]
    for name in missing:
        _issue(result, "KSLIDE_REQUIRED_ARTIFACT_MISSING", Severity.CRITICAL, "Required pre-completion artifact is missing.", target=name)
    result.status = "PASS" if not result.issues else "FAIL"
    return result


def _persist_verification(run_dir: Path, result: VerificationResult) -> None:
    atomic_write_json(run_dir / "verification" / "summary.json", result.as_dict(), mode=0o600)
    lines = ["# K-Slide Verification", "", f"Status: **{result.status}**", f"Run: `{result.run_id}`", "", f"Work units checked: {result.checked_work_units}", f"Critical issues: {result.critical_count}", f"Unaccounted source items: {result.unaccounted_count}"]
    if result.issues:
        lines.extend(["", "## Issues"])
        lines.extend(f"- **{issue.severity.value}** `{issue.code}`: {issue.message}" + (f" (`{issue.target}`)" if issue.target else "") for issue in result.issues)
    lines.extend(["", "## Completion policy", "", f"Policy version: `{COMPLETION_POLICY.version}`", "", "`RUN_COMPLETE.md` is created only by deterministic finalization after current verification passes.", ""])
    atomic_write_text(run_dir / "06_verification.md", "\n".join(lines))


def verify_run(run_dir: Path) -> VerificationResult:
    with run_lock(run_dir):
        state = load_state(run_dir)
        if state.phase == RunPhase.COMPLETE:
            sentinel = run_dir / "RUN_COMPLETE.md"
            sentinel.unlink(missing_ok=True)
            state.transition(RunPhase.VERIFYING, next_action="Re-verifying current artifacts")
            save_state(run_dir, state)
        elif state.phase in {RunPhase.TRANSLATED, RunPhase.TRANSLATING, RunPhase.REPAIRING, RunPhase.NEEDS_REVIEW, RunPhase.VERIFIED}:
            if state.phase != RunPhase.VERIFYING:
                state.transition(RunPhase.VERIFYING, next_action="Deterministic verification in progress")
                save_state(run_dir, state)
        else:
            result = VerificationResult(status="FAIL", run_id=state.run_id)
            _issue(result, "KSLIDE_PHASE_NOT_VERIFIABLE", Severity.CRITICAL, "Run is not in a translation/verification phase.", target=state.phase.value)
            _persist_verification(run_dir, result)
            return result
        result = _verify_unlocked(run_dir)
        try:
            queue = load_queue(run_dir)
            for unit in queue.work_units:
                if unit.status in {WorkUnitStatus.TRANSLATED, WorkUnitStatus.VERIFIED}:
                    unit.verification_status = "PASS" if result.passed else "FAIL"
                    unit.status = WorkUnitStatus.VERIFIED if result.passed else WorkUnitStatus.VERIFY_FAILED
                    unit.revision += 1
            save_queue(run_dir, queue)
        except (KSlideError, OSError):
            pass
        if result.passed:
            state.transition(RunPhase.VERIFIED, next_action="Finalize after current verification")
        else:
            state.transition(RunPhase.FAIL_REPAIRABLE, next_action="Repair exact verification targets")
        save_state(run_dir, state)
        _persist_verification(run_dir, result)
        return result


def finalize_run(run_dir: Path) -> VerificationResult:
    with run_lock(run_dir):
        state = load_state(run_dir)
        if state.phase == RunPhase.COMPLETE:
            (run_dir / "RUN_COMPLETE.md").unlink(missing_ok=True)
            state.transition(RunPhase.VERIFYING, next_action="Re-verifying current artifacts")
            save_state(run_dir, state)
        elif state.phase != RunPhase.VERIFYING:
            state.transition(RunPhase.VERIFYING, next_action="Re-verifying current artifacts")
            save_state(run_dir, state)
        result = _verify_unlocked(run_dir)
        _persist_verification(run_dir, result)
        if not result.passed:
            state = load_state(run_dir)
            state.transition(RunPhase.FAIL_REPAIRABLE, next_action="Repair exact verification targets")
            save_state(run_dir, state)
            raise KSlideError(ErrorCode.COMPLETION_BLOCKED, "K-Slide cannot finalize because current deterministic verification has not passed.", {"verification": result.as_dict()})
        ensure_completion_artifacts(run_dir, include_sentinel=False)
        atomic_write_text(run_dir / "RUN_COMPLETE.md", "# DONE\n\nK-Slide deterministic verification passed against the current artifacts.\n")
        missing = COMPLETION_POLICY.missing(run_dir, include_sentinel=True)
        if missing:
            raise KSlideError(ErrorCode.COMPLETION_BLOCKED, "Completion artifacts are incomplete.", {"missing": missing})
        state = load_state(run_dir)
        state.transition(RunPhase.VERIFIED, next_action="Create deterministic completion sentinel")
        state.transition(RunPhase.COMPLETE, next_action=None)
        save_state(run_dir, state)
        return result


# Kept as a narrow compatibility validator for callers that still import the v0.1 name.
def validate_translation_payload(value: dict[str, Any]) -> None:
    from .translation import parse_translation_patch

    parse_translation_patch(value)


def canonicalize_translation_payload(value: dict[str, Any]) -> dict[str, Any]:
    """Compatibility shim: return only the validated model patch, never canonical source state."""

    from .translation import parse_translation_patch

    return parse_translation_patch(value).as_dict()
