"""Version-tolerant normalization of OpenCode JSON event streams.

OpenCode emits a small number of stable concepts through version-specific JSON
wrappers.  This module deliberately normalizes only structured event fields;
it never infers tool usage from prompt or log text.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable


FORBIDDEN_TOOL_NAMES = frozenset({"bash", "shell", "edit", "write", "task", "subagent", "webfetch", "websearch"})
_TOOL_EVENT_TYPES = frozenset({"tool", "tool_call", "tool_use", "tool_start", "tool_end", "tool_result", "function_call", "function_result"})
_MEDIA_KEYS = frozenset({"path", "file", "file_path", "filepath", "filePath", "filename"})


@dataclass(frozen=True)
class NormalizedOpenCodeEvent:
    event_type: str
    session_id: str | None = None
    message_id: str | None = None
    role: str | None = None
    tool_name: str | None = None
    tool_call_id: str | None = None
    tool_arguments: dict[str, Any] | None = None
    tool_result: Any = None
    tool_status: str | None = None
    text: str | None = None
    timestamp: str | int | float | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def is_tool_invocation(self) -> bool:
        return bool(self.tool_name)


def parse_json_events(output: str) -> list[dict[str, Any]]:
    """Parse newline-delimited JSON while ignoring human log lines."""

    events: list[dict[str, Any]] = []
    for line in output.splitlines():
        candidate = line.strip()
        if not candidate.startswith("{"):
            continue
        try:
            value = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            events.append(value)
    return events


def _json_value(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def _event_type(value: dict[str, Any]) -> str:
    raw = value.get("type") or value.get("event") or value.get("kind") or "unknown"
    return str(raw).lower().replace("-", "_")


def _candidate_parts(value: dict[str, Any]) -> Iterable[dict[str, Any]]:
    yield value
    for key in ("part", "data", "message", "payload", "event"):
        child = value.get(key)
        if isinstance(child, dict):
            yield child
            state = child.get("state")
            if isinstance(state, dict):
                yield state
    state = value.get("state")
    if isinstance(state, dict):
        yield state


def _tool_candidate(value: dict[str, Any], event_type: str) -> dict[str, Any] | None:
    for part in _candidate_parts(value):
        part_type = str(part.get("type", "")).lower().replace("-", "_")
        if event_type in _TOOL_EVENT_TYPES or part_type in _TOOL_EVENT_TYPES:
            if isinstance(part.get("tool"), str):
                return part
            if isinstance(part.get("tool_name"), str):
                return part
            function = part.get("function")
            if isinstance(function, dict) and isinstance(function.get("name"), str):
                return {**part, "function": function}
    return None


def _tool_name(candidate: dict[str, Any]) -> str | None:
    if isinstance(candidate.get("tool"), str):
        return candidate["tool"]
    if isinstance(candidate.get("tool_name"), str):
        return candidate["tool_name"]
    function = candidate.get("function")
    if isinstance(function, dict) and isinstance(function.get("name"), str):
        return function["name"]
    return None


def _tool_arguments(candidate: dict[str, Any]) -> dict[str, Any] | None:
    value: Any = candidate.get("arguments", candidate.get("args", candidate.get("input")))
    if value is None:
        function = candidate.get("function")
        value = function.get("arguments") if isinstance(function, dict) else None
    if value is None and isinstance(candidate.get("state"), dict):
        state = candidate["state"]
        value = state.get("input", state.get("arguments", state.get("args")))
    if value is None:
        return None
    parsed = _json_value(value)
    return parsed if isinstance(parsed, dict) else {"value": parsed}


def _tool_result(candidate: dict[str, Any]) -> Any:
    if "output" in candidate:
        return _json_value(candidate["output"])
    if "result" in candidate:
        return _json_value(candidate["result"])
    state = candidate.get("state")
    if isinstance(state, dict):
        if "output" in state:
            return _json_value(state["output"])
        if "result" in state:
            return _json_value(state["result"])
    return None


def normalize_event(value: dict[str, Any]) -> NormalizedOpenCodeEvent:
    event_type = _event_type(value)
    candidate = _tool_candidate(value, event_type)
    tool_name = _tool_name(candidate) if candidate else None
    tool_arguments = _tool_arguments(candidate) if candidate else None
    tool_result = _tool_result(candidate) if candidate else None
    status = None
    if candidate:
        raw_status = candidate.get("status")
        if raw_status is None and isinstance(candidate.get("state"), dict):
            raw_status = candidate["state"].get("status")
        status = str(raw_status) if raw_status is not None else None
    text = value.get("text") if isinstance(value.get("text"), str) else None
    if text is None and isinstance(value.get("part"), dict) and isinstance(value["part"].get("text"), str):
        text = value["part"]["text"]
    call_id = None
    if candidate:
        for key in ("callID", "call_id", "id", "tool_call_id"):
            if candidate.get(key) is not None:
                call_id = str(candidate[key])
                break
    return NormalizedOpenCodeEvent(
        event_type=event_type,
        session_id=str(value.get("sessionID", value.get("session_id"))) if value.get("sessionID", value.get("session_id")) is not None else None,
        message_id=str(value.get("messageID", value.get("message_id"))) if value.get("messageID", value.get("message_id")) is not None else None,
        role=str(value.get("role")) if value.get("role") is not None else None,
        tool_name=tool_name,
        tool_call_id=call_id,
        tool_arguments=tool_arguments,
        tool_result=tool_result,
        tool_status=status,
        text=text,
        timestamp=value.get("timestamp") or value.get("time"),
    )


def normalize_events(events: Iterable[dict[str, Any]]) -> tuple[NormalizedOpenCodeEvent, ...]:
    return tuple(normalize_event(item) for item in events)


def tool_calls(events: Iterable[NormalizedOpenCodeEvent]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(event.tool_name for event in events if event.tool_name))


def forbidden_tool_attempts(events: Iterable[NormalizedOpenCodeEvent]) -> tuple[str, ...]:
    return tuple(sorted({event.tool_name for event in events if event.tool_name and event.tool_name.lower() in FORBIDDEN_TOOL_NAMES}))


def _walk(value: Any) -> Iterable[Any]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def _media_plan_from_result(value: Any) -> dict[str, Any] | None:
    for item in _walk(value):
        if isinstance(item, dict) and isinstance(item.get("model_media_plan"), dict):
            return item["model_media_plan"]
    return None


def _media_paths(arguments: dict[str, Any] | None) -> set[str]:
    paths: set[str] = set()
    for item in _walk(arguments or {}):
        if not isinstance(item, dict):
            continue
        for key in _MEDIA_KEYS:
            candidate = item.get(key)
            if isinstance(candidate, str) and ("/" in candidate or "\\" in candidate or Path(candidate).suffix):
                paths.add(candidate.replace("\\", "/"))
    return paths


def actual_read_paths(events: Iterable[NormalizedOpenCodeEvent]) -> tuple[str, ...]:
    """Return paths from actual structured ``read`` invocations only."""

    return tuple(dict.fromkeys(path for event in events if event.tool_name == "read" for path in _media_paths(event.tool_arguments)))


def _same_media_path(actual: str, required: str) -> bool:
    def normalize(path: str) -> str:
        normalized = path.replace("\\", "/")
        while normalized.startswith("./"):
            normalized = normalized[2:]
        return normalized.lstrip("/")

    actual_norm = normalize(actual)
    required_norm = normalize(required)
    # A basename-only match can falsely credit a different crop with the same
    # filename. Absolute tool paths may have a workspace prefix, so accept an
    # exact match or a suffix that preserves the complete relative path.
    return actual_norm == required_norm or actual_norm.endswith("/" + required_norm)


def media_compliance(events: Iterable[NormalizedOpenCodeEvent]) -> dict[str, Any]:
    """Prove image reads from structured ``read`` calls, per work unit."""

    traces = work_unit_media_traces(events)
    units = list(traces.values())
    items = [item for trace in units for item in trace["items"]]
    return {
        "planned": bool(units),
        "required_count": len(items),
        "read_count": sum(bool(item["read_observed"]) for item in items),
        "required_context_image_read": all(trace["required_context_image_read"] for trace in units) if units else False,
        "required_crop_recall": sum(trace["required_crop_recall"] for trace in units) / len(units) if units else 0.0,
        "media_sequence_valid": bool(units) and all(trace["media_sequence_valid"] for trace in units),
        "items": items,
        "evidence_event_count": sum(1 for trace in units if trace["evidence_event_index"] is not None),
        "work_units": traces,
    }


@dataclass
class WorkUnitEventTrace:
    work_unit_id: str
    evidence_event_index: int | None = None
    evidence_revision: str | None = None
    planned_context_path: str | None = None
    planned_crop_paths: tuple[str, ...] = ()
    observed_read_paths: tuple[str, ...] = ()
    submit_event_index: int | None = None
    submit_observed: bool = False
    items: tuple[dict[str, Any], ...] = ()
    forbidden_tool_attempts: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        values = asdict(self)
        values["planned_crop_paths"] = list(self.planned_crop_paths)
        values["observed_read_paths"] = list(self.observed_read_paths)
        values["items"] = list(self.items)
        values["forbidden_tool_attempts"] = list(self.forbidden_tool_attempts)
        required_crops = [item for item in self.items if item["id"] != "context_image"]
        return {
            **values,
            "required_context_image_read": next((item["read_observed"] for item in self.items if item["id"] == "context_image"), False),
            "required_crop_recall": sum(item["read_observed"] for item in required_crops) / max(1, len(required_crops)),
            "media_sequence_valid": bool(self.items) and self.submit_observed and all(item["read_observed"] and item["read_before_submit"] for item in self.items),
        }


def _object_payload(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def _payload_field(event: NormalizedOpenCodeEvent, key: str) -> Any:
    for payload in (_object_payload(event.tool_arguments), _object_payload(event.tool_result)):
        if key in payload:
            return payload[key]
    return None


def _unit_from_event(event: NormalizedOpenCodeEvent) -> str | None:
    value = _payload_field(event, "work_unit_id")
    return str(value) if isinstance(value, str) and value else None


def work_unit_media_traces(events: Iterable[NormalizedOpenCodeEvent]) -> dict[str, dict[str, Any]]:
    """Bind each evidence/read/submit sequence to its structured work-unit ID."""

    normalized = list(events)
    traces: dict[str, WorkUnitEventTrace] = {}
    current_unit: str | None = None
    read_events: list[tuple[int, str]] = []
    for index, event in enumerate(normalized):
        event_unit = _unit_from_event(event)
        if event.tool_name == "kslide_next" and event_unit:
            current_unit = event_unit
        if event.tool_name == "kslide_evidence":
            current_unit = event_unit or current_unit or "__unbound__"
            plan = _media_plan_from_result(event.tool_result) or {}
            context = plan.get("context_image") or {}
            crops = tuple(str(item["path"]) for item in plan.get("required_crops", []) if isinstance(item, dict) and item.get("path"))
            required: list[dict[str, Any]] = []
            if context.get("required") and context.get("path"):
                required.append({"id": "context_image", "path": str(context["path"])})
            required.extend({"id": str(item.get("region_id", item["path"])), "path": str(item["path"])} for item in plan.get("required_crops", []) if isinstance(item, dict) and item.get("path"))
            traces[current_unit] = WorkUnitEventTrace(
                work_unit_id=current_unit,
                evidence_event_index=index,
                evidence_revision=_payload_field(event, "evidence_revision"),
                planned_context_path=str(context["path"]) if context.get("path") else None,
                planned_crop_paths=crops,
                items=tuple({"id": item["id"], "path": item["path"], "planned": True, "read_observed": False, "read_before_submit": False} for item in required),
            )
        if event.tool_name == "read":
            read_events.extend((index, path) for path in _media_paths(event.tool_arguments))
        if event.tool_name == "kslide_submit":
            current_unit = event_unit or current_unit or "__unbound__"
            prior = traces.get(current_unit)
            if prior:
                traces[current_unit] = WorkUnitEventTrace(**{**asdict(prior), "submit_event_index": index, "submit_observed": True})
    result: dict[str, dict[str, Any]] = {}
    for unit_id, trace in traces.items():
        evidence_index = trace.evidence_event_index
        submit_index = trace.submit_event_index
        scoped_reads = [(index, path) for index, path in read_events if evidence_index is not None and index > evidence_index and (submit_index is None or index < submit_index)]
        items: list[dict[str, Any]] = []
        for item in trace.items:
            matching = [index for index, actual in scoped_reads if _same_media_path(actual, item["path"])]
            read_index = min(matching) if matching else None
            items.append({**item, "read_observed": read_index is not None, "read_before_submit": read_index is not None and submit_index is not None and read_index < submit_index})
        observed = tuple(path for _, path in scoped_reads)
        scope_start = evidence_index if evidence_index is not None else 0
        scope_end = submit_index + 1 if submit_index is not None else len(normalized)
        scoped_events = normalized[scope_start:scope_end]
        completed = WorkUnitEventTrace(
            **{
                **asdict(trace),
                "observed_read_paths": observed,
                "items": tuple(items),
                "forbidden_tool_attempts": tuple(sorted(set(forbidden_tool_attempts(scoped_events)))),
            }
        )
        result[unit_id] = completed.as_dict()
    return result


def is_error_event(event: NormalizedOpenCodeEvent, raw: dict[str, Any] | None = None) -> bool:
    if event.event_type in {"error", "fatal", "failure"}:
        return True
    return isinstance(raw, dict) and isinstance(raw.get("error"), (str, dict, list))
