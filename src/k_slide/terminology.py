"""Versioned termbase loading and locked/preferred terminology checks."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import ErrorCode, KSlideError


VALID_STATUSES = {"LOCKED", "PREFERRED", "DO_NOT_TRANSLATE", "SUGGESTED"}


@dataclass(frozen=True)
class TermRecord:
    source: str
    preferred: dict[str, str]
    status: str = "SUGGESTED"
    scope: tuple[str, ...] = ()
    avoid: tuple[str, ...] = ()
    term_id: str | None = None

    @property
    def default(self) -> str | None:
        return self.preferred.get("default") or next(iter(self.preferred.values()), None)

    def as_dict(self) -> dict[str, Any]:
        return {"source": self.source, "preferred": self.preferred, "status": self.status, "scope": list(self.scope), "avoid": list(self.avoid), "term_id": self.term_id}


@dataclass(frozen=True)
class Termbase:
    version: str
    records: tuple[TermRecord, ...] = ()
    origin: str = "core"

    def resolve(self, source: str) -> TermRecord | None:
        candidates = [record for record in self.records if record.source == source]
        return max(candidates, key=lambda record: len(record.source), default=None)

    def as_dict(self) -> dict[str, Any]:
        return {"version": self.version, "origin": self.origin, "records": [record.as_dict() for record in self.records]}


def _parse_records(value: Any, *, origin: str) -> Termbase:
    if not isinstance(value, dict):
        raise KSlideError(ErrorCode.SCHEMA_INVALID, "Termbase must be an object.", {"origin": origin})
    records_value = value.get("records", value.get("terms", []))
    if not isinstance(records_value, list):
        raise KSlideError(ErrorCode.SCHEMA_INVALID, "Termbase records must be an array.", {"origin": origin})
    records: list[TermRecord] = []
    seen: set[str] = set()
    for item in records_value:
        if not isinstance(item, dict) or not isinstance(item.get("source"), str) or not item["source"].strip():
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "Termbase record needs a non-empty source key.", {"origin": origin})
        source = item["source"]
        if source in seen:
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "Termbase contains duplicate source keys.", {"source": source, "origin": origin})
        seen.add(source)
        preferred = item.get("preferred", {})
        if isinstance(preferred, str):
            preferred = {"default": preferred}
        if not isinstance(preferred, dict) or not preferred or any(not isinstance(key, str) or not isinstance(target, str) or not target.strip() for key, target in preferred.items()):
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "Termbase preferred translations must be non-empty strings.", {"source": source, "origin": origin})
        status = str(item.get("status", "SUGGESTED")).upper()
        if status not in VALID_STATUSES:
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "Termbase status is invalid.", {"source": source, "status": status})
        records.append(TermRecord(source, dict(preferred), status, tuple(item.get("scope", [])), tuple(item.get("avoid", [])), item.get("term_id")))
    return Termbase(str(value.get("version", "1.0")), tuple(records), origin)


def load_termbase(path: Path) -> Termbase:
    try:
        if path.suffix.lower() in {".yaml", ".yml"}:
            try:
                import yaml  # type: ignore
            except ImportError as exc:
                raise KSlideError(ErrorCode.SCHEMA_INVALID, "PyYAML is required to read YAML termbases.", {"path": str(path)}) from exc
            value = yaml.safe_load(path.read_text(encoding="utf-8"))
        else:
            value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise KSlideError(ErrorCode.SCHEMA_INVALID, "Termbase could not be read.", {"path": str(path), "reason": str(exc)}) from exc
    return _parse_records(value, origin=str(path))


def merge_termbases(*termbases: Termbase) -> Termbase:
    merged: dict[str, TermRecord] = {}
    for termbase in termbases:
        for record in termbase.records:
            existing = merged.get(record.source)
            if existing and existing.status == "LOCKED" and record.status == "LOCKED" and existing.default != record.default:
                raise KSlideError(ErrorCode.SCHEMA_INVALID, "Conflicting locked terminology records.", {"source": record.source, "left": existing.default, "right": record.default})
            merged[record.source] = record
    return Termbase("+".join(termbase.version for termbase in termbases if termbase.version) or "1.0", tuple(merged.values()), "merged")


def load_effective_termbase(project_root: Path, *, run_override: Path | None = None) -> Termbase:
    paths = [Path(__file__).resolve().parents[2] / "termbase" / "core.json"]
    private = run_override or project_root / ".k-slide-config" / "termbase.local.json"
    if private.is_file():
        paths.append(private)
    loaded = [load_termbase(path) for path in paths if path.is_file()]
    return merge_termbases(*loaded) if loaded else Termbase("1.0", (), "empty")
