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
    binding_identity: dict[str, Any] | None = None

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
        scope = item.get("scope", [])
        avoid = item.get("avoid", [])
        if not isinstance(scope, (list, tuple)) or any(not isinstance(entry, str) or not entry.strip() for entry in scope):
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "Termbase record scope metadata is invalid.", {"source": source})
        if not isinstance(avoid, (list, tuple)) or any(not isinstance(entry, str) or not entry.strip() for entry in avoid):
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "Termbase record avoid metadata is invalid.", {"source": source})
        term_id = item.get("term_id")
        if term_id is not None and (not isinstance(term_id, str) or not term_id.strip()):
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "Termbase term_id metadata is invalid.", {"source": source})
        records.append(TermRecord(source, dict(preferred), status, tuple(scope), tuple(avoid), term_id))
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
        raise KSlideError(ErrorCode.SCHEMA_INVALID, "Termbase could not be read.", {"path": str(path), "reason": type(exc).__name__}) from exc
    return _parse_records(value, origin=str(path))


def merge_termbases(*termbases: Termbase) -> Termbase:
    merged: dict[str, TermRecord] = {}
    for termbase in termbases:
        for record in termbase.records:
            existing = merged.get(record.source)
            if existing is not None:
                if existing.as_dict() != record.as_dict():
                    raise KSlideError(ErrorCode.SCHEMA_INVALID, "Conflicting terminology records require governed precedence.", {"source": record.source})
                raise KSlideError(ErrorCode.SCHEMA_INVALID, "Duplicate terminology records are ambiguous.", {"source": record.source})
            merged[record.source] = record
    return Termbase("+".join(termbase.version for termbase in termbases if termbase.version) or "1.0", tuple(merged.values()), "merged")


def load_effective_termbase(
    project_root: Path,
    *,
    authority: Any | None = None,
    run_override: Path | None = None,
    authoritative: bool = True,
) -> Termbase:
    """Resolve governed terminology; reference overrides must be explicit."""

    from .governed_terminology import load_reference_termbase, resolve_governed_termbase

    if not authoritative:
        if run_override is None:
            raise KSlideError(ErrorCode.SCHEMA_INVALID, "Non-authoritative termbase resolution requires an explicit reference overlay path.")
        return load_reference_termbase(project_root, run_override=run_override)
    if run_override is not None:
        raise KSlideError(ErrorCode.SCHEMA_INVALID, "Arbitrary run termbase overrides cannot be authoritative.")
    return resolve_governed_termbase(project_root, authority=authority)


def __getattr__(name: str) -> Any:
    """Lazy compatibility exports for the governed terminology contract."""

    if name in {"GovernedTermbaseSource", "TermbaseGovernance", "TermbaseGovernanceAdapter"}:
        from . import governed_terminology

        return getattr(governed_terminology, name)
    raise AttributeError(name)
