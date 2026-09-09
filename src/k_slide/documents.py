"""Provider-independent normalized document and unit records."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class DocumentUnit:
    work_unit_id: str
    document_id: str
    input_id: str
    source_index: int
    kind: str
    width_px: int
    height_px: int
    canonical_render_path: str
    render_sha256: str
    native_evidence_path: str
    native_evidence: tuple[dict[str, Any], ...] = ()
    render_dpi: float | None = None
    warnings: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["native_evidence"] = list(self.native_evidence)
        value["warnings"] = list(self.warnings)
        return value


@dataclass(frozen=True)
class NormalizedDocument:
    document_id: str
    input_id: str
    kind: str
    source_sha256: str
    units: tuple[DocumentUnit, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["units"] = [unit.as_dict() for unit in self.units]
        return value


@dataclass(frozen=True)
class NormalizationResult:
    documents: tuple[NormalizedDocument, ...]
    warnings: tuple[str, ...] = ()
    capabilities: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {"documents": [document.as_dict() for document in self.documents], "warnings": list(self.warnings), "capabilities": self.capabilities}
