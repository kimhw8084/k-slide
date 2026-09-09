"""Canonical model-facing TranslationPatch contract metadata."""

from __future__ import annotations

from .semantics import ClaimKind, CommitmentStatus, RelationDirection, RelationType, SpeechAct, Uncertainty

TRANSLATION_PATCH_SCHEMA_VERSION = "1.0"

ROOT_REQUIRED_FIELDS = frozenset({"schema_version", "work_unit_id", "evidence_revision", "regions", "tables", "visual_interpretations", "executive_claims"})
ROOT_OPTIONAL_FIELDS = frozenset({"repair_revision"})
REGION_REQUIRED_FIELDS = frozenset({"region_id", "english", "term_ids", "unresolved"})
REGION_OPTIONAL_FIELDS = frozenset({"commitment_status", "speech_act", "unresolved_reason", "hangul_retention"})
TABLE_REQUIRED_FIELDS = frozenset({"table_id", "cells"})
TABLE_OPTIONAL_FIELDS = frozenset()
CELL_REQUIRED_FIELDS = frozenset({"cell_id", "english", "unresolved"})
CELL_OPTIONAL_FIELDS = frozenset({"unresolved_reason", "hangul_retention"})
RELATION_REQUIRED_FIELDS = frozenset({"relation_id", "interpretation", "evidence_ids"})
RELATION_OPTIONAL_FIELDS = frozenset({"source_element_ids", "relation_type", "direction", "hangul_retention"})
CLAIM_REQUIRED_FIELDS = frozenset({"claim_id", "kind", "text", "evidence_ids", "uncertainty"})
CLAIM_OPTIONAL_FIELDS = frozenset({"hangul_retention"})
HANGUL_RETENTION_REQUIRED_FIELDS = frozenset({"reason", "evidence_id"})
HANGUL_RETENTION_OPTIONAL_FIELDS = frozenset()

COMMITMENT_VALUES = tuple(item.value for item in CommitmentStatus)
SPEECH_ACT_VALUES = tuple(item.value for item in SpeechAct)
RELATION_TYPE_VALUES = tuple(item.value for item in RelationType)
DIRECTION_VALUES = tuple(item.value for item in RelationDirection)
CLAIM_KIND_VALUES = tuple(item.value for item in ClaimKind)
UNCERTAINTY_VALUES = tuple(item.value for item in Uncertainty)

CONTRACT_FIELDS = {
    "root": (ROOT_REQUIRED_FIELDS, ROOT_OPTIONAL_FIELDS),
    "region": (REGION_REQUIRED_FIELDS, REGION_OPTIONAL_FIELDS),
    "table": (TABLE_REQUIRED_FIELDS, TABLE_OPTIONAL_FIELDS),
    "cell": (CELL_REQUIRED_FIELDS, CELL_OPTIONAL_FIELDS),
    "relation": (RELATION_REQUIRED_FIELDS, RELATION_OPTIONAL_FIELDS),
    "claim": (CLAIM_REQUIRED_FIELDS, CLAIM_OPTIONAL_FIELDS),
    "hangul_retention": (HANGUL_RETENTION_REQUIRED_FIELDS, HANGUL_RETENTION_OPTIONAL_FIELDS),
}
