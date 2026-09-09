"""Closed semantic vocabularies shared by patches, reports, and evaluators."""

from __future__ import annotations

from enum import Enum
from typing import Any

from .errors import ErrorCode, KSlideError


class CommitmentStatus(str, Enum):
    DECIDED = "decided"
    COMMITTED = "committed"
    PLANNED = "planned"
    SCHEDULED = "scheduled"
    TARGET = "target"
    PROPOSED = "proposed"
    UNDER_REVIEW = "under_review"
    NEEDS_REVIEW = "needs_review"
    DISCUSSION_REQUIRED = "discussion_required"
    EXPECTED = "expected"
    FORECAST = "forecast"
    POSSIBLE = "possible"
    TENTATIVE = "tentative"
    NOT_DECIDED = "not_decided"
    COMPLETED = "completed"
    IN_PROGRESS = "in_progress"
    UNKNOWN = "unknown"


class SpeechAct(str, Enum):
    FACT = "fact"
    STATUS = "status"
    DECISION = "decision"
    PLAN = "plan"
    REQUEST = "request"
    RECOMMENDATION = "recommendation"
    RISK = "risk"
    DEPENDENCY = "dependency"
    FORECAST = "forecast"
    QUESTION = "question"
    UNKNOWN = "unknown"


class ClaimKind(str, Enum):
    TAKEAWAY = "takeaway"
    DECISION_STATUS = "decision_status"
    DECISION_OR_ASK = "decision_or_ask"
    TIMING = "timing"
    KEY_NUMBER = "key_number"
    RISK = "risk"
    DEPENDENCY = "dependency"
    OWNER = "owner"
    TREND = "trend"
    NEXT_STEP = "next_step"
    OTHER = "other"


class Uncertainty(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class CoverageStatus(str, Enum):
    TRANSLATED = "translated"
    UNRESOLVED = "unresolved"
    UNREADABLE = "unreadable"
    INTENTIONALLY_PRESERVED = "intentionally_preserved"
    NOT_APPLICABLE = "not_applicable"


def enum_value(value: Any, enum_type: type[Enum], label: str) -> str:
    if not isinstance(value, str):
        raise KSlideError(ErrorCode.SCHEMA_INVALID, f"{label} must be a string.")
    try:
        return enum_type(value).value
    except ValueError as exc:
        allowed = [item.value for item in enum_type]
        raise KSlideError(ErrorCode.SCHEMA_INVALID, f"{label} is not a supported semantic value.", {"value": value, "allowed": allowed}) from exc
