"""Small deterministic language and modality guards for KSA-24.

This module intentionally does not attempt general language understanding.  It
only classifies visible Unicode scripts and checks a short list of unambiguous
Korean business cues whose semantic direction is already fixed by the closed
modality vocabulary.
"""

from __future__ import annotations

import re
from typing import Iterable

LANGUAGE_VALUES = frozenset({"ko", "en", "mixed", "unknown"})

_HANGUL_RANGES = (
    (0x1100, 0x11FF),
    (0x3130, 0x318F),
    (0xA960, 0xA97F),
    (0xAC00, 0xD7AF),
    (0xD7B0, 0xD7FF),
)
_LATIN_RE = re.compile(r"[A-Za-z\u00C0-\u024F\u1E00-\u1EFF]")
_ENGLISH_SPAN_RE = re.compile(
    r"[A-Za-z][A-Za-z0-9._:/+\-]*(?:[ \t]+(?:[A-Za-z][A-Za-z0-9._:/+\-]*|\d[\d._:/+\-]*))*"
)


def _is_hangul(char: str) -> bool:
    codepoint = ord(char)
    return any(start <= codepoint <= end for start, end in _HANGUL_RANGES)


def classify_source_language(text: str | None) -> str:
    """Return ``ko``, ``en``, ``mixed`` or ``unknown`` from script evidence.

    Digits, punctuation, symbols, whitespace, and other scripts do not count as
    either English or Korean.  A string is English only when it contains a
    Latin letter and no Hangul; this keeps identifiers such as ``Q4`` from
    becoming language evidence by themselves.
    """

    if not isinstance(text, str) or not text:
        return "unknown"
    has_hangul = any(_is_hangul(char) for char in text)
    has_latin = bool(_LATIN_RE.search(text))
    if has_hangul and has_latin:
        return "mixed"
    if has_hangul:
        return "ko"
    if has_latin:
        return "en"
    return "unknown"


def source_english_spans(text: str | None) -> tuple[str, ...]:
    """Return exact Latin-word spans that mixed-language output must retain."""

    if classify_source_language(text) != "mixed":
        return ()
    assert text is not None
    spans: list[str] = []
    for match in _ENGLISH_SPAN_RE.finditer(text):
        value = match.group(0)
        if value and value not in spans:
            spans.append(value)
    return tuple(spans)


# Ordered from the most specific cue to less specific cues.  These are
# deliberately phrase-level checks, not a broad classifier.
_CUES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("under_review", ("검토 중", "검토중", "검토", "논의 중", "논의중")),
    ("possible", ("가능", "수 있음", "수있음", "할 수 있다", "할수있다")),
    ("forecast", ("전망", "예상", "예측", "전망치")),
    ("proposed", ("제안", "제시안", "제안됨")),
    ("tentative", ("잠정", "임시", "미정")),
    ("completed", ("완료", "완료됨", "마침", "끝남")),
    ("in_progress", ("진행 중", "진행중", "추진 중", "추진중")),
    ("decided", ("결정", "확정", "의결")),
    ("committed", ("약속", "커밋", "추진한다", "추진합니다")),
    ("scheduled", ("예정", "일정", "하기로")),
    ("planned", ("계획", "추진 예정", "할 계획")),
    ("target", ("목표", "타깃")),
)

_DECISION_BEARING = frozenset({
    "decided",
    "committed",
    "planned",
    "scheduled",
    "target",
})


def modality_cues(text: str | None) -> frozenset[str]:
    if not isinstance(text, str):
        return frozenset()
    return frozenset(name for name, phrases in _CUES if any(phrase in text for phrase in phrases))


def decision_bearing_status(status: str | None) -> bool:
    return status in _DECISION_BEARING


def modality_mismatch(source_text: str | None, commitment_status: str | None, speech_act: str | None) -> str | None:
    """Return a concise mismatch reason, or ``None`` for an allowed case."""

    cues = modality_cues(source_text)
    if not cues:
        return None
    status = commitment_status
    speech = speech_act

    weakening: dict[str, frozenset[str]] = {
        "under_review": frozenset({"decided", "committed"}),
        "possible": frozenset({"decided", "committed", "planned", "scheduled", "target"}),
        "forecast": frozenset({"decided", "committed", "planned", "scheduled", "target"}),
        "proposed": frozenset({"decided", "committed"}),
        "tentative": frozenset({"decided", "committed"}),
    }
    for cue, forbidden in weakening.items():
        if cue in cues and status in forbidden:
            return f"source cue {cue!r} cannot be strengthened to {status!r}"

    if "completed" in cues and status is not None and status != "completed" and "scheduled" not in cues:
        return f"completed source state cannot be changed to {status!r}"
    if "in_progress" in cues and status is not None and status != "in_progress" and "scheduled" not in cues:
        return f"in_progress source state cannot be changed to {status!r}"
    if "decided" in cues and status in {"under_review", "possible", "tentative", "proposed", "planned", "scheduled", "target"}:
        return f"decided source state cannot be weakened or swapped to {status!r}"
    if "under_review" in cues and speech == "decision":
        return "review language cannot become a decision speech act"
    if "possible" in cues and speech in {"decision", "plan"}:
        return "possibility language cannot become a decision or plan"
    if "forecast" in cues and speech == "decision":
        return "forecast language cannot become a decision"
    if "proposed" in cues and speech == "decision":
        return "proposal language cannot become a decision"
    if "tentative" in cues and speech in {"decision", "plan"}:
        return "tentative language cannot become a decision or plan"
    return None


def any_hangul(text: str | None) -> bool:
    return bool(text) and any(_is_hangul(char) for char in text)


__all__ = [
    "LANGUAGE_VALUES",
    "any_hangul",
    "classify_source_language",
    "decision_bearing_status",
    "modality_cues",
    "modality_mismatch",
    "source_english_spans",
]
