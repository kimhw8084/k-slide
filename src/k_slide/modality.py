"""Small deterministic language and modality guards for KSA-24.

This module intentionally does not attempt general language understanding.  It
only classifies visible Unicode scripts and checks a short list of unambiguous
Korean business cues whose semantic direction is already fixed by the closed
modality vocabulary.
"""

from __future__ import annotations

import re
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


# Only phrase-level cues whose commitment direction is unambiguous are
# admitted.  A bare "검토" or a sentence containing multiple cues remains
# outside this deterministic guard and must be handled as interpretation or
# unresolved content.
_CUES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("under_review", ("검토 중", "검토중", "논의 중", "논의중")),
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
_STATUS_PURPORTING_CLAIM_KINDS = frozenset({"decision_status", "timing", "next_step"})

# This is deliberately a closed compatibility matrix.  It prevents a
# protected cue from being relabeled as a different commitment state while
# leaving ambiguous wording outside the deterministic surface.
_COMPATIBLE_STATUSES: dict[str, frozenset[str]] = {
    status: frozenset({status})
    for status, _phrases in _CUES
}

_EXPECTED_SPEECH: dict[str, str] = {"decided": "decision"}

# These markers are a narrow output-strength guard, not English semantic
# classification.  Each marker is assigned to the same closed state set used
# by the Korean cue matrix.
_ENGLISH_STATE_MARKERS: dict[str, tuple[str, ...]] = {
    "decided": ("decided", "approved", "finalized", "confirmed"),
    "committed": ("committed", "guaranteed", "will execute", "will implement", "will proceed"),
    "planned": ("planned", "plan to", "plans to", "intends to"),
    "scheduled": ("scheduled", "slated", "set for", "due to"),
    "target": ("target", "goal", "aim"),
    "proposed": ("proposed", "proposal", "recommended"),
    "under_review": ("under review", "in review", "being reviewed", "pending review", "in discussion"),
    "possible": ("possible", "may", "might", "could"),
    "tentative": ("tentative", "provisional", "subject to change"),
    "forecast": ("forecast", "forecasted", "projected", "expected", "estimated"),
    "completed": ("completed", "complete", "done", "finished"),
    "in_progress": ("in progress", "underway", "ongoing", "being implemented"),
}

_NEGATED_ENGLISH_STATE_MARKERS: dict[str, tuple[str, ...]] = {
    "decided": ("not approved", "not decided", "not finalized", "not confirmed", "unapproved", "undecided"),
    "committed": ("not committed", "not guaranteed", "will not execute", "will not implement", "will not proceed", "uncommitted"),
    "planned": ("not planned", "no plan", "does not plan"),
    "scheduled": ("not scheduled", "not slated", "not set for"),
    "target": ("not a target", "not the goal", "not targeted"),
}

_HANGUL_FRAGMENT_RE = re.compile(r"[\u1100-\u11ff\u3130-\u318f\ua960-\ua97f\uac00-\ud7ff]+")


def modality_cues(text: str | None) -> frozenset[str]:
    if not isinstance(text, str):
        return frozenset()
    return frozenset(name for name, phrases in _CUES if any(phrase in text for phrase in phrases))


def deterministic_modality(text: str | None) -> tuple[str | None, str | None]:
    """Return one protected source status and an optional fixed speech act."""

    cues = modality_cues(text)
    if len(cues) != 1:
        return None, None
    status = next(iter(cues))
    return status, _EXPECTED_SPEECH.get(status)


def decision_bearing_status(status: str | None) -> bool:
    return status in _DECISION_BEARING


def english_modality_cues(rendered_text: str | None) -> frozenset[str]:
    if not isinstance(rendered_text, str):
        return frozenset()
    lowered = rendered_text.casefold()
    observed = frozenset(
        status
        for status, markers in _ENGLISH_STATE_MARKERS.items()
        if any(marker in lowered for marker in markers)
    )
    return observed - english_negated_modality_cues(rendered_text)


def english_negated_modality_cues(rendered_text: str | None) -> frozenset[str]:
    if not isinstance(rendered_text, str):
        return frozenset()
    lowered = rendered_text.casefold()
    return frozenset(
        status
        for status, markers in _NEGATED_ENGLISH_STATE_MARKERS.items()
        if any(marker in lowered for marker in markers)
    )


def executive_modality_mismatch(
    source_texts: tuple[str | None, ...],
    rendered_text: str | None,
    *,
    claim_kind: str | None,
    provenance: str | None,
) -> str | None:
    """Bind a narrow set of executive-claim status words to cited source cues."""

    if provenance == "unresolved":
        return None
    expected = frozenset().union(*(modality_cues(text) for text in source_texts))
    if not expected:
        return None
    observed = english_modality_cues(rendered_text)
    negated = expected & english_negated_modality_cues(rendered_text)
    if negated:
        return f"executive wording negates cited protected source cues {sorted(negated)!r}"
    if len(expected) > 1:
        if provenance != "supported_interpretation":
            return "multiple protected source cues require unresolved or supported_interpretation treatment"
        if observed != expected:
            return f"multiple protected source cues {sorted(expected)!r} require compatible evidence-bound wording; rendered cues are {sorted(observed)!r}"
        return None
    status = next(iter(expected))
    incompatible = observed - {status}
    if incompatible:
        return f"cited source cue {status!r} is incompatible with executive wording {sorted(incompatible)!r}"
    if claim_kind in _STATUS_PURPORTING_CLAIM_KINDS and decision_bearing_status(status) and status not in observed:
        return f"{claim_kind} claim citing {status!r} evidence must preserve that commitment status"
    return None


def required_english_mismatch(
    rendered_text: str | None,
    retention: object,
    source_text_by_id: dict[str, str],
    allowed_evidence_ids: tuple[str, ...] | list[str],
) -> str | None:
    """Reject rendered Hangul unless it is explicitly retained from cited source."""

    if not any_hangul(rendered_text):
        return None
    if not isinstance(retention, dict):
        return "rendered English contains Hangul without explicit source-retention evidence"
    evidence_id = retention.get("evidence_id")
    reason = retention.get("reason")
    if not isinstance(evidence_id, str) or evidence_id not in set(allowed_evidence_ids) or not isinstance(reason, str) or not reason.strip():
        return "Hangul retention requires a reason and a cited source evidence ID"
    source_text = source_text_by_id.get(evidence_id)
    fragments = _HANGUL_FRAGMENT_RE.findall(rendered_text or "")
    if not isinstance(source_text, str) or not fragments or any(fragment not in source_text for fragment in fragments):
        return "rendered Hangul is not present in the specifically cited source evidence"
    return None


def modality_mismatch(source_text: str | None, commitment_status: str | None, speech_act: str | None, *, language_bound: bool = True) -> str | None:
    """Return a bounded modality mismatch, including omitted metadata."""

    expected_status, expected_speech = deterministic_modality(source_text) if language_bound else (None, None)
    if expected_status is None:
        return None
    if commitment_status is None:
        return f"deterministic source cue {expected_status!r} requires commitment_status"
    compatible = _COMPATIBLE_STATUSES[expected_status]
    if commitment_status not in compatible:
        return f"source cue {expected_status!r} requires compatible commitment_status {sorted(compatible)!r}, not {commitment_status!r}"
    if expected_speech is not None:
        if speech_act is None:
            return f"deterministic source cue {expected_status!r} requires speech_act {expected_speech!r}"
        if speech_act != expected_speech:
            return f"source cue {expected_status!r} requires speech_act {expected_speech!r}, not {speech_act!r}"
    return None


def english_modality_mismatch(
    source_text: str | None,
    rendered_text: str | None,
    commitment_status: str | None,
    *,
    language_bound: bool = True,
    require_status_marker: bool = False,
) -> str | None:
    """Reject incompatible English modality, optionally requiring its source state."""

    expected_status, _ = deterministic_modality(source_text) if language_bound else (None, None)
    if expected_status is None or commitment_status != expected_status or not isinstance(rendered_text, str):
        return None
    observed = english_modality_cues(rendered_text)
    if expected_status in english_negated_modality_cues(rendered_text):
        return f"rendered English negates the protected source status {expected_status!r}"
    incompatible = observed - {expected_status}
    if incompatible:
        return f"source cue {expected_status!r} is incompatible with rendered English modality {sorted(incompatible)!r}"
    if require_status_marker and expected_status not in observed:
        return f"rendered English must preserve the protected source status {expected_status!r}"
    return None


def any_hangul(text: str | None) -> bool:
    return bool(text) and any(_is_hangul(char) for char in text)


__all__ = [
    "LANGUAGE_VALUES",
    "any_hangul",
    "classify_source_language",
    "decision_bearing_status",
    "deterministic_modality",
    "english_modality_mismatch",
    "english_modality_cues",
    "english_negated_modality_cues",
    "executive_modality_mismatch",
    "modality_cues",
    "modality_mismatch",
    "required_english_mismatch",
    "source_english_spans",
]
