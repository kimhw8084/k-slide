"""Deterministic numeric and period evidence extraction/semantic comparison."""

from __future__ import annotations

import re
from typing import Any


_TOKEN = re.compile(
    r"(?<![A-Za-z0-9가-힣])"
    r"(?P<sign>[+\-▲▼]?)\s*"
    r"(?P<open>\(?\s*)"
    r"(?P<number>\d[\d,]*(?:\.\d+)?)"
    r"(?P<close>\s*\)?)"
    r"\s*(?P<unit>%p|%|percentage\s+points?|percent|trillion|billion|million|조원|억원|만원|원|조|억|만|KRW|USD|달러)?"
    r"(?![A-Za-z0-9가-힣])",
    re.IGNORECASE,
)
_PERIOD = re.compile(r"(?<![A-Za-z0-9])(?:[1-4]Q(?:['’]?\d{2})?|Q[1-4](?:['’]?\d{2})?|1H\d{0,2}|2H\d{0,2}|[12]분기|상반기|하반기|YoY|QoQ|전년比|전분기比)(?![A-Za-z0-9])", re.IGNORECASE)

_UNIT_INFO: dict[str, tuple[float, str, str | None]] = {
    "만": (10**4, "scaled_number", None),
    "만원": (10**4, "currency", "KRW"),
    "억": (10**8, "scaled_number", None),
    "억원": (10**8, "currency", "KRW"),
    "조": (10**12, "scaled_number", None),
    "조원": (10**12, "currency", "KRW"),
    "원": (1.0, "currency", "KRW"),
    "krw": (1.0, "currency", "KRW"),
    "usd": (1.0, "currency", "USD"),
    "달러": (1.0, "currency", "USD"),
    "%": (1.0, "percentage", None),
    "percent": (1.0, "percentage", None),
    "%p": (1.0, "percentage_point", None),
    "percentage point": (1.0, "percentage_point", None),
    "percentage points": (1.0, "percentage_point", None),
    "trillion": (10**12, "currency", "KRW"),
    "billion": (10**9, "currency", "KRW"),
    "million": (10**6, "currency", "KRW"),
}


def _normal_unit(value: str | None) -> str | None:
    if value is None:
        return None
    return re.sub(r"\s+", " ", value.strip().lower())


def _direction(sign: str, opening: str, unit: str | None) -> str | None:
    if sign in {"+", "▲"}:
        return "positive"
    if sign in {"-", "▼"} or "(" in opening:
        return "negative"
    return None


def _period_after(text: str, end: int) -> str | None:
    window = text[end : min(len(text), end + 48)]
    match = _PERIOD.search(window)
    return match.group(0) if match else None


def extract_numeric_facts(
    text: str | None,
    *,
    source_region_id: str | None = None,
    source_object_id: str | None = None,
    source_table_id: str | None = None,
    source_cell_id: str | None = None,
) -> list[dict[str, Any]]:
    """Extract source-owned facts with deterministic IDs scoped to the source object."""

    if not text:
        return []
    object_id = source_object_id or source_region_id or "source"
    facts: list[dict[str, Any]] = []
    matches: list[tuple[int, str, float | None, str | None, str, str]] = []
    for match in _TOKEN.finditer(text):
        unit_display = match.group("unit")
        unit = _normal_unit(unit_display)
        raw = float(match.group("number").replace(",", ""))
        factor, quantity, currency = _UNIT_INFO.get(unit or "", (1.0, "number", None))
        canonical = raw * factor
        direction = _direction(match.group("sign"), match.group("open"), unit)
        matches.append((match.start(), match.group(0), canonical, unit_display, quantity, direction or ""))
        facts.append(
            {
                "fact_id": f"{object_id}-n{len(facts) + 1:02d}",
                "source_object_id": object_id,
                "source_region_id": source_region_id,
                "source_table_id": source_table_id,
                "source_cell_id": source_cell_id,
                "source_string": match.group(0),
                "raw_value": raw,
                "canonical_value": canonical,
                "scale_factor": factor,
                "source_unit": unit_display,
                "semantic_quantity": quantity,
                "currency": currency,
                "time_period": _period_after(text, match.end()),
                "direction": direction,
                "approximation": "approximate" if "~" in text[max(0, match.start() - 2) : match.start() + 1] else None,
            }
        )
    for period in _PERIOD.finditer(text):
        if any(start <= period.start() < start + len(source) for start, source, *_ in matches):
            continue
        value = period.group(0)
        facts.append(
            {
                "fact_id": f"{object_id}-n{len(facts) + 1:02d}",
                "source_object_id": object_id,
                "source_region_id": source_region_id,
                "source_table_id": source_table_id,
                "source_cell_id": source_cell_id,
                "source_string": value,
                "raw_value": None,
                "canonical_value": None,
                "scale_factor": 1.0,
                "source_unit": None,
                "semantic_quantity": "period",
                "currency": None,
                "time_period": value,
                "direction": None,
                "approximation": None,
            }
        )
    return facts


def _target_facts(text: str | None) -> list[dict[str, Any]]:
    return extract_numeric_facts(text, source_object_id="target")


def numeric_fact_matches(source: dict[str, Any], target_text: str | None) -> tuple[bool, str]:
    """Compare a source fact to translated text without requiring literal formatting."""

    if source.get("semantic_quantity") == "period":
        expected = str(source.get("time_period") or source.get("source_string") or "").lower()
        normalized = (target_text or "").lower()
        aliases = {expected}
        aliases.update({"first half"} if expected.startswith("1h") or expected in {"상반기"} else set())
        aliases.update({"second half"} if expected.startswith("2h") or expected in {"하반기"} else set())
        aliases.update({"q1"} if expected.startswith("1q") or expected.startswith("q1") or expected == "1분기" else set())
        if any(alias in normalized for alias in aliases):
            return True, "period equivalent"
        return False, f"period {source.get('source_string')} is absent or changed"
    targets = _target_facts(target_text)
    canonical = source.get("canonical_value")
    quantity = source.get("semantic_quantity")
    direction = source.get("direction")
    normalized_target = (target_text or "").lower()
    positive_words = ("increase", "increased", "growth", "gain", "improve", "improved", "up", "higher")
    negative_words = ("decrease", "decreased", "decline", "drop", "loss", "deteriorat", "down", "lower")
    if direction == "positive" and any(word in normalized_target for word in negative_words):
        return False, f"direction for {source.get('source_string')} was reversed"
    if direction == "negative" and any(word in normalized_target for word in positive_words):
        return False, f"direction for {source.get('source_string')} was reversed"
    for target in targets:
        if canonical is None or target.get("canonical_value") is None:
            continue
        tolerance = max(abs(float(canonical)) * 1e-9, 1e-9)
        if abs(float(canonical) - float(target["canonical_value"])) > tolerance:
            continue
        if quantity == "percentage_point" and target.get("semantic_quantity") != "percentage_point":
            continue
        if quantity == "percentage" and target.get("semantic_quantity") == "percentage_point":
            continue
        if source.get("currency") and target.get("currency") and source.get("currency") != target.get("currency"):
            continue
        if direction and target.get("direction") and direction != target.get("direction"):
            continue
        return True, "numeric meaning preserved"
    return False, f"numeric fact {source.get('source_string')} is absent or semantically changed"
