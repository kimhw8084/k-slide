"""Deterministic first-pass numeric evidence extraction."""

from __future__ import annotations

import re
from typing import Any

_NUMBER = re.compile(r"(?<![A-Za-z0-9])(?:\(?[-+]?\d[\d,]*(?:\.\d+)?\)?)(?:\s*(?:%p|%|조원|억원|만원|조|억|만|원|KRW|USD|달러))?(?![A-Za-z0-9])", re.IGNORECASE)
_PERIOD = re.compile(r"\b(?:[1-4]Q|Q[1-4]|1H|2H|상반기|하반기|YoY|QoQ)\b", re.IGNORECASE)


def extract_numeric_facts(text: str | None, *, source_region_id: str) -> list[dict[str, Any]]:
    if not text:
        return []
    facts: list[dict[str, Any]] = []
    for index, match in enumerate(_NUMBER.finditer(text), start=1):
        source_string = match.group(0)
        normalized = source_string.replace(",", "").replace("(", "").replace(")", "")
        numeric_match = re.search(r"[-+]?\d+(?:\.\d+)?", normalized)
        value = float(numeric_match.group(0)) if numeric_match else None
        unit_match = re.search(r"(?:%p|%|조원|억원|만원|조|억|만|원|KRW|USD|달러)$", normalized, re.IGNORECASE)
        facts.append({
            "fact_id": f"{source_region_id}-n{index:02d}",
            "source_region_id": source_region_id,
            "source_string": source_string,
            "canonical_value": value,
            "source_unit": unit_match.group(0) if unit_match else None,
            "semantic_quantity": None,
            "time_period": next((period.group(0) for period in _PERIOD.finditer(text[match.end():])), None),
            "direction": "negative" if source_string.startswith("(") or source_string.startswith("-") else None,
            "approximation": "approximate" if "~" in text[max(0, match.start() - 1):match.start() + 1] else None,
        })
    return facts
