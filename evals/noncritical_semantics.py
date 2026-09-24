"""Closed deterministic gold for non-critical semantic equivalence.

Public assertions live beside, rather than inside, the frozen scenario corpus
so adding this scoring contract does not change KSA-26 corpus fingerprints.
Governed external assertions are supplied in each hash-bound gold wrapper.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from typing import Any


PUBLIC_NONCRITICAL_ASSERTIONS: dict[str, list[dict[str, Any]]] = {
    "scenario-0001": [
        {
            "assertion_id": "ncs-208d55c7be6ea492c5bc4d18",
            "surface": "region",
            "source_text": "KPI 개선 추진",
            "accepted_phrases": ["KPI improvement initiative", "initiative to improve KPIs"],
        },
        {
            "assertion_id": "ncs-c7b7228a9c50bf62ac068ad7",
            "surface": "region",
            "source_text": "Revenue 성장률 및 주요 리스크 검토",
            "accepted_phrases": [
                "review of revenue growth and key risks",
                "review of revenue growth and major risks",
                "revenue growth rate and key risks under review",
            ],
        },
    ],
}

_ASSERTION_ID = re.compile(r"^ncs-[0-9a-f]{24}$")
_SURFACES = frozenset({"region", "table_cell", "executive_claim", "visual_interpretation"})


def normalized_phrase_tokens(value: str) -> tuple[str, ...]:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    return tuple(re.findall(r"[a-z0-9]+", normalized))


def validate_assertions(value: Any) -> list[dict[str, Any]]:
    """Validate the closed source-bound assertion schema without echoing gold."""

    if not isinstance(value, list):
        raise ValueError("non-critical semantic assertions must be a list")
    identifiers: set[str] = set()
    validated: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"assertion_id", "surface", "source_text", "accepted_phrases"}:
            raise ValueError("non-critical semantic assertion has an unsupported shape")
        assertion_id = item.get("assertion_id")
        surface = item.get("surface")
        source_text = item.get("source_text")
        phrases = item.get("accepted_phrases")
        if not isinstance(assertion_id, str) or not _ASSERTION_ID.fullmatch(assertion_id) or assertion_id in identifiers:
            raise ValueError("non-critical semantic assertion identity is malformed")
        if not isinstance(surface, str) or surface not in _SURFACES:
            raise ValueError("non-critical semantic assertion surface is unsupported")
        if not isinstance(source_text, str) or not source_text.strip():
            raise ValueError("non-critical semantic assertion source anchor is malformed")
        if not isinstance(phrases, list) or not phrases or any(not isinstance(phrase, str) or not phrase.strip() for phrase in phrases):
            raise ValueError("non-critical semantic assertion meaning contract is malformed")
        tokens = [normalized_phrase_tokens(phrase) for phrase in phrases]
        if any(not phrase_tokens for phrase_tokens in tokens) or len(tokens) != len(set(tokens)):
            raise ValueError("non-critical semantic assertion meaning contract is ambiguous")
        identifiers.add(assertion_id)
        validated.append({
            "assertion_id": assertion_id,
            "surface": surface,
            "source_text": source_text,
            "accepted_phrases": list(phrases),
        })
    return validated


def public_assertions_for(scenario_id: str) -> list[dict[str, Any]]:
    return validate_assertions(PUBLIC_NONCRITICAL_ASSERTIONS.get(scenario_id, []))


def assertions_for_scenario(scenario: Any) -> list[dict[str, Any]]:
    gold = getattr(scenario, "gold", {})
    if not isinstance(gold, dict):
        raise ValueError("scenario gold contract is malformed")
    if "noncritical_semantic_assertions" in gold:
        return validate_assertions(gold["noncritical_semantic_assertions"])
    return public_assertions_for(str(getattr(scenario, "scenario_id", "")))


def public_assertion_ids_by_scenario() -> dict[str, list[str]]:
    return {
        scenario_id: sorted(item["assertion_id"] for item in public_assertions_for(scenario_id))
        for scenario_id in sorted(PUBLIC_NONCRITICAL_ASSERTIONS)
    }


def public_gold_contract_sha256() -> str:
    encoded = json.dumps(PUBLIC_NONCRITICAL_ASSERTIONS, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
