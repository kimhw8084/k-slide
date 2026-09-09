"""Bind semantic evaluation roles to immutable EvidenceIR IDs.

Gold describes roles and source text. Runtime IDs are created by the engine and
must never be guessed by the scorer or supplied by the model.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class GoldBinding:
    bindings: dict[str, str]
    failures: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return not self.failures


def _candidates(evidence: Any, source_text: str) -> list[str]:
    needle = source_text.strip()
    values: list[tuple[str, str]] = []
    for region in getattr(evidence, "regions", ()):
        values.append((region.region_id, str(region.selected_literal_candidate or "")))
    for table in getattr(evidence, "tables", ()):
        for cell in table.cells:
            values.append((cell.cell_id, str(cell.source_text or "")))
    for element in getattr(evidence, "visual_elements", ()):
        if not isinstance(element, dict) or not element.get("element_id"):
            continue
        label = element.get("source_text") or element.get("label") or element.get("title") or ""
        values.append((str(element["element_id"]), str(label)))
    exact = [identifier for identifier, text in values if text.strip() == needle]
    if exact:
        return exact
    return [identifier for identifier, text in values if needle and needle in text]


def bind_gold_roles(scenario: Any, evidence: Any) -> GoldBinding:
    process = scenario.gold.get("process") or {}
    bindings: dict[str, str] = {}
    failures: list[str] = []
    for node in process.get("nodes", []):
        role = str(node.get("id") or node.get("role") or "").strip()
        source_text = str(node.get("source_text") or node.get("label") or "").strip()
        if not role or not source_text:
            continue
        candidates = _candidates(evidence, source_text)
        if len(candidates) != 1:
            failures.append(f"GOLD_BINDING_FAILURE:{role}:{len(candidates)}")
        else:
            bindings[role] = candidates[0]
    chart = scenario.gold.get("chart") or {}
    if chart:
        chart_id = str(chart.get("chart_id") or "chart")
        candidates = [str(item.get("element_id")) for item in getattr(evidence, "visual_elements", ()) if isinstance(item, dict) and (item.get("kind") == "chart" or item.get("chart"))]
        if len(candidates) == 1:
            bindings[chart_id] = candidates[0]
        elif chart_id not in bindings:
            failures.append(f"GOLD_BINDING_FAILURE:{chart_id}:{len(candidates)}")
    return GoldBinding(bindings, tuple(failures))


def bind_process_relations(scenario: Any, evidence: Any) -> tuple[list[dict[str, Any]], GoldBinding]:
    binding = bind_gold_roles(scenario, evidence)
    relations: list[dict[str, Any]] = []
    for relation in (scenario.gold.get("process") or {}).get("relations", []):
        source = binding.bindings.get(str(relation.get("from")))
        target = binding.bindings.get(str(relation.get("to")))
        if not source or not target:
            if not any(item.startswith(f"GOLD_BINDING_FAILURE:{relation.get('from')}") for item in binding.failures):
                failures = list(binding.failures)
                failures.append(f"GOLD_BINDING_FAILURE:{relation.get('from')}->{relation.get('to')}:unbound")
                binding = GoldBinding(binding.bindings, tuple(failures))
            continue
        relations.append({"from": source, "to": target, "type": relation.get("type"), "direction": relation.get("direction")})
    return relations, binding
