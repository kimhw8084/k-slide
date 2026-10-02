"""Conservative, engine-owned ruled-table geometry from normalized pixels.

This is a bounded grid detector, not a general document-layout recognizer.
Only closed rectangular cells are reconstructed. Uncertain geometry and ink
without a trustworthy literal remain review obligations.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .evidence_ir import RISKY_LITERAL_STATES, EvidenceRegion


MAX_LINES = 2048
MAX_CELLS = 4096


def _lines(image: Any, minimum: int) -> list[tuple[int, int, int]]:
    width, height = image.size
    pixels = image.tobytes()
    pattern = re.compile(b"\x01{" + str(minimum).encode("ascii") + b",}")
    lines: list[tuple[int, int, int]] = []
    for coordinate in range(height):
        for match in pattern.finditer(pixels, coordinate * width, (coordinate + 1) * width):
            start, end = match.start() - coordinate * width, match.end() - coordinate * width - 1
            # Collapse adjacent pixels of one stroke, retaining its extent.
            duplicate = next((i for i in range(len(lines) - 1, max(-1, len(lines) - 64), -1)
                              if coordinate - lines[i][0] <= 4 and abs(start - lines[i][1]) <= 4 and abs(end - lines[i][2]) <= 4), None)
            if duplicate is not None:
                previous = lines[duplicate]
                lines[duplicate] = (coordinate, min(start, previous[1]), max(end, previous[2]))
            else:
                lines.append((coordinate, start, end))
            if len(lines) > MAX_LINES:
                return lines
    coordinates = sorted({line[0] for line in lines})
    representative = {}
    start = None
    for coordinate in coordinates:
        if start is None or coordinate - start > 4:
            start = coordinate
        representative[coordinate] = start
    return [(representative[position], left, right) for position, left, right in lines]


def _covers(lines: list[tuple[int, int, int]], coordinate: int, start: int, end: int) -> bool:
    return any(abs(position - coordinate) <= 4 and left <= start + 4 and right >= end - 4
               for position, left, right in lines)


def ruled_table_items(render: Path, work_unit_id: str, regions: list[EvidenceRegion],
                      source_items: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    from PIL import Image

    with Image.open(render) as source:
        binary = source.convert("L").point(lambda value: 1 if value < 180 else 0)
    horizontal = _lines(binary, max(24, binary.width // 80))
    vertical = _lines(binary.transpose(Image.Transpose.TRANSPOSE), max(24, binary.height // 80))
    if len(horizontal) > MAX_LINES or len(vertical) > MAX_LINES:
        return [], ["Page geometry exceeds the bounded table detector; review the full page."]
    edges: dict[tuple[str, int], set[tuple[str, int]]] = {}
    for h_index, (y, left, right) in enumerate(horizontal):
        for v_index, (x, top, bottom) in enumerate(vertical):
            if left - 4 <= x <= right + 4 and top - 4 <= y <= bottom + 4:
                h, v = ("h", h_index), ("v", v_index)
                edges.setdefault(h, set()).add(v)
                edges.setdefault(v, set()).add(h)
    groups = []
    unseen = set(edges)
    while unseen:
        pending = [min(unseen)]
        component = set()
        while pending:
            node = pending.pop()
            if node in component:
                continue
            component.add(node)
            pending.extend(edges[node] - component)
        unseen -= component
        hs = [horizontal[i] for axis, i in component if axis == "h"]
        vs = [vertical[i] for axis, i in component if axis == "v"]
        xs, ys = sorted({v[0] for v in vs}), sorted({h[0] for h in hs})
        if len(xs) >= 3 and len(ys) >= 3:
            groups.append((xs, ys, hs, vs))
    geometry = {item["source_id"]: item.get("bbox_px") for item in source_items}
    tables, issues = [], []
    for xs, ys, hs, vs in sorted(groups, key=lambda group: (group[1][0], group[0][0])):
        if any(item.get("table") and item.get("bbox_px")
               and item["bbox_px"][0] <= xs[0] + 4 and item["bbox_px"][1] <= ys[0] + 4
               and item["bbox_px"][2] >= xs[-1] - 4 and item["bbox_px"][3] >= ys[-1] - 4
               for item in source_items):
            continue
        rows, columns = len(ys) - 1, len(xs) - 1
        if rows * columns > MAX_CELLS:
            issues.append("Table geometry exceeds the bounded cell inventory; review the full page.")
            continue
        if not (all(_covers(hs, y, xs[0], xs[-1]) for y in (ys[0], ys[-1]))
                and all(_covers(vs, x, ys[0], ys[-1]) for x in (xs[0], xs[-1]))):
            issues.append("A possible table has incomplete outer boundaries; its structure requires review.")
            continue
        slots = {(r, c) for r in range(rows) for c in range(columns)}
        spans = []
        while slots:
            pending = [min(slots)]
            merged = set()
            while pending:
                r, c = pending.pop()
                if (r, c) in merged:
                    continue
                merged.add((r, c))
                for nr, nc, divided in (
                    (r, c - 1, _covers(vs, xs[c], ys[r], ys[r + 1])),
                    (r, c + 1, _covers(vs, xs[c + 1], ys[r], ys[r + 1])),
                    (r - 1, c, _covers(hs, ys[r], xs[c], xs[c + 1])),
                    (r + 1, c, _covers(hs, ys[r + 1], xs[c], xs[c + 1])),
                ):
                    if not divided and 0 <= nr < rows and 0 <= nc < columns and (nr, nc) not in merged:
                        pending.append((nr, nc))
            slots -= merged
            r0, r1 = min(r for r, _ in merged), max(r for r, _ in merged)
            c0, c1 = min(c for _, c in merged), max(c for _, c in merged)
            if len(merged) != (r1 - r0 + 1) * (c1 - c0 + 1):
                issues.append("A possible table has ambiguous merged-cell boundaries; review its structure.")
                spans = []
                break
            spans.append((r0, c0, r1, c1))
        if not spans:
            continue
        item_id = f"{work_unit_id}-grid-{len(tables) + 1:03d}"
        cells = []
        for r0, c0, r1, c1 in sorted(spans):
            left, top, right, bottom = xs[c0], ys[r0], xs[c1 + 1], ys[r1 + 1]
            selected, ambiguous = [], False
            for region in regions:
                bbox = geometry.get(region.region_id) or region.bbox_px
                x0, y0, x1, y1 = bbox
                if min(right, x1) <= max(left, x0) or min(bottom, y1) <= max(top, y0):
                    continue
                if x0 < left - 4 or y0 < top - 4 or x1 > right + 4 or y1 > bottom + 4:
                    ambiguous = True
                else:
                    selected.append(region)
            selected.sort(key=lambda region: region.reading_order)
            trusted = bool(selected) and all(region.evidence_state not in RISKY_LITERAL_STATES
                       and region.recovery_status != "NEEDS_REVIEW"
                       and region.selected_literal_candidate for region in selected)
            inset = 5
            interior = binary.crop((left + inset, top + inset, max(left + inset + 1, right - inset), max(top + inset + 1, bottom - inset)))
            has_ink = interior.histogram()[1] > 3
            unknown = ambiguous or (not trusted and (has_ink or bool(selected)))
            text = None if unknown else ("\n".join(region.selected_literal_candidate for region in selected) if trusted else "")
            if unknown:
                issues.append(f"Table {len(tables) + 1}, row {r0 + 1}, column {c0 + 1} contains unresolved source evidence.")
            for row in range(r0, r1 + 1):
                for column in range(c0, c1 + 1):
                    origin = (row, column) == (r0, c0)
                    merged = r1 > r0 or c1 > c0
                    cells.append({
                        "cell_id": f"{item_id}-cell-{row:03d}-{column:03d}",
                        "row": row, "column": column,
                        "rowspan": r1 - r0 + 1 if origin else 1,
                        "colspan": c1 - c0 + 1 if origin else 1,
                        "text": text if origin else None,
                        "is_blank": origin and text == "",
                        "is_merge_origin": origin and merged,
                        "is_spanned": not origin,
                        "cell_state": "unknown" if unknown and origin else None,
                        "evidence_region_ids": [region.region_id for region in selected],
                    })
        tables.append({"source_id": item_id, "bbox_px": [xs[0], ys[0], xs[-1], ys[-1]],
                       "table": {"row_count": rows, "column_count": columns, "cells": cells}})
    return tables, list(dict.fromkeys(issues))
