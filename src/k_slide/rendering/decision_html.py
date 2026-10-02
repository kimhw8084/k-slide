"""Script-free employee result page, rendered only from canonical artifacts."""

from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Any
from urllib.parse import quote

from ..evidence_ir import load_evidence
from ..io import read_json
from ..ir import SlideIR
from ..queue import load_queue
from ..storage import StorageArtifact, storage_path


STYLE = """
:root{color-scheme:light dark;--bg:#f5f6f8;--surface:#fff;--ink:#152234;--muted:#4d5e73;--line:#dce2e9;--accent:#185ec1;--warn:#795300;--warn-bg:#fff4d6}
*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:5rem}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}
a{color:var(--accent);text-underline-offset:3px}a:focus-visible,summary:focus-visible{outline:3px solid var(--accent);outline-offset:4px;border-radius:3px}
.skip{position:absolute;left:1rem;top:-5rem;background:var(--surface);padding:1rem;z-index:5}.skip:focus{top:1rem}
header,main,footer{max-width:1160px;margin:auto;padding:2rem}header{padding-bottom:1rem}.eyebrow{font-size:.75rem;letter-spacing:.14em;font-weight:700;text-transform:uppercase;color:var(--muted)}
h1{font-size:clamp(2rem,4vw,3.2rem);line-height:1.15;letter-spacing:-.035em;margin:.6rem 0}h2{font-size:1.5rem;letter-spacing:-.02em;margin:0 0 1rem}h3{font-size:1.05rem;margin:0 0 .8rem}p{margin:.5rem 0 1rem}
.muted,small{color:var(--muted)}.run{overflow-wrap:anywhere;font-size:.8rem}.topline{display:flex;gap:1rem;align-items:center;justify-content:space-between;flex-wrap:wrap}
nav{position:sticky;top:0;z-index:2;background:var(--surface);border-block:1px solid var(--line)}nav div{max-width:1160px;margin:auto;display:flex;gap:1.5rem;padding:.8rem 2rem;overflow:auto}nav a{white-space:nowrap;text-decoration:none;font-weight:600}
.banner{padding:1rem 1.2rem;background:var(--warn-bg);color:var(--warn);border-left:4px solid currentColor;border-radius:5px;margin:1rem 0}.banner strong{display:block}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1.2rem}.card,.unit{padding:1.4rem;background:var(--surface);border:1px solid var(--line);border-radius:12px;min-width:0}.card:first-child{grid-column:1/-1}
section{margin-bottom:2.5rem}.claim{padding:1rem 0;border-top:1px solid var(--line)}.claim:first-of-type{border-top:0;padding-top:0}.claim p{white-space:pre-wrap;overflow-wrap:anywhere}.meta{display:flex;gap:.5rem;flex-wrap:wrap;font-size:.78rem;color:var(--muted)}.badge{border:1px solid var(--line);border-radius:5px;padding:.1rem .5rem}.unresolved{color:var(--warn);background:var(--warn-bg);border-color:transparent}.sources{font-size:.85rem;margin-top:.5rem}.sources a{margin-right:1rem}
details{margin-top:1rem}summary{cursor:pointer;font-weight:600;padding:.5rem 0}figure{margin:1rem 0}img{display:block;max-width:100%;height:auto;border:1px solid var(--line);background:white;border-radius:6px}figcaption{font-size:.8rem;color:var(--muted);margin:.4rem 0}
.unit{margin:1rem 0}.literal{white-space:pre-wrap;overflow-wrap:anywhere}.scroll{overflow-x:auto;max-width:100%}table{border-collapse:collapse;width:100%;font-size:.92rem;margin:1rem 0}caption{text-align:left;color:var(--muted);margin:.4rem 0}th,td{border:1px solid var(--line);text-align:left;padding:.65rem;vertical-align:top;white-space:pre-wrap;min-width:6rem}th{background:var(--bg)}.empty{color:var(--muted);font-style:italic}.review-item{border-left:3px solid var(--warn);padding:.5rem 1rem;margin:1rem 0}footer{border-top:1px solid var(--line);font-size:.8rem;padding-top:1rem}
@media(prefers-color-scheme:dark){:root{--bg:#101722;--surface:#182231;--ink:#edf2f9;--muted:#b1bfd0;--line:#39475a;--accent:#9ec5ff;--warn:#ffe0a0;--warn-bg:#352d1d}}
@media(max-width:650px){header,main,footer{padding:1.2rem}.grid{grid-template-columns:1fr}.card,.unit{padding:1rem}nav div{padding:.8rem 1.2rem;gap:1.2rem}}
@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}}
@media print{@page{margin:15mm}html{color-scheme:light}body{background:white;color:#111;font-size:10pt}header,main,footer{padding:0;max-width:none}nav,.skip{display:none}.grid{display:block}.card,.unit{margin:1rem 0;padding:.8rem;border-color:#ccc;border-radius:0}.claim,.review-item,tr,figure{break-inside:avoid}h2,h3,summary{break-after:avoid}.banner{color:#493200;background:#fff7df}.scroll{overflow:visible}table{table-layout:fixed;font-size:9pt}td,th{min-width:0;overflow-wrap:anywhere}details> :not(summary){display:block!important}img{max-height:220mm;object-fit:contain}a{color:inherit}.muted,small,.meta,figcaption{color:#444}}
"""


def _text(value: Any) -> str:
    return escape(str(value or ""), quote=True)


def _anchor(value: str) -> str:
    return "source-" + quote(value, safe="-_.")


def _media(run_dir: Path, value: Any) -> str | None:
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        return None
    path = run_dir / value
    try:
        relative = path.resolve(strict=True).relative_to(run_dir.resolve())
    except (OSError, ValueError):
        return None
    if path.suffix.lower() not in {".png", ".jpg", ".jpeg", ".webp"}:
        return None
    return quote(relative.as_posix(), safe="/-_.")


def _claim(item: dict[str, Any]) -> str:
    unresolved = item.get("unresolved")
    label = "Needs review" if unresolved else str(item.get("provenance", "not_established")).replace("_", " ").capitalize()
    links, seen = [], set()
    for source in item.get("source_refs", []):
        unit = source.get("work_unit_id")
        if unit and unit not in seen:
            seen.add(unit)
            links.append(f'<a href="#{_anchor(unit)}">{_text(source.get("human_reference", unit))}</a>')
    return ('<article class="claim"><p>' + _text(item.get("text") or item.get("unresolved_reason") or "Not established.")
            + f'</p><div class="meta"><span class="badge {"unresolved" if unresolved else ""}">{_text(label)}</span>'
            + f'<span>Uncertainty: {_text(item.get("uncertainty", "unknown"))}</span></div>'
            + ('<div class="sources">' + "".join(links) + "</div>" if links else "") + "</article>")


def decision_html(run_dir: Path, view: dict[str, Any]) -> str:
    sections = view["sections"]
    verification = view["verification"]
    warnings = sections["unresolved_warnings"]["items"]
    ready = verification["state"] == "PASS" and not warnings
    heading = "Verification passed" if ready else "Review status before relying on this result"
    explanation = ("Deterministic checks passed for the current artifacts. Source references remain available below."
                   if ready else "This result contains unfinished checks or unresolved evidence. Review the warnings and original source before making a decision.")
    lines = ['<!doctype html><html lang="en"><head><meta charset="utf-8">',
             '<meta name="viewport" content="width=device-width, initial-scale=1">',
             '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; img-src \'self\' data:; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">',
             '<title>K-Slide · Decision View</title><style>' + STYLE + '</style></head><body>',
             '<a class="skip" href="#main">Skip to result</a><header><div class="topline"><span class="eyebrow">K-Slide / Evidence-backed English</span>',
             '<span class="run muted">Run ' + _text(view["run_id"]) + '</span></div><h1>Understand the decision.</h1>',
             '<p class="muted">The key points first. The complete English reconstruction and original evidence below.</p>',
             f'<div class="banner" role="status"><strong>{heading}</strong>{explanation}</div></header>',
             '<nav aria-label="Result sections"><div><a href="#decision">Decision View</a><a href="#review">Review warnings</a><a href="#reconstruction">English reconstruction</a><a href="#sources">Source evidence</a></div></nav>',
             '<main id="main"><section id="decision"><h2>Decision View</h2><div class="grid">']
    for key, label in (("key_takeaway", "Key takeaway"), ("decisions_and_asks", "Decisions and asks"),
                       ("key_numbers", "Key numbers"), ("risks_and_dependencies", "Risks and dependencies"),
                       ("timing_and_owners", "Timing and owners"), ("conflicts", "Competing assertions")):
        items = sections[key].get("items", [])
        empty = "Conflict assessment is not complete." if sections[key]["state"] == "not_assessed" else "Not established in the current evidence."
        lines.append(f'<div class="card"><h3>{label}</h3>' + ("".join(_claim(item) for item in items) if items else f'<p class="empty">{empty}</p>') + '</div>')
    lines.extend(['</div></section><section id="review"><h2>Review warnings</h2>',
                  '<p class="muted">Uncertainty is retained with the result. A source correction must go through the engine’s review and verification flow.</p>'])
    lines.extend('<div class="review-item">' + _claim(item) + '</div>' for item in warnings)
    if not warnings:
        lines.append('<p>No unresolved warnings are recorded.</p>')
    lines.append('</section><section id="reconstruction"><h2>English reconstruction</h2>')
    queue = load_queue(run_dir)
    media = []
    for unit in sorted(queue.work_units, key=lambda item: (item.document_id, item.source_index, item.work_unit_id)):
        lines.append(f'<article class="unit"><h3>Page / slide {unit.source_index + 1}</h3><p class="run muted">{_text(unit.document_id)}</p>')
        path = storage_path(run_dir, StorageArtifact.CANONICAL_IR, f"ir/{unit.work_unit_id}.json")
        if not path.is_file():
            lines.append('<p class="empty">Translation has not been submitted.</p></article>')
            continue
        evidence = load_evidence(run_dir, unit.work_unit_id)
        slide = SlideIR.from_dict(read_json(path), evidence=evidence)
        for region in sorted(slide.regions, key=lambda item: item.reading_order):
            lines.append('<p class="literal">' + _text(region.translation or region.unresolved_reason or "Unresolved source text.")
                         + '</p><p class="meta">' + _text((region.provenance or "unresolved").replace("_", " ")) + '</p>')
        for index, table in enumerate(slide.tables, start=1):
            lines.append(f'<div class="scroll" role="region" aria-label="Table {index}" tabindex="0"><table><caption>Table {index}' + (f' · Unit: {_text(table.unit)}' if table.unit else '') + '</caption><tbody>')
            for row in range(table.row_count):
                lines.append('<tr>')
                for cell in sorted((cell for cell in table.cells if cell.row == row), key=lambda cell: cell.column):
                    if cell.is_spanned:
                        continue
                    tag = "th" if cell.is_header else "td"
                    scope = ' scope="col"' if cell.is_header else ''
                    text = cell.translation or ("Needs review" if cell.unresolved else "")
                    lines.append(f'<{tag}{scope} rowspan="{cell.rowspan}" colspan="{cell.colspan}">{_text(text)}</{tag}>')
                lines.append('</tr>')
            lines.append('</tbody></table></div>')
            for note in table.source_notes:
                lines.append('<p class="muted">Source footnote: ' + _text(note) + '</p>')
        if slide.visual_relations:
            lines.append('<h3>Visual and process meaning</h3>')
            for relation in slide.visual_relations:
                lines.append('<p class="literal">' + _text(relation.interpretation or relation.unresolved_reason or "Not established.")
                             + '</p><p class="meta">' + _text((relation.provenance or "unresolved").replace("_", " "))
                             + ' · Direction: ' + _text(relation.direction or "unknown") + '</p>')
        if slide.numeric_facts:
            lines.append('<details><summary>Source numbers and units</summary><ul>')
            for fact in slide.numeric_facts:
                lines.append('<li>' + _text(fact.source_string) + ((' · ' + _text(fact.source_unit)) if fact.source_unit else '') + '</li>')
            lines.append('</ul></details>')
        lines.append(f'<a href="#{_anchor(unit.work_unit_id)}">Compare with original source</a></article>')
        media.append((unit, evidence))
    lines.append('</section><section id="sources"><h2>Source evidence</h2><p class="muted">Open an original page to compare its content with the English reconstruction.</p>')
    for unit, evidence in media:
        lines.append(f'<details class="unit" id="{_anchor(unit.work_unit_id)}"><summary>Page / slide {unit.source_index + 1} · {_text(unit.document_id)}</summary>')
        image = _media(run_dir, evidence.source.get("context_image_path"))
        if image:
            lines.append(f'<figure><img loading="lazy" src="{image}" alt="Original source page {unit.source_index + 1}; compare against the English reconstruction"><figcaption>Original source · {_text(unit.work_unit_id)}</figcaption></figure>')
        else:
            lines.append('<p class="empty">The source image is unavailable in this view. Open the engine evidence packet.</p>')
        for region in evidence.regions:
            crop = _media(run_dir, region.crop_original_path)
            if crop:
                lines.append(f'<details><summary>Evidence region {region.reading_order}</summary><figure><img loading="lazy" src="{crop}" alt="Source evidence region {region.reading_order}"><figcaption>{_text(region.region_id)}</figcaption></figure></details>')
        lines.append('</details>')
    lines.extend(['</section></main><footer>Generated from retained K-Slide artifacts. Printing does not change verification or approval. Handle exported content under the source document’s company policy.</footer></body></html>'])
    return "\n".join(lines)
