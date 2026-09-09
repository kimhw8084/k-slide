"""Render scenario specifications as realistic multi-format business artifacts.

The corpus intentionally uses native visual structures: raster tables are drawn
as grids, charts contain axes/series, process cases contain boxes and arrows,
and PPTX cases use editable tables/charts/shapes where the format supports it.
"""

from __future__ import annotations

import json
import math
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .fonts import FontInfo, discover_korean_font, load_font
from .scenarios import Scenario


@dataclass(frozen=True)
class VisualVariant:
    name: str
    width: int
    height: int
    jpeg_quality: int = 95
    blur_radius: float = 0.0
    contrast: float = 1.0
    rotation: float = 0.0
    font_scale: float = 1.0


DEFAULT_VARIANT = VisualVariant("default", 1600, 900)
CORPUS_VARIANTS = (
    DEFAULT_VARIANT,
    VisualVariant("hd", 1920, 1080, font_scale=1.0),
    VisualVariant("compressed", 1280, 720, jpeg_quality=60, font_scale=0.92),
    VisualVariant("small_text", 1920, 1080, font_scale=0.72),
    VisualVariant("degraded", 1280, 720, jpeg_quality=40, blur_radius=0.8, contrast=0.82, rotation=2.0, font_scale=0.88),
)


def _text(draw, xy, value: str, font, fill, *, anchor=None, spacing=4):
    draw.multiline_text(xy, str(value), font=font, fill=fill, anchor=anchor, spacing=spacing)


def _wrap(value: str, limit: int = 36) -> str:
    words = str(value).split()
    if not words:
        return ""
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = word if not current else f"{current} {word}"
        if len(candidate) > limit and current:
            lines.append(current)
            current = word
        else:
            current = candidate
    lines.append(current)
    return "\n".join(lines)


def _colors(category: str) -> tuple[tuple[int, int, int], tuple[int, int, int]]:
    if category in {"financial_table", "chart"}:
        return (12, 49, 86), (224, 240, 249)
    if category in {"process_diagram", "state_resume"}:
        return (23, 75, 72), (226, 244, 239)
    if category == "prompt_injection":
        return (87, 36, 36), (255, 239, 235)
    return (25, 55, 96), (238, 243, 249)


def _header(image, scenario: Scenario, info: FontInfo, *, variant: VisualVariant):
    from PIL import ImageDraw

    draw = ImageDraw.Draw(image)
    primary, secondary = _colors(scenario.category)
    draw.rectangle((0, 0, image.width, 112), fill=primary)
    _text(draw, (56, 28), scenario.title_ko, load_font(round(42 * variant.font_scale), info), "white")
    _text(draw, (56, 82), f"{scenario.category}  |  {scenario.split}", load_font(round(16 * variant.font_scale), info), secondary)
    return draw, primary, secondary


def _draw_text_slide(image, scenario: Scenario, info: FontInfo, variant: VisualVariant):
    draw, primary, secondary = _header(image, scenario, info, variant=variant)
    top = 170
    for index, line in enumerate(scenario.body_ko, start=1):
        y = top + (index - 1) * 125
        draw.ellipse((72, y + 9, 110, y + 47), fill=primary)
        _text(draw, (91, y + 28), str(index), load_font(round(18 * variant.font_scale), info), "white", anchor="mm")
        _text(draw, (140, y), _wrap(line, 55), load_font(round(28 * variant.font_scale), info), (26, 33, 45))
        draw.line((140, y + 68, image.width - 80, y + 68), fill=(210, 218, 229), width=2)
    if scenario.gold.get("visual_elements"):
        draw.rounded_rectangle((image.width - 430, image.height - 130, image.width - 70, image.height - 72), radius=12, fill=secondary)
        _text(draw, (image.width - 250, image.height - 101), "검토 필요", load_font(round(20 * variant.font_scale), info), primary, anchor="mm")


def _draw_table(image, scenario: Scenario, info: FontInfo, variant: VisualVariant, *, x: int, y: int, width: int, height: int):
    from PIL import ImageDraw

    draw = ImageDraw.Draw(image)
    table = scenario.gold["table"]
    rows = table["rows"]
    row_height = height // len(rows)
    col_width = width // len(rows[0])
    for row_index, row in enumerate(rows):
        for col_index, value in enumerate(row):
            left = x + col_index * col_width
            top = y + row_index * row_height
            right = x + (col_index + 1) * col_width
            bottom = y + (row_index + 1) * row_height
            fill = (18, 66, 111) if row_index == 0 else ((242, 247, 251) if row_index % 2 else (255, 255, 255))
            draw.rectangle((left, top, right, bottom), fill=fill, outline=(146, 163, 181), width=2)
            color = "white" if row_index == 0 else (31, 40, 52)
            _text(draw, ((left + right) // 2, (top + bottom) // 2), _wrap(value, 14), load_font(round(19 * variant.font_scale), info), color, anchor="mm")
    draw.rectangle((x, y, x + width, y + height), outline=(18, 66, 111), width=3)
    _text(draw, (x, y + height + 18), "주: 금액은 원화 기준이며 전년 대비 증감은 별도 표기", load_font(round(15 * variant.font_scale), info), (80, 91, 106))


def _draw_table_slide(image, scenario: Scenario, info: FontInfo, variant: VisualVariant):
    draw, _primary, _secondary = _header(image, scenario, info, variant=variant)
    _text(draw, (70, 148), scenario.body_ko[0], load_font(round(25 * variant.font_scale), info), (44, 54, 68))
    _draw_table(image, scenario, info, variant, x=70, y=205, width=image.width - 140, height=430)
    _text(draw, (70, 700), scenario.body_ko[1], load_font(round(24 * variant.font_scale), info), (95, 46, 35))


def _draw_chart(image, scenario: Scenario, info: FontInfo, variant: VisualVariant, *, x: int, y: int, width: int, height: int):
    from PIL import ImageDraw

    draw = ImageDraw.Draw(image)
    chart = scenario.gold["chart"]
    left, bottom, right, top = x + 70, y + height - 58, x + width - 20, y + 30
    draw.rectangle((x, y, x + width, y + height), fill=(255, 255, 255), outline=(195, 207, 220), width=2)
    draw.line((left, top, left, bottom), fill=(52, 65, 80), width=3)
    draw.line((left, bottom, right, bottom), fill=(52, 65, 80), width=3)
    values = chart["series"][0]["values"]
    high = max(values) * 1.15
    points = []
    for index, value in enumerate(values):
        px = left + index * ((right - left) / max(1, len(values) - 1))
        py = bottom - (value / high) * (bottom - top)
        points.append((px, py))
        draw.ellipse((px - 8, py - 8, px + 8, py + 8), fill=(31, 113, 179), outline="white", width=2)
        _text(draw, (px, py - 22), str(value), load_font(round(16 * variant.font_scale), info), (31, 77, 124), anchor="mm")
        _text(draw, (px, bottom + 20), chart["categories"][index], load_font(round(16 * variant.font_scale), info), (52, 65, 80), anchor="mm")
    if len(points) > 1:
        draw.line(points, fill=(31, 113, 179), width=5, joint="curve")
    _text(draw, (x + 22, y + 20), chart["title"], load_font(round(23 * variant.font_scale), info), (27, 44, 63))
    draw.line((right - 180, y + 24, right - 140, y + 24), fill=(31, 113, 179), width=5)
    _text(draw, (right - 130, y + 14), "매출", load_font(round(17 * variant.font_scale), info), (27, 44, 63))


def _draw_chart_slide(image, scenario: Scenario, info: FontInfo, variant: VisualVariant):
    draw, _primary, _secondary = _header(image, scenario, info, variant=variant)
    _draw_chart(image, scenario, info, variant, x=60, y=150, width=1000, height=550)
    draw.rounded_rectangle((1110, 190, image.width - 70, 390), radius=15, fill=(232, 246, 239), outline=(117, 174, 139), width=2)
    _text(draw, (1150, 225), "핵심 관찰", load_font(round(24 * variant.font_scale), info), (30, 91, 56))
    _text(draw, (1150, 280), "분기별 매출은\n지속 증가 추세", load_font(round(28 * variant.font_scale), info), (30, 91, 56), spacing=8)
    _text(draw, (1110, 500), scenario.body_ko[1], load_font(round(22 * variant.font_scale), info), (75, 46, 35))


def _draw_process(image, scenario: Scenario, info: FontInfo, variant: VisualVariant, *, x: int, y: int, width: int, height: int):
    from PIL import ImageDraw

    draw = ImageDraw.Draw(image)
    nodes = scenario.gold.get("process", {}).get("nodes", [])
    node_width = min(220, (width - 60) // max(1, len(nodes)))
    gap = (width - node_width * len(nodes)) // max(1, len(nodes) - 1)
    for index, node in enumerate(nodes):
        left = x + index * (node_width + gap)
        top = y + 120 + (index % 2) * 22
        draw.rounded_rectangle((left, top, left + node_width, top + 100), radius=18, fill=(232, 246, 239), outline=(36, 112, 91), width=3)
        _text(draw, (left + node_width // 2, top + 50), _wrap(node["label"], 10), load_font(round(20 * variant.font_scale), info), (29, 77, 63), anchor="mm")
        if index < len(nodes) - 1:
            arrow_y = top + 50
            start = left + node_width + 6
            end = left + node_width + gap - 6
            draw.line((start, arrow_y, end, arrow_y), fill=(36, 112, 91), width=5)
            draw.polygon([(end, arrow_y), (end - 16, arrow_y - 11), (end - 16, arrow_y + 11)], fill=(36, 112, 91))
    _text(draw, (x, y + 30), "단계별 실행 흐름", load_font(round(26 * variant.font_scale), info), (29, 77, 63))


def _draw_process_slide(image, scenario: Scenario, info: FontInfo, variant: VisualVariant):
    draw, _primary, _secondary = _header(image, scenario, info, variant=variant)
    _draw_process(image, scenario, info, variant, x=75, y=150, width=image.width - 150, height=500)
    draw.rounded_rectangle((115, 720, image.width - 115, 800), radius=14, fill=(255, 245, 224), outline=(214, 157, 61), width=2)
    _text(draw, (image.width // 2, 760), scenario.body_ko[0], load_font(round(23 * variant.font_scale), info), (111, 72, 24), anchor="mm")


def _draw_screenshot_slide(image, scenario: Scenario, info: FontInfo, variant: VisualVariant):
    """Render a cropped Teams/browser-like screenshot around slide content."""

    from PIL import ImageDraw

    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0, image.width, 42), fill=(45, 49, 56))
    for index, color in enumerate(((235, 97, 86), (242, 190, 70), (88, 190, 110))):
        draw.ellipse((18 + index * 28, 13, 31 + index * 28, 26), fill=color)
    _text(draw, (135, 10), "Teams  |  운영 리뷰 화면 캡처", load_font(round(16 * variant.font_scale), info), (230, 234, 240))
    draw.rectangle((0, 42, image.width, image.height), fill=(232, 235, 239))
    draw.rectangle((34, 70, image.width - 34, image.height - 34), fill=(255, 255, 255), outline=(176, 185, 196), width=2)
    draw.rectangle((34, 70, image.width - 34, 146), fill=(25, 55, 96))
    _text(draw, (72, 91), scenario.title_ko, load_font(round(35 * variant.font_scale), info), "white")
    for index, line in enumerate(scenario.body_ko, start=1):
        y = 205 + (index - 1) * 118
        _text(draw, (90, y), f"{index}. {line}", load_font(round(25 * variant.font_scale), info), (30, 40, 54))
        draw.line((90, y + 62, image.width - 90, y + 62), fill=(215, 220, 227), width=2)


def _draw_compound(image, scenario: Scenario, info: FontInfo, variant: VisualVariant):
    draw, primary, _secondary = _header(image, scenario, info, variant=variant)
    _text(draw, (55, 142), "경영진 검토용 종합 화면", load_font(round(23 * variant.font_scale), info), (42, 51, 62))
    if "table" in scenario.gold:
        _draw_table(image, scenario, info, variant, x=55, y=205, width=720, height=330)
    elif "chart" in scenario.gold:
        _draw_chart(image, scenario, info, variant, x=55, y=205, width=760, height=330)
    elif "process" in scenario.gold:
        _draw_process(image, scenario, info, variant, x=55, y=165, width=760, height=370)
    else:
        for index, line in enumerate(scenario.body_ko):
            _text(draw, (60, 210 + index * 88), line, load_font(round(25 * variant.font_scale), info), (40, 48, 60))
    draw.rounded_rectangle((870, 205, image.width - 60, 345), radius=14, fill=(239, 246, 255), outline=(102, 142, 194), width=2)
    _text(draw, (900, 230), "상태", load_font(round(22 * variant.font_scale), info), primary)
    _text(draw, (900, 275), "검토 중", load_font(round(31 * variant.font_scale), info), primary)
    draw.rounded_rectangle((870, 380, image.width - 60, 520), radius=14, fill=(255, 241, 236), outline=(195, 111, 91), width=2)
    _text(draw, (900, 405), "리스크 / 의존성", load_font(round(22 * variant.font_scale), info), (125, 58, 43))
    _text(draw, (900, 455), "예산 승인 및\n관련 부서 협의", load_font(round(26 * variant.font_scale), info), (125, 58, 43), spacing=8)
    _text(draw, (55, 725), "주요 판단: 수치와 구조를 함께 검토해야 함", load_font(round(22 * variant.font_scale), info), (61, 69, 81))


def _apply_degradation(image, variant: VisualVariant):
    from PIL import Image, ImageEnhance, ImageFilter

    result = image
    if variant.contrast != 1.0:
        result = ImageEnhance.Contrast(result).enhance(variant.contrast)
    if variant.blur_radius:
        result = result.filter(ImageFilter.GaussianBlur(variant.blur_radius))
    if variant.rotation:
        result = result.rotate(variant.rotation, resample=Image.Resampling.BICUBIC, expand=False, fillcolor=(247, 249, 252))
    return result


def generate_image(scenario: Scenario, destination: Path, *, width: int = 1600, height: int = 900, image_format: str = "PNG", font_info: FontInfo | None = None, variant: VisualVariant | None = None) -> Path:
    from PIL import Image

    info = font_info or discover_korean_font()
    selected = variant or VisualVariant("custom", width, height)
    selected = VisualVariant(selected.name, width, height, selected.jpeg_quality, selected.blur_radius, selected.contrast, selected.rotation, selected.font_scale)
    destination.parent.mkdir(parents=True, exist_ok=True)
    image = Image.new("RGB", (width, height), (247, 249, 252))
    if scenario.compound:
        _draw_compound(image, scenario, info, selected)
    elif scenario.visual_kind == "table" and "table" in scenario.gold:
        _draw_table_slide(image, scenario, info, selected)
    elif scenario.visual_kind == "chart" and "chart" in scenario.gold:
        _draw_chart_slide(image, scenario, info, selected)
    elif scenario.visual_kind == "process" and "process" in scenario.gold:
        _draw_process_slide(image, scenario, info, selected)
    elif scenario.visual_kind == "degradation":
        _draw_screenshot_slide(image, scenario, info, selected)
    else:
        _draw_text_slide(image, scenario, info, selected)
    image = _apply_degradation(image, selected)
    save_format = image_format.upper()
    save_kwargs = {"optimize": True}
    if save_format in {"JPG", "JPEG"}:
        save_format = "JPEG"
        save_kwargs["quality"] = selected.jpeg_quality
    image.save(destination, format=save_format, **save_kwargs)
    return destination


def _pdf_text(scenario: Scenario) -> str:
    return "\n".join((scenario.title_ko, *scenario.body_ko))


def _generate_pdf(source_image: Path, destination: Path, scenario: Scenario, *, pdf_kind: str, font_info: FontInfo) -> bool:
    try:
        import fitz
        from PIL import Image
    except ImportError:
        return False
    with Image.open(source_image) as image:
        width, height = image.size
    with fitz.open() as document:
        page = document.new_page(width=width, height=height)
        page.insert_image(page.rect, filename=str(source_image))
        if pdf_kind in {"native", "mixed"}:
            try:
                # Keep the raster visual as the truth and add an invisible text
                # layer for native-PDF extraction tests.
                page.insert_textbox(fitz.Rect(20, 20, width - 20, height - 20), _pdf_text(scenario), fontsize=10, fontfile=font_info.path, color=(1, 1, 1), render_mode=3)
            except (OSError, RuntimeError, ValueError):
                pdf_kind = "image_only_fallback"
        document.set_metadata({"title": scenario.title_ko, "subject": f"K-Slide synthetic {pdf_kind}"})
        document.save(destination)
    return True


def _add_pptx_text(slide, text: str, x, y, width, height, *, font_size: int = 20, bold: bool = False):
    from pptx.util import Pt

    frame = slide.shapes.add_textbox(x, y, width, height).text_frame
    frame.word_wrap = True
    frame.text = text
    for paragraph in frame.paragraphs:
        paragraph.font.size = Pt(font_size)
        paragraph.font.bold = bold
    return frame


def _generate_pptx(scenario: Scenario, destination: Path, *, font_info: FontInfo) -> bool:
    try:
        from pptx import Presentation
        from pptx.chart.data import CategoryChartData
        from pptx.enum.chart import XL_CHART_TYPE
        from pptx.enum.shapes import MSO_SHAPE
        from pptx.dml.color import RGBColor
        from pptx.util import Inches, Pt
    except ImportError:
        return False
    presentation = Presentation()
    presentation.slide_width = Inches(13.333)
    presentation.slide_height = Inches(7.5)
    slide = presentation.slides.add_slide(presentation.slide_layouts[6])
    _add_pptx_text(slide, scenario.title_ko, Inches(0.45), Inches(0.25), Inches(12.3), Inches(0.55), font_size=28, bold=True)
    if scenario.compound:
        shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(8.5), Inches(1.5), Inches(4.1), Inches(1.15))
        shape.text = "상태\n검토 중"
        shape.text_frame.paragraphs[0].font.size = Pt(22)
        shape.text_frame.paragraphs[1].font.size = Pt(28)
        shape.fill.solid(); shape.fill.fore_color.rgb = RGBColor(232, 241, 252)
        if "table" in scenario.gold:
            _add_pptx_table(slide, scenario, Inches(0.6), Inches(1.45), Inches(7.2), Inches(3.4))
        elif "chart" in scenario.gold:
            _add_pptx_chart(slide, scenario, Inches(0.6), Inches(1.45), Inches(7.2), Inches(3.4), CategoryChartData, XL_CHART_TYPE)
        elif "process" in scenario.gold:
            _add_pptx_process(slide, scenario, Inches(0.6), Inches(1.7), Inches(7.2), Inches(3.0), MSO_SHAPE)
        else:
            for index, line in enumerate(scenario.body_ko):
                _add_pptx_text(slide, line, Inches(8.5), Inches(4.8 + index * 0.45), Inches(4.0), Inches(0.35), font_size=16)
        _add_pptx_text(slide, "리스크 / 의존성\n예산 승인 및 관련 부서 협의", Inches(8.5), Inches(3.15), Inches(4.1), Inches(1.15), font_size=20)
    elif scenario.visual_kind == "table" and "table" in scenario.gold:
        _add_pptx_table(slide, scenario, Inches(0.55), Inches(1.35), Inches(12.2), Inches(4.1))
    elif scenario.visual_kind == "chart" and "chart" in scenario.gold:
        _add_pptx_chart(slide, scenario, Inches(0.55), Inches(1.35), Inches(8.4), Inches(4.6), CategoryChartData, XL_CHART_TYPE)
        _add_pptx_text(slide, "핵심 관찰\n분기별 매출은 지속 증가 추세", Inches(9.3), Inches(2.0), Inches(3.1), Inches(1.5), font_size=22)
    elif scenario.visual_kind == "process" and "process" in scenario.gold:
        _add_pptx_process(slide, scenario, Inches(0.6), Inches(1.8), Inches(12.0), Inches(3.3), MSO_SHAPE)
    elif scenario.visual_kind == "degradation":
        chrome = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.35), Inches(0.95), Inches(12.65), Inches(0.35))
        chrome.text = "Teams  |  운영 리뷰 화면 캡처"
        chrome.fill.solid(); chrome.fill.fore_color.rgb = RGBColor(45, 49, 56)
        _add_pptx_text(slide, "[Screenshot crop]", Inches(0.65), Inches(1.45), Inches(4), Inches(0.4), font_size=18, bold=True)
        for index, line in enumerate(scenario.body_ko):
            _add_pptx_text(slide, f"{index + 1}. {line}", Inches(0.75), Inches(2.05 + index * 0.65), Inches(11.5), Inches(0.45), font_size=21)
    else:
        top = 1.4
        for line in scenario.body_ko:
            _add_pptx_text(slide, f"• {line}", Inches(0.75), Inches(top), Inches(11.5), Inches(0.55), font_size=22)
            top += 0.8
    presentation.save(destination)
    return True


def generate_deck_pptx(scenarios: Iterable[Scenario], destination: Path) -> bool:
    """Generate a real linked multi-slide PPTX for deck-level evaluations."""

    try:
        from pptx import Presentation
        from pptx.dml.color import RGBColor
        from pptx.enum.shapes import MSO_SHAPE
        from pptx.util import Inches, Pt
    except ImportError:
        return False
    slides = list(scenarios)
    if not slides:
        return False
    presentation = Presentation()
    presentation.slide_width = Inches(13.333)
    presentation.slide_height = Inches(7.5)
    for index, scenario in enumerate(slides, start=1):
        slide = presentation.slides.add_slide(presentation.slide_layouts[6])
        _add_pptx_text(slide, scenario.title_ko, Inches(0.45), Inches(0.25), Inches(12.3), Inches(0.55), font_size=28, bold=True)
        _add_pptx_text(slide, f"Slide {index} of {len(slides)}", Inches(10.8), Inches(0.35), Inches(2.0), Inches(0.3), font_size=12)
        for line_index, line in enumerate(scenario.body_ko):
            _add_pptx_text(slide, f"• {line}", Inches(0.8), Inches(1.45 + line_index * 0.7), Inches(7.4), Inches(0.55), font_size=22)
        callout = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(8.65), Inches(1.45), Inches(3.8), Inches(1.25))
        callout.text = "공식 용어\nAI Platform"
        callout.fill.solid()
        callout.fill.fore_color.rgb = RGBColor(232, 241, 252)
        callout.text_frame.paragraphs[0].font.size = Pt(18)
        callout.text_frame.paragraphs[1].font.size = Pt(24)
        risk = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(8.65), Inches(3.1), Inches(3.8), Inches(1.25))
        risk.text = "리스크 / 의존성\n관련 부서 협의"
        risk.fill.solid()
        risk.fill.fore_color.rgb = RGBColor(255, 241, 236)
        for paragraph in risk.text_frame.paragraphs:
            paragraph.font.size = Pt(18)
    destination.parent.mkdir(parents=True, exist_ok=True)
    presentation.save(destination)
    return True


def _add_pptx_table(slide, scenario: Scenario, x, y, width, height):
    from pptx.dml.color import RGBColor
    from pptx.util import Pt

    rows = scenario.gold["table"]["rows"]
    table = slide.shapes.add_table(len(rows), len(rows[0]), x, y, width, height).table
    for row_index, row in enumerate(rows):
        for col_index, value in enumerate(row):
            cell = table.cell(row_index, col_index)
            cell.text = value
            cell.fill.solid(); cell.fill.fore_color.rgb = RGBColor(18, 66, 111) if row_index == 0 else RGBColor(247, 250, 253)
            cell.text_frame.paragraphs[0].font.size = Pt(14)
            cell.text_frame.paragraphs[0].font.bold = row_index == 0


def _add_pptx_chart(slide, scenario: Scenario, x, y, width, height, CategoryChartData, XL_CHART_TYPE):
    data = CategoryChartData()
    data.categories = scenario.gold["chart"]["categories"]
    for series in scenario.gold["chart"]["series"]:
        data.add_series(series["name"], series["values"])
    chart = slide.shapes.add_chart(XL_CHART_TYPE.LINE_MARKERS, x, y, width, height, data).chart
    chart.has_title = True
    chart.chart_title.text_frame.text = scenario.gold["chart"]["title"]
    chart.has_legend = True


def _add_pptx_process(slide, scenario: Scenario, x, y, width, height, MSO_SHAPE):
    from pptx.dml.color import RGBColor
    from pptx.util import Inches, Pt

    nodes = scenario.gold["process"]["nodes"]
    node_width = width / len(nodes) - Inches(0.15)
    for index, node in enumerate(nodes):
        left = x + index * (width / len(nodes))
        box = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, y, node_width, height * 0.55)
        box.text = node["label"]
        box.fill.solid(); box.fill.fore_color.rgb = RGBColor(232, 246, 239)
        box.text_frame.paragraphs[0].font.size = Pt(15)
        if index < len(nodes) - 1:
            arrow = slide.shapes.add_shape(MSO_SHAPE.RIGHT_ARROW, left + node_width, y + height * 0.18, Inches(0.35), Inches(0.35))
            arrow.fill.solid(); arrow.fill.fore_color.rgb = RGBColor(36, 112, 91)


def _pdf_kind(scenario: Scenario) -> str:
    if scenario.category == "visual_degradation":
        return "image_only"
    if scenario.category in {"financial_table", "simple_mixed_text", "modality_decision_state"}:
        return "native"
    return "mixed"


def generate_artifacts(scenarios: Iterable[Scenario], output: Path, *, formats: tuple[str, ...] = ("png",), variants: Iterable[VisualVariant] | None = None) -> dict[str, int]:
    """Generate independent scenario/variant/format cases.

    A separate directory is used for every case so a PDF or PPTX can never be
    mistaken for the PNG representation during engine evaluation.
    """

    selected_variants = tuple(variants or (DEFAULT_VARIANT,))
    info = discover_korean_font()
    output.mkdir(parents=True, exist_ok=True)
    counts = {name.lower(): 0 for name in formats}
    all_scenarios = list(scenarios)
    corpus_manifest = {"schema_version": "1.0", "font": info.as_dict(), "scenario_count": len(all_scenarios), "variants": [variant.__dict__ for variant in selected_variants], "formats": [item.lower() for item in formats]}
    (output / "CORPUS_MANIFEST.json").write_text(json.dumps(corpus_manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    for scenario in all_scenarios:
        scenario_dir = output / scenario.scenario_id
        scenario_dir.mkdir(parents=True, exist_ok=True)
        (scenario_dir / "gold.json").write_text(json.dumps(scenario.as_dict(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        for variant in selected_variants:
            for format_name in formats:
                suffix = format_name.lower()
                case_dir = scenario_dir / variant.name / suffix
                case_dir.mkdir(parents=True, exist_ok=True)
                destination = case_dir / f"source.{suffix}"
                generated_pdf_kind = None
                if suffix in {"png", "jpg", "jpeg", "webp"}:
                    generate_image(scenario, destination, width=variant.width, height=variant.height, image_format="JPEG" if suffix in {"jpg", "jpeg"} else suffix.upper(), font_info=info, variant=variant)
                elif suffix == "pdf":
                    temporary_png = case_dir / "_source_for_pdf.png"
                    generate_image(scenario, temporary_png, width=variant.width, height=variant.height, font_info=info, variant=variant)
                    generated_pdf_kind = _pdf_kind(scenario)
                    if not _generate_pdf(temporary_png, destination, scenario, pdf_kind=generated_pdf_kind, font_info=info):
                        continue
                    temporary_png.unlink(missing_ok=True)
                elif suffix == "pptx":
                    if not _generate_pptx(scenario, destination, font_info=info):
                        continue
                else:
                    continue
                metadata = {"scenario_id": scenario.scenario_id, "category": scenario.category, "split": scenario.split, "format": suffix, "variant": variant.__dict__, "font": info.as_dict(), "pdf_kind": generated_pdf_kind, "semantic_quality_scored": False}
                (case_dir / "metadata.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
                counts[suffix] += 1
    return counts
