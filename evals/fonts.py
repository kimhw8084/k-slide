"""Verified Korean font discovery for generated evaluation artifacts."""

from __future__ import annotations

import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from shutil import which


class KoreanFontUnavailable(RuntimeError):
    """Raised when a corpus cannot be rendered with real Hangul glyphs."""


@dataclass(frozen=True)
class FontInfo:
    family: str
    path: str
    version: str | None = None

    def as_dict(self) -> dict[str, str | None]:
        return asdict(self)


_REPRESENTATIVE = "가 한 검토 추진 고도화"
_CANDIDATE_PATHS = (
    "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
    "/usr/share/fonts/opentype/noto/NotoSansCJKkr-Regular.otf",
    "/usr/share/fonts/opentype/noto/NotoSansKR-Regular.otf",
    "/usr/share/fonts/truetype/nanum/NanumGothic.ttf",
    "/Library/Fonts/NotoSansCJKkr-Regular.otf",
    "/System/Library/Fonts/Supplemental/Noto Sans CJK KR.ttf",
    "/System/Library/Fonts/AppleSDGothicNeo.ttc",
    "/System/Library/Fonts/Supplemental/AppleGothic.ttf",
    "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
    "/Library/Fonts/Arial Unicode.ttf",
)


def _cmap_supports(path: Path) -> bool:
    try:
        from fontTools.ttLib import TTCollection, TTFont

        required = {ord(character) for character in _REPRESENTATIVE if not character.isspace()}
        with path.open("rb") as stream:
            if path.suffix.lower() in {".ttc", ".otc"}:
                with TTCollection(stream) as collection:
                    return any(required.issubset({code for table in font["cmap"].tables for code in table.cmap}) for font in collection.fonts)
            with TTFont(stream) as font:
                return required.issubset({code for table in font["cmap"].tables for code in table.cmap})
    except (ImportError, OSError, KeyError, ValueError):
        return False


def _pillow_supports(path: Path) -> bool:
    try:
        from PIL import ImageFont

        font = ImageFont.truetype(str(path), 32)
        return all(font.getbbox(character) is not None for character in _REPRESENTATIVE if not character.isspace())
    except (ImportError, OSError, ValueError):
        return False


def _family_and_version(path: Path) -> tuple[str, str | None]:
    try:
        from fontTools.ttLib import TTCollection, TTFont

        with path.open("rb") as stream:
            if path.suffix.lower() in {".ttc", ".otc"}:
                with TTCollection(stream) as collection:
                    font = collection.fonts[0]
                    names = font["name"].names
                    family = next((item.toUnicode() for item in names if item.nameID == 1), path.stem)
                    version = next((item.toUnicode() for item in names if item.nameID == 5), None)
                    return family, version
            with TTFont(stream) as font:
                names = font["name"].names
                family = next((item.toUnicode() for item in names if item.nameID == 1), path.stem)
                version = next((item.toUnicode() for item in names if item.nameID == 5), None)
                return family, version
    except (ImportError, OSError, KeyError, ValueError):
        return path.stem, None


def _fc_candidates() -> list[Path]:
    binary = which("fc-match")
    if not binary:
        return []
    paths: list[Path] = []
    for family in ("Noto Sans CJK KR", "Noto Sans KR", "NanumGothic"):
        try:
            result = subprocess.run([binary, "-f", "%{file}\\n", family], capture_output=True, text=True, timeout=3, check=False)
        except (OSError, subprocess.TimeoutExpired):
            continue
        candidate = Path(result.stdout.strip().splitlines()[0]) if result.stdout.strip() else None
        # fc-match legitimately returns a Latin fallback when the requested
        # Korean family is not installed. Never accept that fallback as proof
        # of Hangul support.
        if candidate and any(token.lower() in candidate.name.lower() for token in ("noto", "nanum", "apple", "arial unicode")):
            paths.append(candidate)
    return paths


def discover_korean_font() -> FontInfo:
    """Find and verify a real Hangul font; never fall back to bitmap defaults."""

    seen: set[Path] = set()
    for candidate in [*_fc_candidates(), *[Path(item) for item in _CANDIDATE_PATHS]]:
        candidate = candidate.resolve() if candidate.exists() else candidate
        if candidate in seen or not candidate.is_file():
            continue
        seen.add(candidate)
        if not (_cmap_supports(candidate) or _pillow_supports(candidate)):
            continue
        family, version = _family_and_version(candidate)
        return FontInfo(family, str(candidate), version)
    raise KoreanFontUnavailable("A verified Korean-capable font is required. Install fonts-noto-cjk or NanumGothic before generating the corpus.")


def load_font(size: int, info: FontInfo | None = None):
    from PIL import ImageFont

    selected = info or discover_korean_font()
    return ImageFont.truetype(selected.path, max(1, int(size)))
