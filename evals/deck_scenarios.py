"""Linked multi-slide evaluation scenarios for terminology and resume tests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .scenarios import Scenario


@dataclass(frozen=True)
class DeckScenario:
    deck_id: str
    slide_count: int
    slides: tuple[Scenario, ...]
    gold: dict[str, Any]


def deck_scenarios() -> list[DeckScenario]:
    decks: list[DeckScenario] = []
    for deck_index, slide_count in enumerate((3, 5, 10, 20, 50), start=1):
        slides: list[Scenario] = []
        for slide_index in range(1, slide_count + 1):
            if slide_index == 1:
                title = "AI Platform 고도화"
                body = ("AI Platform 고도화 추진", "공식 영문 용어: AI Platform")
            elif slide_index % 4 == 0:
                title = "주요 리스크 및 의존성"
                body = ("AI 플랫폼 고도화 관련 리스크 검토", "관련 부서 협의 후 추진 예정")
            elif slide_index % 3 == 0:
                title = "운영 현황"
                body = ("AI 플랫폼", "Q3 출시 검토", "상태: 진행 중")
            else:
                title = "추진 계획"
                body = ("AI Platform", "분기별 진행 현황", "동일 용어를 지속 사용")
            slides.append(Scenario(
                scenario_id=f"{deck_index:02d}-{slide_index:03d}",
                category="cross_slide_consistency",
                seed=50000 + deck_index * 1000 + slide_index,
                split="development",
                title_ko=title,
                body_ko=body,
                visual_kind="text",
                compound=slide_index in {1, slide_count} or slide_index % 5 == 0,
                gold={"locked_term": "AI Platform", "required_term_consistency": True, "visual_elements": ["headline", "callout"]},
            ))
        decks.append(DeckScenario(
            deck_id=f"deck-consistency-{deck_index:02d}",
            slide_count=slide_count,
            slides=tuple(slides),
            gold={"locked_term": "AI Platform", "required_slide_count": slide_count, "resume_safe": True},
        ))
    return decks
