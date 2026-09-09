"""Helpers for the code-owned completion artifact contract."""

from __future__ import annotations

from pathlib import Path

from .errors import ErrorCode, KSlideError
from .policy import COMPLETION_POLICY


def ensure_completion_artifacts(run_dir: Path, *, include_sentinel: bool) -> None:
    missing = COMPLETION_POLICY.missing(run_dir, include_sentinel=include_sentinel)
    if missing:
        raise KSlideError(ErrorCode.COMPLETION_BLOCKED, "Required K-Slide completion artifacts are missing.", {"missing": missing})
