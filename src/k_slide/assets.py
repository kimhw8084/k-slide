"""Resolve shipped runtime data in both source installs and built wheels."""

from pathlib import Path


def runtime_asset(relative: str) -> Path:
    # Callers supply compile-time asset names, never source-document paths.
    packaged = Path(__file__).resolve().parent / "data" / relative
    if packaged.is_file():
        return packaged
    return Path(__file__).resolve().parents[2] / relative
