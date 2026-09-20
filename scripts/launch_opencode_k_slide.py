#!/usr/bin/env python3
"""Supported managed OpenCode entrypoint for the production K-Slide host."""

from k_slide.opencode_bootstrap import main


if __name__ == "__main__":
    raise SystemExit(main())
