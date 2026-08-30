#!/usr/bin/env python3
"""Backward-compatible launcher for the canonical ZAFrida Skill CLI."""

from __future__ import annotations

import runpy
import sys
from pathlib import Path


def main() -> int:
    script = (
        Path(__file__).resolve().parent.parent
        / "skills-template"
        / "zafrida-http-control"
        / "scripts"
        / "zafrida_api.py"
    )
    if not script.is_file():
        print(f"ZAFrida Skill CLI not found: {script}", file=sys.stderr)
        return 2
    runpy.run_path(str(script), run_name="__main__")
    return 0


if __name__ == "__main__":
    sys.exit(main())
