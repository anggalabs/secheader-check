"""Format keluaran: teks berwarna untuk terminal dan JSON untuk otomasi."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict
from typing import List

from .scanner import ScanResult

COLORS = {
    "pass": "\033[32m", "warn": "\033[33m", "fail": "\033[31m",
    "bold": "\033[1m", "dim": "\033[2m", "reset": "\033[0m",
}
ICONS = {"pass": "[PASS]", "warn": "[WARN]", "fail": "[FAIL]"}
GRADE_COLOR = {"A": "pass", "B": "pass", "C": "warn", "D": "warn", "F": "fail"}


def use_color(force_off: bool = False) -> bool:
    if force_off or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _c(text: str, style: str, enabled: bool) -> str:
    return f"{COLORS[style]}{text}{COLORS['reset']}" if enabled else text


def render_text(result: ScanResult, color: bool) -> str:
    lines = [_c(f"Target : {result.target}", "bold", color)]
    if result.error:
        lines.append(_c(f"ERROR  : {result.error}", "fail", color))
        return "\n".join(lines)

    if result.final_url and result.final_url != result.target:
        lines.append(f"Redirect ke: {result.final_url}")
    lines.append(f"Status HTTP: {result.status_code}")
    lines.append("")

    for f in result.findings:
        lines.append(f"{_c(ICONS[f.status], f.status, color)} {f.check}: {f.message}")
        if f.status != "pass" and f.recommendation:
            lines.append(_c(f"       -> {f.recommendation}", "dim", color))

    g = result.grade
    lines.append("")
    lines.append(_c(f"Skor: {result.score}/100  Grade: {g}", GRADE_COLOR.get(g, "bold"), color))
    return "\n".join(lines)


def render_json(results: List[ScanResult]) -> str:
    return json.dumps([asdict(r) for r in results], indent=2, ensure_ascii=False)
