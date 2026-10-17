"""FLOSS (Mandiant FLARE) via its CLI: recovers stack, tight and decoded (obfuscated) strings.

Opt-in (--floss): it emulates code in software (never natively) and takes tens of seconds per file.
Static strings are skipped because Malvexis already extracts them.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from ..config import Config
from ..core.strings import classify_strings
from ..intel.base import make_result
from .runner import ToolNotFound, ToolOutputTooLarge, run_tool

SOURCE = "floss"
SUPPORTED_TYPES = {"pe"}
MIN_LENGTH = 6
MAX_STRINGS = 50
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def parse_floss_output(text: str) -> dict:
    strings = (json.loads(text).get("strings") or {})
    buckets = {}
    for key, label in (("stack_strings", "stack"), ("tight_strings", "tight"), ("decoded_strings", "decoded")):
        values = [i.get("string", "") for i in strings.get(key, [])]
        buckets[label] = [v for v in dict.fromkeys(values) if len(v) >= MIN_LENGTH]
    combined = [s for items in buckets.values() for s in items]
    return {
        "counts": {label: len(items) for label, items in buckets.items()},
        "strings": {label: items[:MAX_STRINGS] for label, items in buckets.items()},
        "indicators": classify_strings(combined),
    }


def scan(path: str | Path, config: Config) -> dict:
    # path first: --no takes a list, so anything after it would be read as more --no values
    args = [str(Path(path).resolve()), "-j", "-q", "-n", str(MIN_LENGTH), "--no", "static"]
    try:
        rc, out, err = run_tool("floss", args, config.tool_timeout)
    except ToolNotFound:
        return make_result(SOURCE, "unavailable", "floss not found (pip install 'malvexis[floss]')")
    except subprocess.TimeoutExpired:
        return make_result(SOURCE, "error", f"floss timed out after {config.tool_timeout}s")
    except ToolOutputTooLarge:
        return make_result(SOURCE, "error", "floss output too large")
    if rc != 0:
        return make_result(SOURCE, "error", f"floss failed: {' '.join(_ANSI.sub('', err or out).split())[-300:] or 'unknown error'}")
    try:
        return make_result(SOURCE, "ok", data=parse_floss_output(out))
    except (ValueError, AttributeError) as exc:
        return make_result(SOURCE, "error", f"Could not parse floss output: {exc}")
