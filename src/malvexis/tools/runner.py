"""The ONLY place Malvexis starts another process.

Safety properties (see AGENTS.md hard rule 1):
- only a fixed allow-list of analyzer names can run, never anything derived from a sample
- argv list with shell=False, no stdin, hard timeout, capped output
- callers pass an absolute sample path; the sample itself is never executed
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ALLOWED_TOOLS = frozenset({"capa", "floss", "clamscan"})
MAX_OUTPUT_BYTES = 100 * 1024 * 1024


class ToolNotFound(Exception):
    pass


class ToolOutputTooLarge(Exception):
    pass


def find_tool(name: str) -> str:
    if name not in ALLOWED_TOOLS:
        raise ValueError(f"{name!r} is not an allowed analysis tool")
    # Prefer the interpreter's own scripts folder so a venv install works without activating it
    scripts = Path(sys.executable).parent
    for candidate in (scripts / name, scripts / f"{name}.exe"):
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    found = shutil.which(name)
    if not found:
        raise ToolNotFound(name)
    return found


def run_tool(name: str, args: list[str], timeout: int) -> tuple[int, str, str]:
    """Run an allow-listed analyzer. Raises ToolNotFound, subprocess.TimeoutExpired, ToolOutputTooLarge."""
    exe = find_tool(name)
    proc = subprocess.run(  # noqa: S603 - fixed executable, list argv, shell=False
        [exe, *args],
        capture_output=True,
        text=True,
        errors="replace",
        timeout=timeout,
        stdin=subprocess.DEVNULL,
        shell=False,
        check=False,
    )
    if len(proc.stdout) > MAX_OUTPUT_BYTES:
        raise ToolOutputTooLarge(name)
    return proc.returncode, proc.stdout, proc.stderr
