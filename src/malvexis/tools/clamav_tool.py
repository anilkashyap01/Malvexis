"""ClamAV via the clamscan CLI. Opt-in (--clamav): each run loads the whole signature database."""
from __future__ import annotations

import subprocess
from pathlib import Path

from ..config import Config
from ..intel.base import make_result
from .runner import ToolNotFound, ToolOutputTooLarge, run_tool

SOURCE = "clamav"
SUPPORTED_TYPES = None


def parse_clamscan(returncode: int, stdout: str, stderr: str, sample: str) -> dict:
    """clamscan exit codes: 0 = no virus found, 1 = virus found, 2 = error."""
    if returncode == 0:
        return make_result(SOURCE, "ok", data={"infected": False, "signature": None})
    if returncode == 1:
        for line in stdout.splitlines():
            if line.endswith(" FOUND"):
                body = line[: -len(" FOUND")]
                prefix = f"{sample}: "
                signature = body[len(prefix):] if body.startswith(prefix) else body.rsplit(": ", 1)[-1]
                return make_result(SOURCE, "ok", data={"infected": True, "signature": signature})
        return make_result(SOURCE, "ok", data={"infected": True, "signature": "unknown"})
    lines = [ln.strip() for ln in (stderr or stdout).splitlines() if ln.strip()]
    db_lines = [ln for ln in lines if "database" in ln.lower()]
    best = (db_lines or lines or ["unknown error"])[-1]
    message = f"clamscan error: {best}"
    if db_lines:
        message += " (run `freshclam` to download signatures)"
    return make_result(SOURCE, "error", message)


def scan(path: str | Path, config: Config) -> dict:
    sample = str(Path(path).resolve())
    args = ["--no-summary"]
    if config.clamav_db_dir:
        args += ["-d", str(config.clamav_db_dir)]
    args.append(sample)
    try:
        rc, out, err = run_tool("clamscan", args, config.tool_timeout)
    except ToolNotFound:
        return make_result(SOURCE, "unavailable", "clamscan not found (install ClamAV, then run `freshclam`)")
    except subprocess.TimeoutExpired:
        return make_result(SOURCE, "error", f"clamscan timed out after {config.tool_timeout}s")
    except ToolOutputTooLarge:
        return make_result(SOURCE, "error", "clamscan output too large")
    return parse_clamscan(rc, out, err, sample)
