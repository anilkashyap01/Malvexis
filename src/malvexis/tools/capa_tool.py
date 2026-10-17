"""capa (Mandiant FLARE) via its CLI: what can this program do, mapped to MITRE ATT&CK.

Opt-in (--capa) because it is slow (10s of seconds per file) and needs two extra downloads:
the capa-rules repo and the sigs/ folder. Its findings are INFORMATIONAL and never change the score:
compiler startup code alone triggers rules such as "allocate or change RWX memory" in benign programs.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from ..config import Config
from ..intel.base import make_result
from .runner import ToolNotFound, ToolOutputTooLarge, run_tool

SOURCE = "capa"
SUPPORTED_TYPES = {"pe", "elf"}
MAX_CAPABILITIES = 150
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def parse_capa_output(text: str) -> dict:
    body = json.loads(text)
    capabilities, techniques = [], {}
    for name, rule in (body.get("rules") or {}).items():
        meta = rule.get("meta", {})
        attack = [a.get("id") for a in meta.get("attack", []) if a.get("id")]
        for a in meta.get("attack", []):
            if a.get("id"):
                techniques[a["id"]] = {
                    "id": a["id"],
                    "tactic": a.get("tactic"),
                    "technique": a.get("technique"),
                    "subtechnique": a.get("subtechnique") or None,
                }
        capabilities.append(
            {
                "name": meta.get("name", name),
                "namespace": meta.get("namespace"),
                "attack": attack,
                "mbc": [m.get("id") for m in meta.get("mbc", []) if m.get("id")],
            }
        )
    capabilities.sort(key=lambda c: (c["namespace"] or "~", c["name"]))
    return {
        "capa_version": (body.get("meta") or {}).get("version"),
        "capability_count": len(capabilities),
        "capabilities": capabilities[:MAX_CAPABILITIES],
        "attack": sorted(techniques.values(), key=lambda t: t["id"]),
    }


def _clean_error(text: str) -> str:
    text = _ANSI.sub("", text)
    return " ".join(text.split())[-300:] or "unknown error"


def scan(path: str | Path, config: Config) -> dict:
    if not config.capa_rules_dir or not config.capa_sigs_dir:
        return make_result(
            SOURCE,
            "unavailable",
            "Set CAPA_RULES_DIR (clone of mandiant/capa-rules) and CAPA_SIGS_DIR (the sigs/ folder of mandiant/capa)",
        )
    args = ["-r", str(config.capa_rules_dir), "-s", str(config.capa_sigs_dir), "-j", str(Path(path).resolve())]
    try:
        rc, out, err = run_tool("capa", args, config.tool_timeout)
    except ToolNotFound:
        return make_result(SOURCE, "unavailable", "capa not found (pip install 'malvexis[capa]')")
    except subprocess.TimeoutExpired:
        return make_result(SOURCE, "error", f"capa timed out after {config.tool_timeout}s")
    except ToolOutputTooLarge:
        return make_result(SOURCE, "error", "capa output too large")
    if rc != 0:
        return make_result(SOURCE, "error", f"capa failed: {_clean_error(err or out)}")
    try:
        return make_result(SOURCE, "ok", data=parse_capa_output(out))
    except (ValueError, AttributeError) as exc:
        return make_result(SOURCE, "error", f"Could not parse capa output: {exc}")
