"""Orchestrates one scan: local analysis first, then tools/rules/intel lookups, then scoring."""
from __future__ import annotations

import datetime as dt
from collections.abc import Iterable
from pathlib import Path

from . import __version__, tools as tools_pkg
from .config import Config
from .core.entropy import analyze_entropy
from .core.filetype import identify_file
from .core.hashing import compute_hashes
from .core.pe_analysis import analyze_pe
from .core.strings import analyze_strings
from .intel import hashlookup, malwarebazaar, virustotal, yara_scan
from .intel.base import make_result
from .intel.cache import Cache
from .scoring import score_result
from .tools import die_tool


def _run_tools(path: Path, config: Config, filetype: dict, requested: set[str]) -> dict:
    results = {"die": die_tool.scan(path, config)}  # cheap and in-process: always attempted
    for name in ("clamav", "capa", "floss"):
        if name not in requested:
            continue
        module = tools_pkg.OPTIONAL_TOOLS[name]
        supported = module.SUPPORTED_TYPES
        if supported is not None and filetype["type"] not in supported:
            results[name] = make_result(name, "unavailable", f"{name} does not analyze this file type ({filetype['description']})")
        else:
            results[name] = module.scan(path, config)
    return results


def analyze_file(
    path: str | Path,
    config: Config,
    offline: bool = False,
    cache: Cache | None = None,
    tools: Iterable[str] = (),
) -> dict:
    """Analyze one file statically. The sample is read, never executed."""
    path = Path(path)
    requested = set(tools)
    size = path.stat().st_size
    result: dict = {
        "tool": {"name": "malvexis", "version": __version__},
        "analyzed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "options": {"offline": offline, "tools": sorted(requested)},
        "file": {"name": path.name, "path": str(path.resolve()), "size": size},
        "errors": [],
    }

    result["hashes"] = compute_hashes(path)
    result["filetype"] = identify_file(path)

    if size == 0:
        result["errors"].append("File is empty; skipping content analysis")
        data = b""
    elif size > config.max_file_size:
        result["errors"].append(f"File is larger than {config.max_file_size:,} bytes; strings/entropy/PE/tool analysis skipped")
        data = b""
    else:
        data = path.read_bytes()

    result["entropy"] = analyze_entropy(data)
    result["strings"] = analyze_strings(data)

    result["pe"] = None
    if data and result["filetype"]["type"] == "pe":
        result["pe"] = analyze_pe(path)
        if result["pe"].get("valid"):
            result["hashes"]["imphash"] = result["pe"].get("imphash")
        else:
            result["errors"].append(result["pe"].get("error", "PE analysis failed"))

    result["tools"] = _run_tools(path, config, result["filetype"], requested) if data else {}

    intel: dict = {"yara": yara_scan.scan(path, config)}  # local: runs even in offline mode
    if not offline:
        sha256 = result["hashes"]["sha256"]
        intel["virustotal"] = virustotal.lookup(sha256, config, cache)
        intel["malwarebazaar"] = malwarebazaar.lookup(sha256, config, cache)
        intel["hashlookup"] = hashlookup.lookup(sha256, config, cache)
    result["intel"] = intel

    result["score"] = score_result(result)
    return result
