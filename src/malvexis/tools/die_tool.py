"""Detect It Easy via the die-python library (in-process, no subprocess). Packer/compiler identification."""
from __future__ import annotations

import json
from pathlib import Path

from ..config import Config
from ..intel.base import make_result

try:
    import die
except ImportError:  # pragma: no cover
    die = None

SOURCE = "die"
SUPPORTED_TYPES = None  # DIE handles many formats; run on everything
PACKER_LIKE = {"packer", "protector", "cryptor", "joiner"}
_db_loaded = False


def _ensure_database() -> None:
    # Without this explicit call die-python silently reports "Unknown" for everything (verified).
    global _db_loaded
    if not _db_loaded:
        die.load_database(str(die.database_path))
        _db_loaded = True


def parse_die_output(text: str) -> dict:
    body = json.loads(text)
    detections, filetype = [], None
    for detect in body.get("detects", []):
        filetype = filetype or detect.get("filetype")
        for value in detect.get("values", []):
            kind = (value.get("type") or "").strip()
            if not kind or kind.lower() == "unknown" or "warning" in kind.lower() or "warning" in (value.get("name") or "").lower():
                continue
            detections.append(
                {
                    "type": kind,
                    "name": value.get("name"),
                    "version": value.get("version"),
                    "info": value.get("info"),
                    "string": value.get("string"),
                }
            )
    packers = sorted({d["string"] for d in detections if d["type"].lower() in PACKER_LIKE and d["string"]})
    return {"filetype": filetype, "detections": detections, "packers": packers}


def scan(path: str | Path, config: Config) -> dict:
    if die is None:
        return make_result(SOURCE, "unavailable", "die-python not installed (pip install 'malvexis[die]')")
    try:
        _ensure_database()
        raw = die.scan_file(str(Path(path).resolve()), die.ScanFlags.DEEP_SCAN | die.ScanFlags.RESULT_AS_JSON)
        return make_result(SOURCE, "ok", data=parse_die_output(raw))
    except Exception as exc:  # DIE is a native engine; never let it break a scan
        return make_result(SOURCE, "error", f"Detect It Easy failed: {type(exc).__name__}: {exc}")
