from __future__ import annotations

import json
from pathlib import Path


def to_json(result: dict | list, indent: int = 2) -> str:
    return json.dumps(result, indent=indent, ensure_ascii=True, default=str)


def write_json(result: dict | list, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(to_json(result), encoding="utf-8")
    return path
