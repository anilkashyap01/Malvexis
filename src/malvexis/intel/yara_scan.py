"""Local YARA scanning. Optional dependency: the pipeline keeps working without it."""
from __future__ import annotations

from pathlib import Path

from ..config import Config
from .base import make_result

try:
    import yara
except ImportError:  # pragma: no cover
    yara = None

SOURCE = "yara"
RULE_SUFFIXES = {".yar", ".yara"}


def collect_rule_files(directories: list[Path]) -> list[Path]:
    files: list[Path] = []
    for directory in directories:
        directory = Path(directory)
        if directory.is_file() and directory.suffix.lower() in RULE_SUFFIXES:
            files.append(directory)
        elif directory.is_dir():
            files += sorted(p for p in directory.rglob("*") if p.suffix.lower() in RULE_SUFFIXES)
    return files


def scan(path: str | Path, config: Config) -> dict:
    if yara is None:
        return make_result(SOURCE, "unavailable", "yara-python not installed (pip install 'malvexis[yara]')")

    rule_files = collect_rule_files(config.rules_dirs)
    if not rule_files:
        return make_result(SOURCE, "unavailable", "No YARA rule files found (use --rules DIR or MALVEXIS_RULES_DIR)")

    compiled, skipped = [], []
    for rule_file in rule_files:
        try:
            compiled.append((rule_file, yara.compile(filepath=str(rule_file))))
        except yara.Error as exc:
            skipped.append({"file": str(rule_file), "error": str(exc)})

    if not compiled:
        return make_result(SOURCE, "error", "All YARA rule files failed to compile", {"skipped": skipped})

    matches = []
    for rule_file, rules in compiled:
        try:
            for m in rules.match(filepath=str(path), timeout=60):
                meta = m.meta or {}
                matches.append(
                    {
                        "rule": m.rule,
                        "namespace": m.namespace,
                        "rule_file": str(rule_file),
                        "tags": list(m.tags),
                        "description": meta.get("description", ""),
                        "severity": str(meta.get("severity", "medium")).lower(),
                        "author": meta.get("author", ""),
                    }
                )
        except yara.Error as exc:
            skipped.append({"file": str(rule_file), "error": f"scan failed: {exc}"})

    return make_result(
        SOURCE,
        "ok",
        data={"rules_loaded": len(compiled), "rules_skipped": skipped, "matches": matches},
    )
