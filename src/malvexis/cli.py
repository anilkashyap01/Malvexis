"""Command line interface: `malvexis scan <file-or-folder>`."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .config import Config
from .intel.cache import Cache
from .pipeline import analyze_file
from .report.html_report import write_html
from .report.json_report import to_json, write_json

VERDICT_LABELS = {"low_risk": "LOW RISK", "suspicious": "SUSPICIOUS", "likely_malicious": "LIKELY MALICIOUS"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="malvexis", description="Malvexis - malware research and threat intelligence (static analysis only)")
    parser.add_argument("--version", action="version", version=f"malvexis {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="analyze a file, or every file in a folder")
    scan.add_argument("target", help="file or folder to analyze")
    scan.add_argument("-r", "--recursive", action="store_true", help="recurse into sub-folders (folder targets)")
    scan.add_argument("--offline", action="store_true", help="skip VirusTotal and MalwareBazaar lookups (YARA still runs)")
    scan.add_argument("--no-cache", action="store_true", help="do not read or write the local lookup cache")
    scan.add_argument("--rules", action="append", metavar="DIR", help="YARA rules file or folder (repeatable)")
    scan.add_argument("--json", metavar="FILE", help="write JSON report to FILE ('-' prints JSON to stdout)")
    scan.add_argument("--html", metavar="FILE", help="write HTML report to FILE (single-file scans)")
    scan.add_argument("--clamav", action="store_true", help="also scan with ClamAV (needs clamscan + signatures; loads the DB each run)")
    scan.add_argument("--capa", action="store_true", help="also run capa capability detection + ATT&CK mapping (slow; needs rules and sigs, see README)")
    scan.add_argument("--floss", action="store_true", help="also recover obfuscated strings with FLOSS (slow)")
    scan.add_argument("--tool-timeout", type=int, metavar="SEC", help="timeout per external tool run (default 300)")
    scan.add_argument("--out-dir", metavar="DIR", help="write <name>.<sha256-prefix>.json/.html per sample (good for batches)")
    return parser


def _collect_targets(target: Path, recursive: bool) -> list[Path]:
    if target.is_file():
        return [target]
    pattern = target.rglob("*") if recursive else target.glob("*")
    return sorted(p for p in pattern if p.is_file())


def _print_summary(result: dict) -> None:
    score = result["score"]
    f, h, t = result["file"], result["hashes"], result["filetype"]
    print(f"File:     {f['name']} ({f['size']:,} bytes)")
    print(f"Type:     {t['description']}" + ("  [extension mismatch]" if t["extension_mismatch"] else ""))
    print(f"SHA-256:  {h['sha256']}")
    print(f"Entropy:  {result['entropy']['overall']} ({result['entropy']['label']})")
    print(f"Verdict:  {VERDICT_LABELS[score['verdict']]} (score {score['score']}/100)")
    for reason in score["reasons"]:
        if reason["points"]:
            print(f"   {reason['points']:+d}".ljust(8) + f"[{reason['signal']}] {reason['detail']}")
    answered = ", ".join(score["sources_answered"]) or "none"
    print(f"Sources:  answered: {answered}")
    for src in score["sources_unavailable"]:
        print(f"          {src['source']}: {src['status']} - {src['message']}")
    _print_tools(result)
    for note in score["notes"]:
        print(f"Note:     {note}")
    for err in result["errors"]:
        print(f"Error:    {err}")


def _tool_summary(name: str, res: dict) -> str:
    if res["status"] != "ok":
        return f"{res['status']} - {res['message']}"
    d = res["data"]
    if name == "die":
        return "; ".join(x["string"] for x in d["detections"] if x["string"]) or "nothing identified"
    if name == "clamav":
        return f"INFECTED: {d['signature']}" if d["infected"] else "no signature match"
    if name == "capa":
        ids = ", ".join(t["id"] for t in d["attack"][:8]) or "none"
        return f"{d['capability_count']} capabilities; ATT&CK: {ids}"
    if name == "floss":
        c = d["counts"]
        return f"{c['stack']} stack, {c['tight']} tight, {c['decoded']} decoded strings"
    return "ok"


def _print_tools(result: dict) -> None:
    requested = set(result.get("options", {}).get("tools", []))
    for name, res in result.get("tools", {}).items():
        if res["status"] == "unavailable" and name not in requested:
            continue  # optional tool the user did not ask for and does not have: stay quiet
        print(f"Tool:     {name}: {_tool_summary(name, res)}")


def _print_batch_line(result: dict) -> None:
    score = result["score"]
    print(f"{VERDICT_LABELS[score['verdict']]:<17} {score['score']:>3}  {result['hashes']['sha256'][:16]}  {result['file']['name']}")


def _write_per_sample(result: dict, out_dir: Path) -> None:
    stem = f"{result['file']['name']}.{result['hashes']['sha256'][:12]}"
    write_json(result, out_dir / f"{stem}.json")
    write_html(result, out_dir / f"{stem}.html")


def cmd_scan(args: argparse.Namespace) -> int:
    target = Path(args.target)
    if not target.exists():
        print(f"error: {target} does not exist", file=sys.stderr)
        return 2

    files = _collect_targets(target, args.recursive)
    if not files:
        print(f"error: no files found in {target}", file=sys.stderr)
        return 2
    batch = target.is_dir()
    if batch and args.html:
        print("error: --html works on a single file; use --out-dir for folders", file=sys.stderr)
        return 2

    config = Config.from_env(rules_dirs=args.rules)
    config.use_cache = not args.no_cache
    if args.tool_timeout:
        config.tool_timeout = args.tool_timeout
    tools = [name for name in ("clamav", "capa", "floss") if getattr(args, name)]
    cache = Cache(config.cache_dir, config.cache_ttl) if (config.use_cache and not args.offline) else None

    json_to_stdout = args.json == "-"
    results = []
    try:
        for path in files:
            try:
                result = analyze_file(path, config, offline=args.offline, cache=cache, tools=tools)
            except OSError as exc:
                print(f"error: cannot read {path}: {exc}", file=sys.stderr)
                continue
            results.append(result)
            if args.out_dir:
                _write_per_sample(result, Path(args.out_dir))
            if json_to_stdout:
                continue
            if batch:
                _print_batch_line(result)
            else:
                _print_summary(result)
    finally:
        if cache:
            cache.close()

    if not results:
        return 2

    payload = results if batch else results[0]
    if json_to_stdout:
        print(to_json(payload))
    elif args.json:
        print(f"JSON report: {write_json(payload, args.json)}")
    if args.html:
        print(f"HTML report: {write_html(results[0], args.html)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        return cmd_scan(args)
    return 2  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
