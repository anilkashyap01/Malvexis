"""PE header analysis via pefile. Parses the file; never executes it."""
from __future__ import annotations

import datetime as dt
from pathlib import Path

import pefile

from .entropy import HIGH, shannon_entropy
from .indicators import PACKER_SECTIONS, classify_api

MACHINE_NAMES = {0x14C: "x86", 0x8664: "x64", 0x1C0: "ARM", 0xAA64: "ARM64", 0x200: "IA64"}
SUBSYSTEM_NAMES = {1: "native", 2: "windows_gui", 3: "windows_cui", 9: "windows_ce_gui", 10: "efi_application"}

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_DIRECTORY_ENTRY_SECURITY = 4
MAX_FUNCS_PER_DLL = 200


def _decode(value: bytes | None) -> str:
    return value.rstrip(b"\x00").decode("ascii", errors="replace") if value else ""


def classify_imports(imports: dict[str, list[str]]) -> list[dict]:
    """Pure helper: map {dll: [functions]} to a list of suspicious {api, category, dll}."""
    hits = []
    for dll, funcs in imports.items():
        for func in funcs:
            category = classify_api(func)
            if category:
                hits.append({"api": func, "category": category, "dll": dll})
    return hits


def _analyze_sections(pe: pefile.PE) -> list[dict]:
    sections = []
    for sec in pe.sections:
        data = sec.get_data()
        entropy = shannon_entropy(data)
        chars = sec.Characteristics
        executable = bool(chars & IMAGE_SCN_MEM_EXECUTE)
        writable = bool(chars & IMAGE_SCN_MEM_WRITE)
        name = _decode(sec.Name)
        flags = []
        if executable and writable:
            flags.append("writable_and_executable")
        if entropy >= HIGH:
            flags.append("high_entropy")
        if sec.SizeOfRawData == 0 and sec.Misc_VirtualSize > 0 and executable:
            flags.append("executable_but_empty_on_disk")
        if name.lower() in PACKER_SECTIONS:
            flags.append("packer_section_name")
        sections.append(
            {
                "name": name,
                "virtual_address": hex(sec.VirtualAddress),
                "virtual_size": sec.Misc_VirtualSize,
                "raw_size": sec.SizeOfRawData,
                "entropy": entropy,
                "readable": bool(chars & IMAGE_SCN_MEM_READ),
                "writable": writable,
                "executable": executable,
                "flags": flags,
            }
        )
    return sections


def _analyze_imports(pe: pefile.PE) -> tuple[dict[str, list[str]], int]:
    imports: dict[str, list[str]] = {}
    total = 0
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = _decode(entry.dll).lower()
        funcs = []
        for imp in entry.imports:
            total += 1
            funcs.append(_decode(imp.name) if imp.name else f"ordinal_{imp.ordinal}")
        imports.setdefault(dll, []).extend(funcs[:MAX_FUNCS_PER_DLL])
    return imports, total


def _analyze(pe: pefile.PE, file_size: int) -> dict:
    fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER

    # compile timestamp
    ts = fh.TimeDateStamp
    ts_iso, ts_flags = None, []
    try:
        ts_iso = dt.datetime.fromtimestamp(ts, dt.timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        ts_flags.append("invalid")
    if ts == 0:
        ts_flags.append("zeroed")
    elif ts > (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1)).timestamp():
        ts_flags.append("in_future")

    sections = _analyze_sections(pe)
    imports, import_count = _analyze_imports(pe)

    ep = oh.AddressOfEntryPoint
    ep_section = pe.get_section_by_rva(ep) if ep else None
    ep_section_name = _decode(ep_section.Name) if ep_section else None
    last_section_name = sections[-1]["name"] if sections else None

    exports = []
    for sym in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", []) or []:
        if sym.name:
            exports.append(_decode(sym.name))

    packers = sorted({PACKER_SECTIONS[s["name"].lower()] for s in sections if s["name"].lower() in PACKER_SECTIONS})

    overlay_offset = pe.get_overlay_data_start_offset()
    overlay_size = max(0, file_size - overlay_offset) if overlay_offset else 0

    try:
        imphash = pe.get_imphash() or None
    except Exception:  # pragma: no cover - malformed import tables
        imphash = None

    security_dir = oh.DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_SECURITY] if len(oh.DATA_DIRECTORY) > IMAGE_DIRECTORY_ENTRY_SECURITY else None

    return {
        "valid": True,
        "machine": MACHINE_NAMES.get(fh.Machine, hex(fh.Machine)),
        "is_dll": bool(fh.Characteristics & 0x2000),
        "subsystem": SUBSYSTEM_NAMES.get(oh.Subsystem, str(oh.Subsystem)),
        "is_driver": oh.Subsystem == 1,
        "compile_timestamp": ts_iso,
        "timestamp_flags": ts_flags,
        "entry_point": hex(ep),
        "entry_point_section": ep_section_name,
        "entry_point_in_last_section": bool(ep_section_name and ep_section_name == last_section_name and len(sections) > 1),
        "image_base": hex(oh.ImageBase),
        "sections": sections,
        "imports": imports,
        "import_count": import_count,
        "suspicious_imports": classify_imports(imports),
        "exports": exports[:200],
        "imphash": imphash,
        "packers": packers,
        "overlay_size": overlay_size,
        "has_signature_blob": bool(security_dir and security_dir.VirtualAddress),  # presence only, NOT validated
    }


def analyze_pe(path: str | Path) -> dict:
    path = Path(path)
    try:
        pe = pefile.PE(str(path))
    except pefile.PEFormatError as exc:
        return {"valid": False, "error": f"Not a parseable PE file: {exc}"}
    try:
        return _analyze(pe, path.stat().st_size)
    except Exception as exc:  # malformed samples are normal here; report instead of crashing
        return {"valid": False, "error": f"PE analysis failed: {type(exc).__name__}: {exc}"}
    finally:
        pe.close()
