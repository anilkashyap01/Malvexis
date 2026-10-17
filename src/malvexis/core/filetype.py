"""Identify a file by its magic bytes instead of trusting the extension."""
from __future__ import annotations

import struct
from pathlib import Path

HEADER_BYTES = 4096

# type key -> (description, extensions normally used for it)
TYPE_INFO: dict[str, tuple[str, tuple[str, ...]]] = {
    "pe": ("Windows PE executable/library", (".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".efi")),
    "dos_mz": ("DOS MZ executable (no PE header)", (".exe", ".com")),
    "elf": ("Linux/Unix ELF binary", (".so", ".o", ".elf", ".bin", "")),
    "macho": ("macOS Mach-O binary", (".dylib", ".bundle", ".o", "")),
    "pdf": ("PDF document", (".pdf",)),
    "ole2": ("OLE2 compound file (legacy Office)", (".doc", ".xls", ".ppt", ".msi", ".msg")),
    "zip": ("ZIP archive (also docx/xlsx/jar/apk)", (".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk", ".odt")),
    "rar": ("RAR archive", (".rar",)),
    "7z": ("7-Zip archive", (".7z",)),
    "gzip": ("gzip archive", (".gz", ".tgz")),
    "script": ("Script with shebang", (".sh", ".py", ".pl", ".rb", "")),
    "lnk": ("Windows shortcut (LNK)", (".lnk",)),
    "unknown": ("Unknown / plain data", ()),
}


def _is_pe(header: bytes) -> bool:
    if len(header) < 0x40 or header[:2] != b"MZ":
        return False
    (e_lfanew,) = struct.unpack_from("<I", header, 0x3C)
    if e_lfanew + 4 <= len(header):
        return header[e_lfanew : e_lfanew + 4] == b"PE\x00\x00"
    # PE header lies beyond what we read: verify by reading it from disk in identify_file
    return False


def detect_type(header: bytes, path: Path | None = None) -> str:
    """Return a TYPE_INFO key for the given header bytes."""
    if header[:2] == b"MZ":
        if _is_pe(header):
            return "pe"
        if path is not None and len(header) >= 0x40:
            (e_lfanew,) = struct.unpack_from("<I", header, 0x3C)
            try:
                with path.open("rb") as fh:
                    fh.seek(e_lfanew)
                    if fh.read(4) == b"PE\x00\x00":
                        return "pe"
            except OSError:
                pass
        return "dos_mz"
    if header[:4] == b"\x7fELF":
        return "elf"
    if header[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "macho"
    if header[:5] == b"%PDF-":
        return "pdf"
    if header[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole2"
    if header[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return "zip"
    if header[:6] == b"Rar!\x1a\x07":
        return "rar"
    if header[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    if header[:2] == b"\x1f\x8b":
        return "gzip"
    if header[:4] == b"L\x00\x00\x00" and header[4:20] == bytes.fromhex("0114020000000000c000000000000046"):
        return "lnk"
    if header[:2] == b"#!":
        return "script"
    return "unknown"


def identify_file(path: str | Path) -> dict:
    path = Path(path)
    with path.open("rb") as fh:
        header = fh.read(HEADER_BYTES)
    key = detect_type(header, path)
    description, expected = TYPE_INFO[key]
    ext = path.suffix.lower()
    mismatch = bool(expected) and ext not in expected
    return {
        "type": key,
        "description": description,
        "extension": ext,
        "extension_mismatch": mismatch,
        "expected_extensions": list(expected),
    }
