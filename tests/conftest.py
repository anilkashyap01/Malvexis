"""Shared fixtures: a tiny hand-built PE and a runtime-assembled EICAR file."""
from __future__ import annotations

import struct

import pytest


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def build_pe(sections=None, timestamp=1_600_000_000, machine=0x14C, overlay=b"") -> bytes:
    """Build a minimal, parseable PE32 image. sections = [(name_bytes, data_bytes, characteristics)]."""
    sections = sections or [(b".text", b"\x90" * 512, 0x60000020)]
    assert len(sections) <= 4
    headers_size = 0x200

    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)

    size_opt = 224
    file_header = struct.pack("<HHIIIHH", machine, len(sections), timestamp, 0, 0, size_opt, 0x0102)

    section_headers, raw_blobs = b"", b""
    va, raw_ptr = 0x1000, headers_size
    for name, data, chars in sections:
        raw_size = _align(len(data), 0x200)
        section_headers += struct.pack("<8sIIIIIIHHI", name, len(data), va, raw_size, raw_ptr, 0, 0, 0, 0, chars)
        raw_blobs += data.ljust(raw_size, b"\x00")
        va += _align(len(data), 0x1000)
        raw_ptr += raw_size
    size_of_image = va

    opt = struct.pack("<HBBIIIIII", 0x10B, 14, 0, 0x200, 0, 0, 0x1000, 0x1000, 0x2000)
    opt += struct.pack("<3I6H4I2H6I", 0x400000, 0x1000, 0x200, 6, 0, 0, 0, 6, 0, 0, size_of_image, headers_size, 0, 3, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    opt += b"\x00" * (16 * 8)
    assert len(opt) == size_opt

    headers = (bytes(dos) + b"PE\x00\x00" + file_header + opt + section_headers).ljust(headers_size, b"\x00")
    return headers + raw_blobs + overlay


@pytest.fixture
def make_pe(tmp_path):
    def _make(name="sample.exe", **kwargs):
        path = tmp_path / name
        path.write_bytes(build_pe(**kwargs))
        return path

    return _make


@pytest.fixture
def eicar_file(tmp_path):
    # Assembled at runtime so the repo and zip never contain the full signature (avoids AV false alarms)
    sig = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" + "!$H+H*"
    path = tmp_path / "eicar.com"
    path.write_text(sig)
    return path
