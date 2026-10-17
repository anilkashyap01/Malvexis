import hashlib
import os

from malvexis.core import entropy, filetype, hashing, indicators, pe_analysis, strings


def test_hashes_match_known_vectors(tmp_path):
    f = tmp_path / "abc.bin"
    f.write_bytes(b"abc")
    h = hashing.compute_hashes(f)
    assert h["sha256"] == hashlib.sha256(b"abc").hexdigest()
    assert h["md5"] == "900150983cd24fb0d6963f7d28e17f72"
    assert h["size"] == 3


def test_entropy_extremes():
    assert entropy.shannon_entropy(b"\x00" * 1000) == 0.0
    assert entropy.shannon_entropy(bytes(range(256)) * 4) == 8.0
    assert entropy.analyze_entropy(os.urandom(200_000))["label"] == "high"
    assert entropy.analyze_entropy(b"")["overall"] == 0.0


def test_filetype_detection_and_mismatch(make_pe, tmp_path):
    exe = make_pe("good.exe")
    assert filetype.identify_file(exe)["type"] == "pe"
    assert not filetype.identify_file(exe)["extension_mismatch"]

    disguised = tmp_path / "invoice.pdf"
    disguised.write_bytes(exe.read_bytes())
    info = filetype.identify_file(disguised)
    assert info["type"] == "pe" and info["extension_mismatch"]

    pdf = tmp_path / "doc.pdf"
    pdf.write_bytes(b"%PDF-1.7 hello")
    assert filetype.identify_file(pdf)["type"] == "pdf"

    mz_only = tmp_path / "dos.exe"
    mz_only.write_bytes(b"MZ" + b"\x00" * 100)
    assert filetype.identify_file(mz_only)["type"] == "dos_mz"


def test_strings_extraction_and_iocs():
    blob = b"\x00\x01http://evil.example/payload.bin\x00\x02" + "C:\\Users\\Public\\x.exe".encode("utf-16-le") + b"\x00\x00" + b"WriteProcessMemory\x00 10.1.2.3 \x00powershell -enc AAA"
    out = strings.analyze_strings(blob)
    ind = out["indicators"]
    assert "http://evil.example/payload.bin" in ind["urls"]
    assert "10.1.2.3" in ind["ips"]
    assert "WriteProcessMemory" in ind["suspicious_apis"]
    assert any("Users" in p for p in ind["file_paths"])
    assert "powershell" in ind["suspicious_keywords"]
    assert out["unicode_count"] >= 1


def test_ignored_ips_and_bad_octets():
    ind = strings.classify_strings(["0.0.0.0", "999.1.1.1", "8.8.8.8"])
    assert ind["ips"] == ["8.8.8.8"]


def test_classify_api_handles_suffixes():
    assert indicators.classify_api("CreateProcessA") == "execution"
    assert indicators.classify_api("ZwWriteVirtualMemory") == "injection"
    assert indicators.classify_api("printf") is None


def test_pe_analysis_basic_fields(make_pe):
    pe = pe_analysis.analyze_pe(make_pe())
    assert pe["valid"] and pe["machine"] == "x86"
    assert pe["sections"][0]["name"] == ".text"
    assert pe["sections"][0]["executable"] and not pe["sections"][0]["writable"]
    assert pe["import_count"] == 0
    assert pe["overlay_size"] == 0


def test_pe_flags_wx_highentropy_packer_and_overlay(make_pe):
    sections = [(b"UPX0", os.urandom(4096), 0xE0000020), (b".text", b"\x90" * 512, 0x60000020)]
    pe = pe_analysis.analyze_pe(make_pe(sections=sections, overlay=b"A" * 2000, timestamp=0))
    flags = pe["sections"][0]["flags"]
    assert {"writable_and_executable", "high_entropy", "packer_section_name"} <= set(flags)
    assert pe["packers"] == ["UPX"]
    assert pe["overlay_size"] == 2000
    assert "zeroed" in pe["timestamp_flags"]


def test_pe_analysis_rejects_garbage(tmp_path):
    bad = tmp_path / "bad.exe"
    bad.write_bytes(b"MZ" + b"\x00" * 200)
    assert pe_analysis.analyze_pe(bad)["valid"] is False


def test_classify_imports():
    hits = pe_analysis.classify_imports({"kernel32.dll": ["WriteProcessMemory", "CreateRemoteThread", "ExitProcess"]})
    assert {h["api"] for h in hits} == {"WriteProcessMemory", "CreateRemoteThread"}
