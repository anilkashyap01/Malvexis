import json
from pathlib import Path

import pytest

from malvexis.cli import main
from malvexis.report.html_report import render_html
from malvexis.scoring import score_result, verdict_for

RULES = Path(__file__).resolve().parent.parent / "rules"


def base_result(**over):
    r = {"filetype": {"type": "pe", "extension_mismatch": False}, "pe": {"valid": True, "sections": [], "suspicious_imports": [], "import_count": 50}, "entropy": {"label": "normal"}, "strings": {"indicators": {}}, "intel": {}}
    r.update(over)
    return r


def test_verdict_thresholds():
    assert verdict_for(0) == "low_risk" and verdict_for(24) == "low_risk"
    assert verdict_for(25) == "suspicious" and verdict_for(59) == "suspicious"
    assert verdict_for(60) == "likely_malicious"


def test_clean_file_is_low_risk_with_local_only_note():
    out = score_result(base_result())
    assert out["score"] == 0 and out["verdict"] == "low_risk"
    assert any("local analysis only" in n for n in out["notes"])


def test_virustotal_detections_drive_verdict():
    intel = {"virustotal": {"status": "ok", "data": {"malicious": 40, "total_engines": 70}}, "malwarebazaar": {"status": "not_found"}}
    out = score_result(base_result(intel=intel))
    assert out["verdict"] == "likely_malicious"
    assert set(out["sources_answered"]) == {"virustotal", "malwarebazaar"}


def test_rate_limit_is_listed_as_unavailable_and_scan_continues():
    intel = {"virustotal": {"status": "rate_limited", "message": "slow down"}, "malwarebazaar": {"status": "ok", "data": {"signature": "Emotet"}}}
    out = score_result(base_result(intel=intel))
    assert out["sources_unavailable"][0]["source"] == "virustotal"
    assert out["score"] == 50


def test_injection_imports_need_two_apis():
    one = base_result(pe={"valid": True, "sections": [], "import_count": 50, "suspicious_imports": [{"api": "WriteProcessMemory", "category": "injection", "dll": "k"}]})
    two = base_result(pe={"valid": True, "sections": [], "import_count": 50, "suspicious_imports": [{"api": "WriteProcessMemory", "category": "injection", "dll": "k"}, {"api": "CreateRemoteThread", "category": "injection", "dll": "k"}]})
    assert score_result(one)["score"] == 0
    assert score_result(two)["score"] == 20


def test_yara_contribution_is_capped():
    matches = [{"rule": f"r{i}", "severity": "high", "description": ""} for i in range(5)]
    out = score_result(base_result(intel={"yara": {"status": "ok", "data": {"matches": matches}}}))
    assert out["score"] == 60


def test_cli_offline_scan_json_and_html(eicar_file, tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    code = main(["scan", str(eicar_file), "--offline", "--rules", str(RULES), "--json", str(tmp_path / "r.json"), "--html", str(tmp_path / "r.html")])
    assert code == 0
    data = json.loads((tmp_path / "r.json").read_text())
    assert data["hashes"]["sha256"] and data["file"]["name"] == "eicar.com"
    assert (tmp_path / "r.html").read_text().startswith("<!doctype html>")
    if data["intel"]["yara"]["status"] == "ok":
        assert data["score"]["verdict"] == "likely_malicious"
    assert "Verdict:" in capsys.readouterr().out


def test_cli_batch_and_out_dir(make_pe, tmp_path, capsys):
    folder = tmp_path / "batch"
    folder.mkdir()
    (folder / "a.exe").write_bytes(make_pe("tmp_a.exe").read_bytes())
    (folder / "b.txt").write_text("hello")
    out_dir = tmp_path / "out"
    assert main(["scan", str(folder), "--offline", "--out-dir", str(out_dir)]) == 0
    assert len(list(out_dir.glob("*.json"))) == 2 and len(list(out_dir.glob("*.html"))) == 2
    assert main(["scan", str(folder), "--html", "x.html"]) == 2


def test_cli_missing_target(tmp_path):
    assert main(["scan", str(tmp_path / "nope")]) == 2


def test_html_report_escapes_hostile_strings(make_pe):
    from malvexis.config import Config
    from malvexis.pipeline import analyze_file

    pe_path = make_pe()
    result = analyze_file(pe_path, Config(), offline=True)
    result["strings"]["indicators"]["urls"] = ["http://x/<script>alert(1)</script>"]
    html = render_html(result)
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html


def test_cli_no_args_prints_banner_and_author(capsys):
    assert main([]) == 0
    out = capsys.readouterr().out
    assert "MALVEXIS" in out
    assert "https://github.com/anilkashyap01" in out
    assert "Usage:" in out


def test_cli_scan_prints_banner(eicar_file, capsys):
    assert main(["scan", str(eicar_file), "--offline"]) == 0
    out = capsys.readouterr().out
    assert "MALVEXIS" in out
    assert "https://github.com/anilkashyap01" in out
    assert "Verdict:" in out
