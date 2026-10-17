"""Unit tests for the external-tool wrappers. Real captured tool output lives in tests/data/."""
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from malvexis import tools as tools_pkg
from malvexis.config import Config
from malvexis.pipeline import analyze_file
from malvexis.scoring import score_result
from malvexis.tools import capa_tool, clamav_tool, die_tool, floss_tool, runner

DATA = Path(__file__).parent / "data"


# ---------------------------------------------------------------- runner ----
def test_runner_rejects_unlisted_tools():
    with pytest.raises(ValueError):
        runner.find_tool("bash")
    with pytest.raises(ValueError):
        runner.run_tool("../../bin/sh", [], 5)


def test_runner_tool_not_found(monkeypatch, tmp_path):
    monkeypatch.setattr(runner.sys, "executable", str(tmp_path / "python"))
    monkeypatch.setattr(runner.shutil, "which", lambda name: None)
    with pytest.raises(runner.ToolNotFound):
        runner.find_tool("capa")


def test_runner_uses_argv_list_no_shell_timeout(monkeypatch):
    seen = {}

    def fake_run(argv, **kwargs):
        seen["argv"], seen["kwargs"] = argv, kwargs
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(runner, "find_tool", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    assert runner.run_tool("clamscan", ["--no-summary", "/x; rm -rf /"], 7) == (0, "ok", "")
    assert seen["argv"] == ["/usr/bin/clamscan", "--no-summary", "/x; rm -rf /"]  # one argv item, never a shell string
    assert seen["kwargs"]["shell"] is False and seen["kwargs"]["timeout"] == 7 and seen["kwargs"]["stdin"] == subprocess.DEVNULL


def test_runner_output_cap(monkeypatch):
    monkeypatch.setattr(runner, "find_tool", lambda name: name)
    monkeypatch.setattr(runner, "MAX_OUTPUT_BYTES", 5)
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0, stdout="x" * 10, stderr=""))
    with pytest.raises(runner.ToolOutputTooLarge):
        runner.run_tool("capa", [], 5)


# ------------------------------------------------------------------- DIE ----
def test_die_parse_real_output_for_packed_exe():
    out = die_tool.parse_die_output((DATA / "die_packed.json").read_text())
    assert out["filetype"] == "PE64"
    assert out["packers"] == ["Packer: UPX(4.22)[NRV,best]"]
    assert out["detections"][0]["name"] == "UPX" and out["detections"][0]["version"] == "4.22"


def test_die_parse_ignores_unknown_and_warnings():
    unknown = {"detects": [{"filetype": "PE64", "values": [{"type": "Unknown", "name": "Unknown", "string": "Unknown: Unknown"}]}]}
    assert die_tool.parse_die_output(json.dumps(unknown))["detections"] == []
    warn = {"detects": [{"filetype": "PE64", "values": [{"type": "(Heur)Warning", "name": "x", "string": "w"}]}]}
    assert die_tool.parse_die_output(json.dumps(warn))["detections"] == []
    assert die_tool.parse_die_output('{"detects": []}')["packers"] == []


def test_die_unavailable_without_library(monkeypatch, tmp_path):
    monkeypatch.setattr(die_tool, "die", None)
    assert die_tool.scan(tmp_path, Config())["status"] == "unavailable"


def test_die_loads_database_once_and_reports_errors(monkeypatch, tmp_path):
    calls = {"load": 0}
    fake = SimpleNamespace(
        database_path=tmp_path,
        ScanFlags=SimpleNamespace(DEEP_SCAN=1, RESULT_AS_JSON=2),
        load_database=lambda p: calls.__setitem__("load", calls["load"] + 1),
        scan_file=lambda p, f: (DATA / "die_packed.json").read_text(),
    )
    monkeypatch.setattr(die_tool, "die", fake)
    monkeypatch.setattr(die_tool, "_db_loaded", False)
    assert die_tool.scan(tmp_path, Config())["status"] == "ok"
    assert die_tool.scan(tmp_path, Config())["status"] == "ok"
    assert calls["load"] == 1

    fake.scan_file = lambda p, f: (_ for _ in ()).throw(RuntimeError("engine crashed"))
    assert die_tool.scan(tmp_path, Config())["status"] == "error"


# ---------------------------------------------------------------- ClamAV ----
def test_clamscan_exit_codes():
    ok = clamav_tool.parse_clamscan(0, "/s: OK\n", "", "/s")
    assert ok["data"] == {"infected": False, "signature": None}
    hit = clamav_tool.parse_clamscan(1, "/s: Malvexis.Test.Signature.UNOFFICIAL FOUND\n", "", "/s")
    assert hit["data"] == {"infected": True, "signature": "Malvexis.Test.Signature.UNOFFICIAL"}
    # a path containing ": " must not confuse signature extraction
    odd = clamav_tool.parse_clamscan(1, "/a: b/s: Win.Test FOUND\n", "", "/a: b/s")
    assert odd["data"]["signature"] == "Win.Test"


def test_clamscan_missing_database_gives_freshclam_hint():
    stderr = "LibClamAV Error: cli_loaddbdir: No supported database files found in /var/lib/clamav\nERROR: Can't open file or directory\n"  # real output
    res = clamav_tool.parse_clamscan(2, "", stderr, "/s")
    assert res["status"] == "error" and "freshclam" in res["message"] and "database" in res["message"]


def test_clamav_scan_paths(monkeypatch, tmp_path):
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"x")
    seen = {}
    monkeypatch.setattr(clamav_tool, "run_tool", lambda name, args, t: seen.update(args=args, name=name) or (0, "", ""))
    clamav_tool.scan(sample, Config(clamav_db_dir=tmp_path))
    assert seen["name"] == "clamscan" and seen["args"][-1] == str(sample.resolve()) and "-d" in seen["args"]

    def missing(*a):
        raise runner.ToolNotFound("clamscan")

    monkeypatch.setattr(clamav_tool, "run_tool", missing)
    assert clamav_tool.scan(sample, Config())["status"] == "unavailable"

    def slow(*a):
        raise subprocess.TimeoutExpired("clamscan", 1)

    monkeypatch.setattr(clamav_tool, "run_tool", slow)
    assert clamav_tool.scan(sample, Config())["status"] == "error"


# ------------------------------------------------------------------ capa ----
def test_capa_parse_real_output():
    out = capa_tool.parse_capa_output((DATA / "capa_sample.json").read_text())
    names = {c["name"] for c in out["capabilities"]}
    assert {"write file on Windows", "get hostname", "delay execution"} <= names
    assert out["capability_count"] == 13
    ids = {t["id"] for t in out["attack"]}
    assert {"T1082", "T1129"} <= ids
    hostname = next(t for t in out["attack"] if t["id"] == "T1082")
    assert hostname["tactic"] and hostname["technique"]


def test_capa_needs_rules_and_sigs(tmp_path):
    res = capa_tool.scan(tmp_path, Config())
    assert res["status"] == "unavailable" and "CAPA_RULES_DIR" in res["message"]


def test_capa_scan_builds_safe_command_and_parses(monkeypatch, tmp_path):
    sample = tmp_path / "-weird name.exe"  # leading dash must not become an option
    sample.write_bytes(b"MZ")
    cfg = Config(capa_rules_dir=tmp_path / "rules", capa_sigs_dir=tmp_path / "sigs")
    seen = {}
    monkeypatch.setattr(capa_tool, "run_tool", lambda name, args, t: seen.update(args=args) or (0, (DATA / "capa_sample.json").read_text(), ""))
    res = capa_tool.scan(sample, cfg)
    assert res["status"] == "ok" and res["data"]["capability_count"] == 13
    assert seen["args"][-1] == str(sample.resolve()) and seen["args"][-1].startswith("/")


def test_capa_failure_is_cleaned(monkeypatch, tmp_path):
    cfg = Config(capa_rules_dir=tmp_path, capa_sigs_dir=tmp_path)
    monkeypatch.setattr(capa_tool, "run_tool", lambda *a: (1, "", "\x1b[31mERROR\x1b[0m   capa:  signatures missing"))
    res = capa_tool.scan(tmp_path / "x", cfg)
    assert res["status"] == "error" and "\x1b" not in res["message"] and "signatures missing" in res["message"]
    monkeypatch.setattr(capa_tool, "run_tool", lambda *a: (0, "not json", ""))
    assert capa_tool.scan(tmp_path / "x", cfg)["status"] == "error"


# ----------------------------------------------------------------- FLOSS ----
def test_floss_parse_real_output_and_min_length():
    out = floss_tool.parse_floss_output((DATA / "floss_sample.json").read_text())
    assert out["strings"]["stack"] == ["malvexis_stack_demo"]
    assert out["strings"]["decoded"] == []  # 'kpnJ' is below the minimum length
    assert out["counts"] == {"stack": 1, "tight": 1, "decoded": 0}


def test_floss_indicators_found_in_obfuscated_strings():
    body = {"strings": {"stack_strings": [{"string": "http://evil.example/c2"}, {"string": "powershell -enc AAAA"}], "decoded_strings": [{"string": "10.9.8.7"}]}}
    out = floss_tool.parse_floss_output(json.dumps(body))
    assert out["indicators"]["urls"] == ["http://evil.example/c2"]
    assert out["indicators"]["suspicious_keywords"] == ["powershell"]


def test_floss_command_puts_path_before_list_option(monkeypatch, tmp_path):
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ")
    seen = {}
    monkeypatch.setattr(floss_tool, "run_tool", lambda name, args, t: seen.update(args=args) or (0, '{"strings": {}}', ""))
    assert floss_tool.scan(sample, Config())["status"] == "ok"
    assert seen["args"][0] == str(sample.resolve())  # --no takes a list: the path must come first
    assert seen["args"][seen["args"].index("--no") + 1] == "static"


# -------------------------------------------------------------- pipeline ----
def test_pipeline_runs_requested_tools_and_skips_unsupported_types(make_pe, tmp_path, monkeypatch):
    monkeypatch.setattr(die_tool, "die", None)
    monkeypatch.setattr(capa_tool, "scan", lambda p, c: {"source": "capa", "status": "ok", "message": "", "data": {"attack": [], "capabilities": [], "capability_count": 0}})
    monkeypatch.setattr(clamav_tool, "scan", lambda p, c: {"source": "clamav", "status": "ok", "message": "", "data": {"infected": False, "signature": None}})
    res = analyze_file(make_pe(), Config(), offline=True, tools=["capa", "clamav"])
    assert set(res["tools"]) == {"die", "capa", "clamav"}  # floss was not requested
    assert res["options"] == {"offline": True, "tools": ["capa", "clamav"]}

    pdf = tmp_path / "d.pdf"
    pdf.write_bytes(b"%PDF-1.7 hello world")
    res = analyze_file(pdf, Config(), offline=True, tools=["capa", "floss"])
    assert res["tools"]["capa"]["status"] == "unavailable" and "does not analyze" in res["tools"]["capa"]["message"]
    assert res["tools"]["floss"]["status"] == "unavailable"


def test_empty_file_skips_tools(tmp_path):
    f = tmp_path / "empty.bin"
    f.write_bytes(b"")
    assert analyze_file(f, Config(), offline=True, tools=["capa"])["tools"] == {}


# --------------------------------------------------------------- scoring ----
def _base(**over):
    r = {"filetype": {"type": "pe", "extension_mismatch": False}, "pe": {"valid": True, "sections": [], "suspicious_imports": [], "import_count": 50}, "entropy": {"label": "normal"}, "strings": {"indicators": {}}, "intel": {}, "tools": {}}
    r.update(over)
    return r


def _tool(name, **data):
    return {"source": name, "status": "ok", "message": "", "data": data}


def test_clamav_hit_adds_points():
    out = score_result(_base(tools={"clamav": _tool("clamav", infected=True, signature="Win.Trojan.X")}))
    assert out["score"] == 50 and "Win.Trojan.X" in out["reasons"][0]["detail"]
    assert score_result(_base(tools={"clamav": _tool("clamav", infected=False, signature=None)}))["score"] == 0


def test_die_packer_scored_once_even_with_section_names():
    die = _tool("die", packers=["Packer: UPX(4.22)"], detections=[])
    only_die = score_result(_base(tools={"die": die}))
    assert only_die["score"] == 15 and only_die["reasons"][0]["signal"] == "detect_it_easy"

    pe = {"valid": True, "packers": ["UPX"], "sections": [], "suspicious_imports": [], "import_count": 50}
    both = score_result(_base(pe=pe, tools={"die": die}))
    assert both["score"] == 15 and "confirmed by Detect It Easy" in both["reasons"][0]["detail"]


def test_floss_hidden_indicators_add_points_and_capa_never_scores():
    floss = _tool("floss", indicators={"urls": ["http://x.example"], "ips": [], "registry_keys": [], "suspicious_keywords": []}, counts={}, strings={})
    assert score_result(_base(tools={"floss": floss}))["score"] == 10
    capa = _tool("capa", attack=[{"id": "T1055"}], capabilities=[{"name": "inject", "namespace": "host-interaction/process/inject", "attack": ["T1055"], "mbc": []}], capability_count=1)
    assert score_result(_base(tools={"capa": capa}))["score"] == 0  # informational only


# ------------------------------------------------------------------- CLI ----
def test_cli_tool_lines(make_pe, capsys, monkeypatch):
    from malvexis.cli import main

    monkeypatch.setattr(die_tool, "die", None)
    monkeypatch.setattr(runner.shutil, "which", lambda n: None)
    monkeypatch.setattr(runner.sys, "executable", "/nonexistent/python")
    pe = make_pe()
    assert main(["scan", str(pe), "--offline", "--no-cache"]) == 0
    quiet = capsys.readouterr().out
    assert "Tool:" not in quiet  # optional tools nobody asked for and nobody has: no noise

    assert main(["scan", str(pe), "--offline", "--no-cache", "--clamav", "--capa", "--floss", "--tool-timeout", "5"]) == 0
    loud = capsys.readouterr().out
    assert "Tool:     clamav: unavailable" in loud and "Tool:     capa: unavailable" in loud and "Tool:     floss: unavailable" in loud
