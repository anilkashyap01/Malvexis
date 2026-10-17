"""Run the REAL tools against harmless fixtures. Skipped automatically when a tool or fixture is missing.

Build fixtures with:  scripts/build_fixtures.sh   (needs mingw-w64, optionally upx)
capa also needs:      CAPA_RULES_DIR and CAPA_SIGS_DIR environment variables.
"""
import os
import shutil
import sys
from pathlib import Path

import pytest

from malvexis.config import Config
from malvexis.pipeline import analyze_file
from malvexis.tools import capa_tool, clamav_tool, die_tool, floss_tool, runner

BUILD = Path(__file__).parent / "fixtures" / "build"
DEMO = BUILD / "benign_demo.exe"
PACKED = BUILD / "benign_packed.exe"


def _have_tool(name):
    try:
        runner.find_tool(name)
        return True
    except runner.ToolNotFound:
        return False


needs_demo = pytest.mark.skipif(not DEMO.exists(), reason="run scripts/build_fixtures.sh first")
needs_packed = pytest.mark.skipif(not PACKED.exists(), reason="packed fixture needs upx + scripts/build_fixtures.sh")


@needs_packed
def test_die_detects_upx_on_real_packed_exe():
    pytest.importorskip("die")
    res = die_tool.scan(PACKED, Config())
    assert res["status"] == "ok", res
    assert any("UPX" in p for p in res["data"]["packers"])


@needs_demo
def test_die_finds_no_packer_on_plain_exe():
    pytest.importorskip("die")
    res = die_tool.scan(DEMO, Config())
    assert res["status"] == "ok" and res["data"]["packers"] == []


@needs_demo
@pytest.mark.skipif(not _have_tool("clamscan"), reason="clamscan not installed")
def test_clamav_with_custom_signature_and_missing_db(tmp_path):
    import hashlib

    data = DEMO.read_bytes()
    (tmp_path / "test.hdb").write_text(f"{hashlib.md5(data).hexdigest()}:{len(data)}:Malvexis.Test.Signature\n")
    hit = clamav_tool.scan(DEMO, Config(clamav_db_dir=tmp_path))
    assert hit["status"] == "ok" and hit["data"]["infected"] and hit["data"]["signature"].startswith("Malvexis.Test.Signature")

    empty = tmp_path / "empty"
    empty.mkdir()
    bad = clamav_tool.scan(DEMO, Config(clamav_db_dir=empty))
    assert bad["status"] == "error"


@needs_demo
@pytest.mark.skipif(not (_have_tool("capa") and os.getenv("CAPA_RULES_DIR") and os.getenv("CAPA_SIGS_DIR")), reason="capa or CAPA_RULES_DIR/CAPA_SIGS_DIR missing")
def test_capa_real_run():
    cfg = Config(capa_rules_dir=Path(os.environ["CAPA_RULES_DIR"]), capa_sigs_dir=Path(os.environ["CAPA_SIGS_DIR"]))
    res = capa_tool.scan(DEMO, cfg)
    assert res["status"] == "ok", res
    names = {c["name"] for c in res["data"]["capabilities"]}
    assert "write file on Windows" in names and "get hostname" in names
    assert "T1082" in {t["id"] for t in res["data"]["attack"]}


@needs_demo
@pytest.mark.skipif(not _have_tool("floss"), reason="floss not installed")
def test_floss_recovers_stack_string():
    res = floss_tool.scan(DEMO, Config())
    assert res["status"] == "ok", res
    assert "malvexis_stack_demo" in res["data"]["strings"]["stack"]


@needs_packed
def test_full_pipeline_with_real_tools_on_packed_exe():
    pytest.importorskip("die")
    res = analyze_file(PACKED, Config(), offline=True)
    assert res["tools"]["die"]["status"] == "ok"
    assert any("UPX" in r["detail"] for r in res["score"]["reasons"])
    assert any("confirmed by Detect It Easy" in r["detail"] for r in res["score"]["reasons"])
