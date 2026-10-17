import requests

from malvexis.config import Config
from malvexis.intel import hashlookup
from malvexis.intel.cache import Cache
from malvexis.report.html_report import render_html
from malvexis.scoring import score_result

SHA = "b" * 64


class FakeResponse:
    def __init__(self, status_code=200, body=None, bad_json=False):
        self.status_code, self._body, self._bad = status_code, body, bad_json

    def json(self):
        if self._bad:
            raise ValueError("bad json")
        return self._body


KNOWN = {"FileName": "notepad.exe", "ProductName": "Windows", "source": ["NSRL"], "hashlookup:trust": 90}


def test_ok_parse(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(200, KNOWN))
    res = hashlookup.lookup(SHA, Config())
    assert res["status"] == "ok"
    assert res["data"]["trust"] == 90 and res["data"]["file_name"] == "notepad.exe" and res["data"]["source"] == "NSRL"
    assert res["data"]["known_malicious"] is None


def test_statuses(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(404, {"message": "Non existing SHA-256"}))
    assert hashlookup.lookup(SHA, Config())["status"] == "not_found"
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(429))
    assert hashlookup.lookup(SHA, Config())["status"] == "rate_limited"
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(500))
    assert hashlookup.lookup(SHA, Config())["status"] == "error"
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(200, bad_json=True))
    assert hashlookup.lookup(SHA, Config())["status"] == "error"


def test_network_error_and_cache(monkeypatch, tmp_path):
    def boom(*a, **k):
        raise requests.ConnectionError("down")

    monkeypatch.setattr(requests, "get", boom)
    assert hashlookup.lookup(SHA, Config())["status"] == "error"

    calls = []
    monkeypatch.setattr(requests, "get", lambda *a, **k: calls.append(1) or FakeResponse(200, KNOWN))
    cache = Cache(tmp_path)
    hashlookup.lookup(SHA, Config(), cache)
    assert "cached" in hashlookup.lookup(SHA, Config(), cache)["message"]
    assert len(calls) == 1
    cache.close()


def _result(hl_data, status="ok"):
    return {
        "filetype": {"type": "pe", "extension_mismatch": False},
        "pe": {"valid": True, "sections": [], "suspicious_imports": [], "import_count": 50},
        "entropy": {"label": "normal"},
        "strings": {"indicators": {}},
        "intel": {"hashlookup": {"status": status, "data": hl_data}},
    }


def test_known_good_reduces_score_but_not_below_zero():
    out = score_result(_result({"trust": 90, "source": "NSRL", "known_malicious": None}))
    assert out["score"] == 0
    assert out["reasons"][-1]["points"] == -20  # visible, listed last

    r = _result({"trust": 90, "source": "NSRL"})
    r["pe"]["packers"] = ["UPX"]  # +15 packer
    r["pe"]["sections"] = [{"name": "UPX0", "flags": ["writable_and_executable"], "entropy": 3.0}]  # +10
    assert score_result(r)["score"] == 5  # 25 - 20


def test_low_trust_does_nothing_and_known_malicious_adds():
    assert score_result(_result({"trust": 20}))["score"] == 0
    assert score_result(_result({"trust": 90, "known_malicious": "ClamAV"}))["score"] == 25


def test_not_found_is_neutral_and_counts_as_answered():
    out = score_result(_result({}, status="not_found"))
    assert out["score"] == 0 and "hashlookup" in out["sources_answered"]


def test_html_shows_signed_points_and_hashlookup_row():
    from malvexis.config import Config as C
    from malvexis.pipeline import analyze_file
    import tempfile, pathlib

    from conftest import build_pe

    with tempfile.TemporaryDirectory() as d:
        p = pathlib.Path(d) / "a.exe"
        p.write_bytes(build_pe())
        result = analyze_file(p, C(), offline=True)
    result["intel"]["hashlookup"] = {"source": "hashlookup", "status": "ok", "message": "", "data": {"trust": 90, "file_name": "a.exe", "product": "Demo", "source": "NSRL", "known_malicious": None}}
    result["score"] = score_result(result)
    html = render_html(result)
    assert "-20" in html and "Known file: a.exe" in html
