import pytest
import requests

from malvexis.config import Config
from malvexis.intel import malwarebazaar, virustotal, yara_scan
from malvexis.intel.cache import Cache

SHA = "a" * 64


class FakeResponse:
    def __init__(self, status_code=200, body=None):
        self.status_code = status_code
        self._body = body or {}

    def json(self):
        return self._body


def test_vt_without_key_is_unavailable():
    assert virustotal.lookup(SHA, Config())["status"] == "unavailable"


def test_vt_ok_not_found_and_rate_limit(monkeypatch):
    cfg = Config(vt_api_key="k")
    body = {"data": {"attributes": {"last_analysis_stats": {"malicious": 12, "harmless": 0, "undetected": 50}, "names": ["x.exe"]}}}
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(200, body))
    res = virustotal.lookup(SHA, cfg)
    assert res["status"] == "ok" and res["data"]["malicious"] == 12 and res["data"]["total_engines"] == 62

    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(404))
    assert virustotal.lookup(SHA, cfg)["status"] == "not_found"

    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(429))
    assert virustotal.lookup(SHA, cfg)["status"] == "rate_limited"


def test_vt_network_error_is_reported_not_raised(monkeypatch):
    def boom(*a, **k):
        raise requests.ConnectionError("offline")

    monkeypatch.setattr(requests, "get", boom)
    assert virustotal.lookup(SHA, Config(vt_api_key="k"))["status"] == "error"


def test_mb_ok_and_not_found(monkeypatch):
    cfg = Config(mb_api_key="k")
    ok = {"query_status": "ok", "data": [{"signature": "Emotet", "tags": ["exe"], "intelligence": {"clamav": ["Win.Trojan"]}}]}
    monkeypatch.setattr(requests, "post", lambda *a, **k: FakeResponse(200, ok))
    res = malwarebazaar.lookup(SHA, cfg)
    assert res["status"] == "ok" and res["data"]["signature"] == "Emotet"

    monkeypatch.setattr(requests, "post", lambda *a, **k: FakeResponse(200, {"query_status": "hash_not_found"}))
    assert malwarebazaar.lookup(SHA, cfg)["status"] == "not_found"
    assert malwarebazaar.lookup(SHA, Config())["status"] == "unavailable"


def test_cache_serves_second_lookup_without_network(monkeypatch, tmp_path):
    cfg = Config(vt_api_key="k")
    cache = Cache(tmp_path)
    calls = []

    def fake_get(*a, **k):
        calls.append(1)
        return FakeResponse(404)

    monkeypatch.setattr(requests, "get", fake_get)
    virustotal.lookup(SHA, cfg, cache)
    second = virustotal.lookup(SHA, cfg, cache)
    assert len(calls) == 1 and "cached" in second["message"]
    cache.close()


def test_cache_expiry(tmp_path):
    cache = Cache(tmp_path, ttl=-1)
    cache.set("k", {"a": 1})
    assert cache.get("k") is None
    cache.close()


def test_yara_scan_matches_eicar(eicar_file, tmp_path):
    pytest.importorskip("yara")
    from pathlib import Path

    cfg = Config(rules_dirs=[Path(__file__).resolve().parent.parent / "rules"])
    res = yara_scan.scan(eicar_file, cfg)
    assert res["status"] == "ok"
    assert any(m["rule"] == "EICAR_Test_File" for m in res["data"]["matches"])


def test_yara_without_rules_is_unavailable(tmp_path):
    pytest.importorskip("yara")
    res = yara_scan.scan(tmp_path, Config(rules_dirs=[tmp_path / "nope"]))
    assert res["status"] == "unavailable"
