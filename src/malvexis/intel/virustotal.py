"""VirusTotal v3 file lookup by SHA-256."""
from __future__ import annotations

import requests

from ..config import Config
from .base import make_result
from .cache import Cache

SOURCE = "virustotal"
URL = "https://www.virustotal.com/api/v3/files/{sha256}"


def _parse(sha256: str, body: dict) -> dict:
    attrs = body.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    classification = attrs.get("popular_threat_classification", {}) or {}
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "total_engines": sum(stats.values()),
        "threat_label": classification.get("suggested_threat_label"),
        "names": (attrs.get("names") or [])[:5],
        "tags": (attrs.get("tags") or [])[:10],
        "type_description": attrs.get("type_description"),
        "first_submission_date": attrs.get("first_submission_date"),
        "reputation": attrs.get("reputation"),
        "link": f"https://www.virustotal.com/gui/file/{sha256}",
    }


def lookup(sha256: str, config: Config, cache: Cache | None = None) -> dict:
    if not config.vt_api_key:
        return make_result(SOURCE, "unavailable", "No VT_API_KEY configured")

    key = f"vt:{sha256}"
    if cache and (hit := cache.get(key)):
        hit["message"] = (hit.get("message") or "").strip() + " (cached)"
        return hit

    try:
        resp = requests.get(
            URL.format(sha256=sha256),
            headers={"x-apikey": config.vt_api_key},
            timeout=config.http_timeout,
        )
    except requests.RequestException as exc:
        return make_result(SOURCE, "error", f"Network error ({type(exc).__name__}): source unreachable")

    if resp.status_code == 200:
        try:
            result = make_result(SOURCE, "ok", data=_parse(sha256, resp.json()))
        except ValueError:
            return make_result(SOURCE, "error", "VirusTotal returned invalid JSON")
    elif resp.status_code == 404:
        result = make_result(SOURCE, "not_found", "Hash not known to VirusTotal")
    elif resp.status_code == 429:
        return make_result(SOURCE, "rate_limited", "VirusTotal rate limit hit; continuing with other sources")
    elif resp.status_code in (401, 403):
        return make_result(SOURCE, "error", f"VirusTotal rejected the API key (HTTP {resp.status_code})")
    else:
        return make_result(SOURCE, "error", f"Unexpected HTTP {resp.status_code} from VirusTotal")

    if cache:
        cache.set(key, result)
    return result
