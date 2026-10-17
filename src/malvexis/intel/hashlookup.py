"""CIRCL hashlookup: is this hash a *known* file (NSRL and other known-software sets)?

No API key needed. A hit does not mean "safe" - it means "known software", which the scorer uses to
reduce false positives. Only the SHA-256 is sent; the file itself is never uploaded.
"""
from __future__ import annotations

import requests

from ..config import Config
from .base import make_result
from .cache import Cache

SOURCE = "hashlookup"
URL = "https://hashlookup.circl.lu/lookup/sha256/{sha256}"


def _as_int(value) -> int | None:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _parse(sha256: str, body: dict) -> dict:
    source = body.get("source")
    return {
        "trust": _as_int(body.get("hashlookup:trust")),
        "file_name": body.get("FileName"),
        "product": body.get("ProductName"),
        "source": ", ".join(source) if isinstance(source, list) else source,
        "known_malicious": body.get("KnownMalicious") or None,
        "link": URL.format(sha256=sha256),
    }


def lookup(sha256: str, config: Config, cache: Cache | None = None) -> dict:
    key = f"hl:{sha256}"
    if cache and (hit := cache.get(key)):
        hit["message"] = (hit.get("message") or "").strip() + " (cached)"
        return hit

    try:
        resp = requests.get(URL.format(sha256=sha256), headers={"Accept": "application/json"}, timeout=config.http_timeout)
    except requests.RequestException as exc:
        return make_result(SOURCE, "error", f"Network error ({type(exc).__name__}): source unreachable")

    if resp.status_code == 200:
        try:
            body = resp.json()
        except ValueError:
            return make_result(SOURCE, "error", "hashlookup returned invalid JSON")
        result = make_result(SOURCE, "ok", data=_parse(sha256, body if isinstance(body, dict) else {}))
    elif resp.status_code == 404:
        result = make_result(SOURCE, "not_found", "Hash not in CIRCL hashlookup (unknown file, which says nothing either way)")
    elif resp.status_code == 429:
        return make_result(SOURCE, "rate_limited", "CIRCL hashlookup rate limit hit")
    else:
        return make_result(SOURCE, "error", f"Unexpected HTTP {resp.status_code} from CIRCL hashlookup")

    if cache:
        cache.set(key, result)
    return result
