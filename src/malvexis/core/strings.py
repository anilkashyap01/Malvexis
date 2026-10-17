"""String extraction (ASCII + UTF-16LE) and indicator-of-compromise classification."""
from __future__ import annotations

import re

from .indicators import SUSPICIOUS_KEYWORDS, classify_api

MIN_LENGTH = 6
MAX_PER_CATEGORY = 50
SAMPLE_SIZE = 40

URL_RE = re.compile(r"https?://[^\s\"'<>\\]{4,}", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
REGISTRY_RE = re.compile(r"(?:HKEY_[A-Z_]+|HKLM|HKCU)\\[^\s\"']+|SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run[^\s\"']*", re.IGNORECASE)
WINPATH_RE = re.compile(r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*")
API_TOKEN_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{3,40}$")

# IPs that are almost always noise (version numbers, unspecified/broadcast addresses)
IGNORED_IPS = {"0.0.0.0", "255.255.255.255", "127.0.0.1"}


def extract_strings(data: bytes, min_length: int = MIN_LENGTH) -> dict[str, list[str]]:
    ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
    unicode_re = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_length)
    ascii_strings = [m.group().decode("ascii") for m in ascii_re.finditer(data)]
    unicode_strings = [m.group().decode("utf-16-le", errors="ignore") for m in unicode_re.finditer(data)]
    return {"ascii": ascii_strings, "unicode": unicode_strings}


def _dedupe(items: list[str], limit: int = MAX_PER_CATEGORY) -> list[str]:
    seen: dict[str, None] = {}
    for item in items:
        if item not in seen:
            seen[item] = None
        if len(seen) >= limit:
            break
    return list(seen)


def classify_strings(strings: list[str]) -> dict[str, list[str]]:
    urls: list[str] = []
    ips: list[str] = []
    emails: list[str] = []
    registry: list[str] = []
    paths: list[str] = []
    keywords: list[str] = []
    apis: list[str] = []

    for s in strings:
        urls += URL_RE.findall(s)
        ips += [ip for ip in IPV4_RE.findall(s) if ip not in IGNORED_IPS]
        emails += EMAIL_RE.findall(s)
        registry += REGISTRY_RE.findall(s)
        paths += WINPATH_RE.findall(s)
        lowered = s.lower()
        keywords += [k for k in SUSPICIOUS_KEYWORDS if k in lowered]
        if API_TOKEN_RE.match(s) and classify_api(s):
            apis.append(s)

    return {
        "urls": _dedupe(urls),
        "ips": _dedupe(ips),
        "emails": _dedupe(emails),
        "registry_keys": _dedupe(registry),
        "file_paths": _dedupe(paths),
        "suspicious_keywords": _dedupe(keywords),
        "suspicious_apis": _dedupe(apis),
    }


def analyze_strings(data: bytes, min_length: int = MIN_LENGTH) -> dict:
    found = extract_strings(data, min_length)
    combined = found["ascii"] + found["unicode"]
    return {
        "min_length": min_length,
        "ascii_count": len(found["ascii"]),
        "unicode_count": len(found["unicode"]),
        "indicators": classify_strings(combined),
        "sample": _dedupe(combined, SAMPLE_SIZE),
    }
