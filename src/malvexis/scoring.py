"""Combine every signal into a score, a verdict and human-readable reasons.

Pure function: reads a result dict, returns a dict. No file access, no network.
All weights are heuristics - tune them here, and keep the reasons visible in reports.
"""
from __future__ import annotations

from .intel.base import ANSWERED

LOW_RISK_MAX = 24
SUSPICIOUS_MAX = 59  # 60+ is "likely_malicious"

YARA_SEVERITY_POINTS = {"critical": 60, "high": 40, "medium": 25, "low": 10}
YARA_CAP = 60

KNOWN_GOOD_TRUST = 50  # CIRCL hashlookup trust score (0-100) needed to treat a hash as known software
KNOWN_GOOD_BONUS = 20

# category -> (minimum distinct APIs required, points)
IMPORT_CATEGORY_RULES = {
    "injection": (2, 20),
    "anti_debug": (2, 10),
    "keylogging": (2, 10),
    "evasion": (2, 5),
    "persistence": (2, 5),
    "crypto": (2, 5),
}


def verdict_for(score: int) -> str:
    if score <= LOW_RISK_MAX:
        return "low_risk"
    if score <= SUSPICIOUS_MAX:
        return "suspicious"
    return "likely_malicious"


def score_result(result: dict) -> dict:
    reasons: list[dict] = []

    def add(signal: str, points: int, detail: str) -> None:
        reasons.append({"signal": signal, "points": points, "detail": detail})

    intel = result.get("intel", {})

    # --- threat intelligence -------------------------------------------------
    vt = intel.get("virustotal", {})
    if vt.get("status") == "ok":
        malicious = vt["data"].get("malicious", 0)
        total = vt["data"].get("total_engines", 0)
        if malicious >= 10:
            add("virustotal", 60, f"{malicious}/{total} engines flag this file as malicious")
        elif malicious >= 3:
            add("virustotal", 35, f"{malicious}/{total} engines flag this file as malicious")
        elif malicious >= 1:
            add("virustotal", 15, f"{malicious}/{total} engines flag this file (low count, may be a false positive)")

    mb = intel.get("malwarebazaar", {})
    if mb.get("status") == "ok":
        sig = mb["data"].get("signature") or "unlabelled"
        add("malwarebazaar", 50, f"Known sample in MalwareBazaar (signature: {sig})")

    hl = intel.get("hashlookup", {})
    if hl.get("status") == "ok":
        hl_data = hl["data"]
        if hl_data.get("known_malicious"):
            add("hashlookup", 25, f"CIRCL hashlookup lists this hash as known malicious ({hl_data['known_malicious']})")
        elif (hl_data.get("trust") or 0) >= KNOWN_GOOD_TRUST:
            add("hashlookup", -KNOWN_GOOD_BONUS, f"Known file in CIRCL hashlookup (trust {hl_data['trust']}, source: {hl_data.get('source') or 'n/a'}): likely legitimate software")

    tools = result.get("tools", {})
    clam = tools.get("clamav", {})
    if clam.get("status") == "ok" and clam["data"].get("infected"):
        add("clamav", 50, f"ClamAV signature match: {clam['data'].get('signature')}")
    die = tools.get("die", {})
    die_packers = die["data"].get("packers", []) if die.get("status") == "ok" else []

    yara_data = intel.get("yara", {})
    if yara_data.get("status") == "ok":
        yara_points = 0
        for match in yara_data["data"].get("matches", []):
            pts = YARA_SEVERITY_POINTS.get(match.get("severity", "medium"), 25)
            yara_points += pts
            add("yara", min(pts, YARA_CAP), f"YARA rule {match['rule']} matched ({match.get('severity', 'medium')}): {match.get('description') or 'no description'}")
        if yara_points > YARA_CAP:  # cap the combined YARA contribution
            overflow = yara_points - YARA_CAP
            _trim(reasons, "yara", overflow)

    # --- file type -----------------------------------------------------------
    ftype = result.get("filetype") or {}
    if ftype.get("extension_mismatch"):
        add("filetype", 10, f"Extension {ftype.get('extension') or '(none)'} does not match detected type: {ftype.get('description')}")

    # --- PE heuristics -------------------------------------------------------
    pe = result.get("pe") or {}
    if pe.get("valid"):
        if pe.get("packers"):
            detail = f"Packer/protector section names: {', '.join(pe['packers'])}"
            if die_packers:
                detail += f" (confirmed by Detect It Easy: {', '.join(die_packers)})"
            add("pe", 15, detail)
        for sec in pe.get("sections", []):
            if "high_entropy" in sec["flags"] and not pe.get("packers") and not die_packers:
                add("pe", 10, f"Section {sec['name']} has high entropy ({sec['entropy']}) - possible packed/encrypted data")
                break
        wx = [s["name"] for s in pe.get("sections", []) if "writable_and_executable" in s["flags"]]
        if wx:
            add("pe", 10, f"Writable and executable section(s): {', '.join(wx)}")
        if any("executable_but_empty_on_disk" in s["flags"] for s in pe.get("sections", [])):
            add("pe", 5, "Executable section with no data on disk (unpacks at runtime)")
        if pe.get("import_count", 0) < 10 and result.get("entropy", {}).get("label") in ("high", "elevated"):
            add("pe", 10, f"Very few imports ({pe.get('import_count', 0)}) combined with high entropy - typical of packed binaries")

        by_category: dict[str, set[str]] = {}
        for hit in pe.get("suspicious_imports", []):
            by_category.setdefault(hit["category"], set()).add(hit["api"])
        for category, (needed, points) in IMPORT_CATEGORY_RULES.items():
            apis = by_category.get(category, set())
            if len(apis) >= needed:
                add("imports", points, f"{category.replace('_', ' ').title()} capability APIs: {', '.join(sorted(apis))}")

        flags = pe.get("timestamp_flags", [])
        if "zeroed" in flags or "in_future" in flags:
            add("pe", 5, f"Suspicious compile timestamp ({', '.join(flags)})")
        if pe.get("overlay_size", 0) > 1024 * 1024:
            add("pe", 5, f"Large overlay appended after the PE image ({pe['overlay_size']:,} bytes)")

    # --- strings -------------------------------------------------------------
    ind = result.get("strings", {}).get("indicators", {})
    net = len(ind.get("urls", [])) + len(ind.get("ips", []))
    if net:
        add("strings", min(10, 5 * net), f"{net} embedded URL/IP indicator(s)")
    if ind.get("suspicious_keywords"):
        add("strings", 5, f"Suspicious command strings: {', '.join(ind['suspicious_keywords'][:5])}")

    if die_packers and not (pe.get("valid") and pe.get("packers")):
        add("detect_it_easy", 15, f"Detect It Easy identifies a packer/protector: {', '.join(die_packers)}")

    floss = tools.get("floss", {})
    if floss.get("status") == "ok":
        f_ind = floss["data"].get("indicators", {})
        hidden = sum(len(f_ind.get(k, [])) for k in ("urls", "ips", "registry_keys", "suspicious_keywords"))
        if hidden:
            add("floss", 10, f"Obfuscated (stack/decoded) strings contain {hidden} indicator(s) that plain string extraction cannot see")

    # --- totals --------------------------------------------------------------
    total = max(0, min(100, sum(r["points"] for r in reasons)))
    reasons.sort(key=lambda r: r["points"], reverse=True)

    answered = [name for name, res in intel.items() if res.get("status") in ANSWERED]
    unavailable = [{"source": name, "status": res.get("status"), "message": res.get("message", "")} for name, res in intel.items() if res.get("status") not in ANSWERED]

    notes = []
    if not any(name in answered for name in ("virustotal", "malwarebazaar")):
        notes.append("No online threat-intel source answered: this verdict is based on local analysis only.")
    if not pe.get("valid") and ftype.get("type") not in ("pe", "dos_mz"):
        notes.append("Deep structural analysis currently covers PE files only.")

    return {
        "score": total,
        "verdict": verdict_for(total),
        "reasons": reasons,
        "sources_answered": answered,
        "sources_unavailable": unavailable,
        "notes": notes,
    }


def _trim(reasons: list[dict], signal: str, overflow: int) -> None:
    """Reduce YARA reason points so the combined contribution respects YARA_CAP."""
    for reason in reversed(reasons):
        if overflow <= 0:
            break
        if reason["signal"] != signal:
            continue
        cut = min(reason["points"], overflow)
        reason["points"] -= cut
        overflow -= cut
