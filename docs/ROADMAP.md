# Malvexis Roadmap

Work top to bottom, one task per change. Every task must follow `AGENTS.md` (especially the hard safety rules) and end with passing tests.

## 1. Throttling for batch scans (high priority)
VirusTotal free tier is 4 requests/min. Batch scans hit the limit within seconds, so most files lose VT data.
- Add `--vt-delay SECONDS` (default 16) used only when scanning folders, and a simple in-process rate limiter in `intel/virustotal.py`.
- Cached hashes must not consume quota or wait.
- Acceptance: a mocked 10-file batch makes at most 4 VT calls per 60 seconds (use an injectable clock in tests); a 429 still degrades gracefully.

## 2. CI and linting
- Add `.github/workflows/ci.yml`: Python 3.10 to 3.13, `pip install -e ".[dev,yara]"`, `ruff check`, `pytest`.
- Add ruff config to `pyproject.toml`; fix any findings.
- Acceptance: CI green on a fresh clone; README gets a badge.

## 3. ELF support
- Add `core/elf_analysis.py` using the `lief` library (optional dependency, `pip install malvexis[elf]`).
- Report: architecture, sections with entropy, imported symbols, suspicious symbol categories (ptrace, execve, socket, dlopen), stripped or not.
- Extend `indicators.py`, `scoring.py`, the HTML template and tests with a hand-built minimal ELF fixture (no real samples).
- Acceptance: `malvexis scan` on an ELF fixture shows an ELF section in the report; PE behavior unchanged.

## 4. ATT&CK without capa (reduced scope)
capa (opt-in `--capa`) already maps capabilities to ATT&CK techniques. Remaining work: a small fallback in `core/attack_mapping.py` that maps suspicious API categories and YARA rule tags to technique IDs when capa is not installed, clearly labelled as "heuristic" in the report. Must not change the score.
- Acceptance: tests per category; capa results take precedence when present.

## 5. IOC export
- `malvexis scan ... --iocs FILE` writes CSV (type, value, source) for hashes, URLs, IPs, domains, registry keys.
- Optional second format: STIX 2.1 bundle (`--iocs-format stix`).
- Defang URLs and IPs in the CSV by default (hxxp://, 1[.]2[.]3[.]4); add `--no-defang`.
- Acceptance: round-trip test on a fixture with known IOCs.

## 6. Office and PDF analysis
- Optional `oletools` integration: detect VBA macros, auto-exec triggers (AutoOpen, Document_Open), suspicious keywords, embedded objects.
- PDF: count `/JS`, `/JavaScript`, `/OpenAction`, `/Launch`, `/EmbeddedFile` keywords by scanning bytes (no rendering, no execution).
- Acceptance: tests use hand-written minimal documents; documents are only parsed, never opened.

## 7. Scoring calibration and false-positive review
- Assemble a small local corpus of benign Windows binaries (outside the repo) and record score distribution in `docs/CALIBRATION.md`.
- Adjust weights only with evidence in that file; keep `low_risk` for typical benign software.
- Acceptance: documented before/after numbers; tests updated.

## 8. More YARA rules
- Add well-commented rules for: suspicious script droppers, ransom-note keywords, credential-dumping strings, common packer stubs.
- Document how to add community rule sets (such as Yara-Rules) through `--rules`, without vendoring them into the repo.
- Acceptance: each rule has `description` and `severity`; a test per rule using a synthetic matching blob.

## 9. Web UI (optional, last)
- Small local-only Flask or FastAPI app: upload a file, run `analyze_file`, show the HTML report. Bind to 127.0.0.1, size-limit uploads, never persist uploads after analysis.
- Acceptance: documented security considerations; tests for size limit and cleanup.

## 10. Tool setup and speed
- `malvexis tools setup`: download capa-rules and the sigs folder into `~/.cache/malvexis/` and print the env vars (no manual git commands).
- ClamAV through the `clamd` daemon (`clamdscan`) so batch scans don't reload the signature database for every file.
- Re-check Detect It Easy's database when die-python ships an engine 4.x build (heuristics and compiler detection).
- Acceptance: batch of 10 files with `--clamav` loads the database once.
