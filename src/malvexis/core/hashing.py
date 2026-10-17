"""File hashing. Streams the file so large samples don't need to fit in memory."""
from __future__ import annotations

import hashlib
from pathlib import Path

try:  # optional fuzzy hash
    import ssdeep
except ImportError:  # pragma: no cover
    ssdeep = None

CHUNK = 1024 * 1024


def compute_hashes(path: str | Path) -> dict:
    path = Path(path)
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()  # noqa: S324 - identifiers, not security
    size = 0
    with path.open("rb") as fh:
        while chunk := fh.read(CHUNK):
            size += len(chunk)
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    result: dict = {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "size": size,
        "ssdeep": None,
        "imphash": None,  # filled in by the pipeline for PE files
    }
    if ssdeep is not None:
        try:
            result["ssdeep"] = ssdeep.hash_from_file(str(path))
        except Exception:  # pragma: no cover - fuzzy hash is best effort
            result["ssdeep"] = None
    return result
