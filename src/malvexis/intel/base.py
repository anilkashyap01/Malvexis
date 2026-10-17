"""Common result shape so scoring and reports can treat every source the same way."""
from __future__ import annotations

# status values:
#   ok            - source answered and has data about the sample
#   not_found     - source answered: it has never seen this sample
#   rate_limited  - quota hit; the pipeline carries on with the other sources
#   unavailable   - not configured or dependency missing
#   error         - network/auth/parsing failure
ANSWERED = {"ok", "not_found"}


def make_result(source: str, status: str, message: str = "", data: dict | None = None) -> dict:
    return {"source": source, "status": status, "message": message, "data": data or {}}
