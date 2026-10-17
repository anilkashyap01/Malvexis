"""Shannon entropy, overall and per block. High entropy suggests packed or encrypted content."""
from __future__ import annotations

import math
from collections import Counter

BLOCK_SIZE = 64 * 1024
HIGH = 7.2  # bits per byte; random/encrypted/compressed data sits near 8.0
ELEVATED = 6.5


def _entropy_from_counts(counts: Counter | list[int], total: int) -> float:
    if total == 0:
        return 0.0
    values = counts.values() if isinstance(counts, Counter) else counts
    return -sum((c / total) * math.log2(c / total) for c in values if c)


def shannon_entropy(data: bytes) -> float:
    return round(_entropy_from_counts(Counter(data), len(data)), 4)


def entropy_label(value: float) -> str:
    if value >= HIGH:
        return "high"
    if value >= ELEVATED:
        return "elevated"
    return "normal"


def analyze_entropy(data: bytes, block_size: int = BLOCK_SIZE) -> dict:
    """Overall entropy plus min/max over fixed-size blocks, computed in a single pass."""
    if not data:
        return {"overall": 0.0, "label": "normal", "block_size": block_size, "max_block": 0.0, "min_block": 0.0, "high_entropy_blocks": 0, "blocks": 0}

    total_counts: Counter = Counter()
    block_values: list[float] = []
    for offset in range(0, len(data), block_size):
        block = data[offset : offset + block_size]
        counts = Counter(block)
        total_counts.update(counts)
        block_values.append(_entropy_from_counts(counts, len(block)))

    overall = round(_entropy_from_counts(total_counts, len(data)), 4)
    return {
        "overall": overall,
        "label": entropy_label(overall),
        "block_size": block_size,
        "blocks": len(block_values),
        "max_block": round(max(block_values), 4),
        "min_block": round(min(block_values), 4),
        "high_entropy_blocks": sum(1 for v in block_values if v >= HIGH),
    }
