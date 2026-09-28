from __future__ import annotations

from collections import Counter
from pathlib import Path
import math


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def analyze_entropy(path: str, sample_size: int = 2 * 1024 * 1024) -> float:
    with Path(path).open("rb") as fh:
        data = fh.read(sample_size)
    return shannon_entropy(data)

