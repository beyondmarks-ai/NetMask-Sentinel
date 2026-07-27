"""Small dependency-free runtime metrics registry."""

from __future__ import annotations

import threading
import time
from collections import Counter, deque
from datetime import datetime, timezone
from typing import Any


class RuntimeMetrics:
    def __init__(self, *, latency_samples: int = 1000) -> None:
        self.started_monotonic = time.monotonic()
        self.started_at = datetime.now(timezone.utc)
        self._counts: Counter[str] = Counter()
        self._latencies: deque[float] = deque(maxlen=latency_samples)
        self._last_error: str | None = None
        self._lock = threading.RLock()

    def increment(self, name: str, amount: int = 1) -> None:
        with self._lock:
            self._counts[name] += amount

    def observe_inference(self, milliseconds: float) -> None:
        with self._lock:
            self._latencies.append(float(milliseconds))

    def error(self, message: str) -> None:
        with self._lock:
            self._counts["errors_total"] += 1
            self._last_error = str(message)[:500]

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            latencies = sorted(self._latencies)
            average = sum(latencies) / len(latencies) if latencies else 0.0
            p95_index = max(0, int(len(latencies) * 0.95) - 1)
            p95 = latencies[p95_index] if latencies else 0.0
            return {
                "started_at": self.started_at.isoformat(),
                "uptime_seconds": round(time.monotonic() - self.started_monotonic, 3),
                "counts": dict(self._counts),
                "inference_ms": {
                    "samples": len(latencies),
                    "average": round(average, 3),
                    "p95": round(p95, 3),
                    "maximum": round(max(latencies), 3) if latencies else 0.0,
                },
                "last_error": self._last_error,
            }