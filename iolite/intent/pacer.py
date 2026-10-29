"""
pacer.py — an adaptive request pacer that rides just under the target's ceiling.

Static rate limits are wrong for hardened targets: too slow wastes the window, too fast gets
you blocked. This is a TCP-style AIMD controller (additive-increase / multiplicative-decrease):
on every clean success it nudges the rate UP, on any block (429/WAF/challenge/5xx) it halves the
rate and shrinks concurrency, and it honors Retry-After. It therefore discovers the fastest pace
the target tolerates and stays just below it — maximum throughput without tripping defences.

Deterministic + testable: the clock and sleep are injectable, so tests advance virtual time
without waiting. Pure-stdlib (QL4).
"""
from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass
class PacerStats:
    requests: int = 0
    increases: int = 0
    backoffs: int = 0
    slept_s: float = 0.0


class AdaptivePacer:
    def __init__(self, rate: float = 2.0, *, min_rate: float = 0.2, max_rate: float = 25.0,
                 max_concurrency: int = 6, ai: float = 0.5, md: float = 0.5,
                 clock=None, sleep=None):
        self.rate = float(rate)
        self.min_rate, self.max_rate = float(min_rate), float(max_rate)
        self.concurrency = 1
        self.max_concurrency = int(max_concurrency)
        self.ai, self.md = float(ai), float(md)
        self._clock = clock or time.monotonic
        self._sleep = sleep or time.sleep
        self._last = 0.0
        self._backoff_until = 0.0
        self._ok_streak = 0
        self.stats = PacerStats()

    def before(self) -> None:
        """Block until it is safe to send the next request (honor backoff + current rate)."""
        now = self._clock()
        if now < self._backoff_until:
            self._do_sleep(self._backoff_until - now)
            now = self._clock()
        interval = 1.0 / max(self.rate, 1e-6)
        wait = (self._last + interval) - now
        if wait > 0:
            self._do_sleep(wait)
            now = self._clock()
        self._last = now
        self.stats.requests += 1

    def on_ok(self) -> None:
        """Clean success → additive increase; grow concurrency after a healthy streak."""
        self.rate = min(self.max_rate, self.rate + self.ai)
        self.stats.increases += 1
        self._ok_streak += 1
        if self._ok_streak >= 5 and self.concurrency < self.max_concurrency:
            self.concurrency += 1
            self._ok_streak = 0

    def on_block(self, *, retry_after: float = 0.0) -> None:
        """A PACE block (429 / 5xx) → multiplicative decrease + shrink concurrency + honor
        Retry-After. This is the signal that we are going too fast globally."""
        self.rate = max(self.min_rate, self.rate * self.md)
        self.concurrency = max(1, self.concurrency // 2)
        self._ok_streak = 0
        self.stats.backoffs += 1
        if retry_after and retry_after > 0:
            self._backoff_until = self._clock() + retry_after

    def soft_penalty(self) -> None:
        """A REQUEST-specific wall (WAF/challenge on one path) → a light touch only. It is not
        evidence that our global pace is wrong, so the overall rate is barely affected."""
        self.rate = max(self.min_rate, self.rate * 0.9)
        self.concurrency = max(1, self.concurrency - 1)
        self._ok_streak = 0

    def _do_sleep(self, secs: float) -> None:
        if secs > 0:
            self.stats.slept_s += secs
            self._sleep(secs)

    def snapshot(self) -> dict:
        return {"rate": round(self.rate, 3), "concurrency": self.concurrency,
                "backoff_until": round(self._backoff_until, 3),
                "requests": self.stats.requests, "backoffs": self.stats.backoffs}
