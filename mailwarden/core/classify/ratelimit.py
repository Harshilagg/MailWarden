"""Local rate limiting for LLM calls: a token bucket plus a per-run cap.

Paces calls so the provider's limits are not hit in the first place (the
backend still handles a 429 as a fallback).
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable

from mailwarden.core.classify.base import BackendUnavailable, LLMBackend
from mailwarden.core.models import Classification

log = logging.getLogger(__name__)


class CallBudgetExhausted(BackendUnavailable):
    """max_llm_calls_per_run reached; the rest stays pending for the next run."""


class TokenBucket:
    def __init__(self, per_minute: int, *, clock: Callable[[], float], sleep: Callable[[float], None]) -> None:
        if per_minute < 1:
            raise ValueError("per_minute must be >= 1")
        self.capacity = float(per_minute)
        self.rate = per_minute / 60.0  # tokens per second
        self._tokens = float(per_minute)
        self._clock = clock
        self._sleep = sleep
        self._updated = clock()

    def _refill(self) -> None:
        now = self._clock()
        self._tokens = min(self.capacity, self._tokens + (now - self._updated) * self.rate)
        self._updated = now

    def take(self) -> None:
        self._refill()
        if self._tokens < 1:
            wait = (1 - self._tokens) / self.rate
            log.debug("LLM rate limit: waiting %.1fs", wait)
            self._sleep(wait)
            self._refill()
        self._tokens -= 1


class RateLimitedBackend(LLMBackend):
    def __init__(
        self,
        inner: LLMBackend,
        *,
        per_minute: int,
        per_run: int,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.inner = inner
        self.name, self.model, self.remote = inner.name, inner.model, inner.remote
        self._bucket = TokenBucket(per_minute, clock=clock, sleep=sleep)
        self._per_run = per_run
        self.calls = 0

    def check(self) -> None:
        self.inner.check()

    def classify(self, redacted_text: str) -> Classification:
        if self.calls >= self._per_run:
            raise CallBudgetExhausted(f"max_llm_calls_per_run ({self._per_run}) reached; the rest stays pending")
        self._bucket.take()
        self.calls += 1
        return self.inner.classify(redacted_text)
