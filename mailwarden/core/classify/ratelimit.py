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

    def take(self, amount: float = 1.0) -> None:
        amount = min(amount, self.capacity)  # an oversized request still goes, after a full refill
        self._refill()
        if self._tokens < amount:
            wait = (amount - self._tokens) / self.rate
            log.debug("LLM rate limit: waiting %.1fs", wait)
            self._sleep(wait)
            self._refill()
        self._tokens -= amount


class RateLimitedBackend(LLMBackend):
    def __init__(
        self,
        inner: LLMBackend,
        *,
        per_minute: int,
        per_run: int,
        tokens_per_minute: int | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.inner = inner
        self.name, self.model, self.remote = inner.name, inner.model, inner.remote
        self._bucket = TokenBucket(per_minute, clock=clock, sleep=sleep)
        # Provider token-per-minute limits (Groq free tier: 8K/min) need a second, size-aware bucket.
        self._token_bucket = TokenBucket(tokens_per_minute, clock=clock, sleep=sleep) if tokens_per_minute else None
        self._per_run = per_run
        self.calls = 0

    def check(self) -> None:
        self.inner.check()

    def _spend(self, estimated_tokens: float) -> None:
        if self.calls >= self._per_run:
            raise CallBudgetExhausted(f"max_llm_calls_per_run ({self._per_run}) reached; the rest stays pending")
        self._bucket.take()
        if self._token_bucket is not None:
            self._token_bucket.take(estimated_tokens)
        self.calls += 1

    def classify(self, redacted_text: str) -> Classification:
        self._spend(estimate_tokens(_CLASSIFY_PROMPT_CHARS + len(redacted_text), output=500))
        return self.inner.classify(redacted_text)

    def extract_jobs(self, redacted_text: str) -> str:
        self._spend(estimate_tokens(_EXTRACT_PROMPT_CHARS + len(redacted_text), output=1200))
        return self.inner.extract_jobs(redacted_text)

    def score_fit(self, messages: list[dict[str, str]]) -> str:
        self._spend(estimate_tokens(sum(len(m.get("content", "")) for m in messages), output=900))
        return self.inner.score_fit(messages)


# Rough sizes of the fixed system prompts (chars), used for token estimates.
_CLASSIFY_PROMPT_CHARS = 2600
_EXTRACT_PROMPT_CHARS = 1200


def estimate_tokens(prompt_chars: int, *, output: int) -> float:
    """~4 chars per token for English prompts, plus the expected reasoning + answer."""
    return prompt_chars / 3.5 + output
