"""Groq backend (cloud). Receives redacted text of SAFE mail only.

Uses strict structured outputs (json_schema) so the model can only emit the
classification schema; the result is still re-validated locally.
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections.abc import Callable

from mailwarden.core.classify.base import BackendError, BackendUnavailable, InvalidOutput, LLMBackend, parse_output
from mailwarden.core.classify.prompt import OUTPUT_SCHEMA, SCHEMA_NAME, build_messages
from mailwarden.core.models import Classification
from mailwarden.security.net import AllowlistedSession, RequestException

log = logging.getLogger(__name__)

CHAT_URL = "https://api.groq.com/openai/v1/chat/completions"
MODELS_URL = "https://api.groq.com/openai/v1/models"
_MAX_RATE_LIMIT_WAITS = 3
_MAX_WAIT_SECONDS = 60.0
_DURATION = re.compile(r"^(?:(\d+)h)?(?:(\d+)m(?!s))?(?:([\d.]+)s)?(?:([\d.]+)ms)?$")


def parse_duration(value: str | None) -> float | None:
    """Groq reset headers look like '4.702s', '1m26.4s', '1h13m26.4s' or '250ms'."""
    if not value:
        return None
    m = _DURATION.match(value.strip())
    if not m or not any(m.groups()):
        return None
    h, mins, secs, ms = m.groups()
    return int(h or 0) * 3600 + int(mins or 0) * 60 + float(secs or 0) + float(ms or 0) / 1000


def estimate_tokens(text: str) -> int:
    """Rough upper estimate for one call: system prompt + email + reasoning + JSON output."""
    return 900 + len(text) // 3


class GroqBackend(LLMBackend):
    name = "groq"
    remote = True

    def __init__(
        self,
        session: AllowlistedSession,
        api_key: str,
        *,
        model: str,
        reasoning_effort: str = "low",
        min_interval_seconds: float = 2.5,
        timeout_seconds: float = 60,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not api_key:
            raise BackendError("no Groq API key stored; run `mailwarden set-groq-key`")
        self._session = session
        self._api_key = api_key
        self.model = model
        self._reasoning_effort = reasoning_effort
        self._min_interval = min_interval_seconds
        self._timeout = timeout_seconds
        self._clock = clock
        self._sleep = sleep
        self._last_call = -float("inf")
        self._tokens_remaining: int | None = None
        self._tokens_reset_at = 0.0

    def __repr__(self) -> str:
        return f"GroqBackend(model={self.model!r}, api_key=***)"

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"}

    def check(self) -> None:
        try:
            resp = self._session.get(MODELS_URL, headers=self._headers(), timeout=15)
        except RequestException as e:
            raise BackendUnavailable(f"cannot reach Groq ({type(e).__name__})") from None
        if resp.status_code == 401:
            raise BackendError("Groq rejected the API key; run `mailwarden set-groq-key` again")
        if resp.status_code != 200:
            raise BackendUnavailable(f"Groq models endpoint returned HTTP {resp.status_code}")
        ids = {m.get("id") for m in resp.json().get("data", [])}
        if self.model not in ids:
            raise BackendError(f"model {self.model!r} is not available to this Groq key")

    def _pace(self, needed_tokens: int) -> None:
        wait = self._last_call + self._min_interval - self._clock()
        if self._tokens_remaining is not None and self._tokens_remaining < needed_tokens:
            wait = max(wait, self._tokens_reset_at - self._clock())
        if wait > 0:
            log.debug("pacing Groq requests: waiting %.1fs", wait)
            self._sleep(wait)
        self._last_call = self._clock()

    def _record_limits(self, headers) -> None:
        try:
            remaining = headers.get("x-ratelimit-remaining-tokens")
            self._tokens_remaining = int(remaining) if remaining is not None else None
        except ValueError:
            self._tokens_remaining = None
        reset = parse_duration(headers.get("x-ratelimit-reset-tokens"))
        self._tokens_reset_at = self._clock() + min(reset or 0.0, _MAX_WAIT_SECONDS)
        if headers.get("x-ratelimit-remaining-requests") == "0":
            raise BackendUnavailable("Groq daily request limit reached; remaining mail stays pending")

    def classify(self, redacted_text: str) -> Classification:
        payload = {
            "model": self.model,
            "messages": build_messages(redacted_text),
            "temperature": 0,
            "max_completion_tokens": 1024,
            "reasoning_effort": self._reasoning_effort,
            "include_reasoning": False,
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": SCHEMA_NAME, "strict": True, "schema": OUTPUT_SCHEMA},
            },
        }
        needed = estimate_tokens(redacted_text)
        for _ in range(_MAX_RATE_LIMIT_WAITS + 1):
            self._pace(needed)
            try:
                resp = self._session.post(CHAT_URL, headers=self._headers(), json=payload, timeout=self._timeout)
            except RequestException as e:
                raise BackendUnavailable(f"Groq request failed ({type(e).__name__})") from None
            if resp.status_code == 429:
                try:
                    wait = float(resp.headers.get("retry-after") or 10)
                except ValueError:
                    wait = 10.0
                if wait > _MAX_WAIT_SECONDS:
                    raise BackendUnavailable("Groq daily limit reached; remaining mail stays pending")
                log.debug("Groq rate limit reached; waiting %.0fs", wait)
                self._sleep(wait)
                continue
            self._record_limits(resp.headers)
            break
        else:
            raise BackendUnavailable("Groq rate limit persisted; remaining mail left pending")

        if resp.status_code == 401:
            raise BackendError("Groq rejected the API key")
        if resp.status_code == 400:
            # Only the error code is read: the body may echo model output derived from mail.
            try:
                code = (resp.json().get("error") or {}).get("code", "")
            except ValueError:
                code = ""
            if code == "json_validate_failed":
                raise InvalidOutput("Groq output failed schema validation")
            raise BackendError(f"Groq rejected the request (HTTP 400, code {code or 'unknown'}); check config")
        if resp.status_code >= 500 or resp.status_code != 200:
            raise BackendUnavailable(f"Groq returned HTTP {resp.status_code}")
        try:
            content = resp.json()["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError, json.JSONDecodeError):
            raise InvalidOutput("unexpected Groq response shape") from None
        return parse_output(content or "")
