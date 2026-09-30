"""Groq backend (cloud). Receives redacted text of SAFE mail only.

Uses strict structured outputs (json_schema) so the model can only emit the
classification schema; the result is still re-validated locally.
"""

from __future__ import annotations

import json
import logging
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
        min_interval_seconds: float = 0,
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

    def _pace(self) -> None:
        # Primary pacing is the local token bucket (RateLimitedBackend); this is
        # only an optional minimum spacing between calls.
        wait = self._last_call + self._min_interval - self._clock()
        if wait > 0:
            self._sleep(wait)
        self._last_call = self._clock()

    def classify(self, redacted_text: str) -> Classification:
        if getattr(self, "_exhausted", False):
            raise BackendUnavailable("Groq daily request limit reached; remaining mail stays pending")
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
        for _ in range(_MAX_RATE_LIMIT_WAITS + 1):
            self._pace()
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
            if resp.headers.get("x-ratelimit-remaining-requests") == "0":
                log.info("Groq daily request limit reached after this call")
                self._exhausted = True
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
