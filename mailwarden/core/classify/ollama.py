"""Ollama backend (optional, fully local). Not used unless llm.backend = "ollama"."""

from __future__ import annotations

from mailwarden.core.classify.base import BackendError, BackendUnavailable, InvalidOutput, LLMBackend, parse_output
from mailwarden.core.classify.prompt import OUTPUT_SCHEMA, build_messages
from mailwarden.core.models import Classification
from mailwarden.security.net import AllowlistedSession, RequestException


class OllamaBackend(LLMBackend):
    name = "ollama"
    remote = False

    def __init__(self, session: AllowlistedSession, *, base_url: str, model: str, timeout_seconds: float) -> None:
        self._session = session
        self._base = base_url.rstrip("/")
        self.model = model
        self._timeout = timeout_seconds

    def check(self) -> None:
        try:
            resp = self._session.get(f"{self._base}/api/tags", timeout=5)
        except RequestException:
            raise BackendUnavailable(f"Ollama is not running at {self._base}; start it with `ollama serve`") from None
        models = {m.get("name") for m in resp.json().get("models", [])}
        if self.model not in models:
            raise BackendError(f"Ollama model {self.model!r} not pulled; run `ollama pull {self.model}`")

    def classify(self, redacted_text: str) -> Classification:
        payload = {
            "model": self.model,
            "messages": build_messages(redacted_text),
            "format": OUTPUT_SCHEMA,
            "stream": False,
            "options": {"temperature": 0},
        }
        try:
            resp = self._session.post(f"{self._base}/api/chat", json=payload, timeout=self._timeout)
        except RequestException as e:
            raise BackendUnavailable(f"Ollama request failed ({type(e).__name__})") from None
        if resp.status_code != 200:
            raise BackendUnavailable(f"Ollama returned HTTP {resp.status_code}")
        try:
            content = resp.json()["message"]["content"]
        except (KeyError, TypeError, ValueError):
            raise InvalidOutput("unexpected Ollama response shape") from None
        return parse_output(content or "")
