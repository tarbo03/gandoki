"""LLM client — OpenRouter (default) + Ollama, behind one interface.

Both use the OpenAI-compatible /chat/completions path. OpenRouter is the
default (easy onboarding). Ollama is the recommended production path
(no egress, no rate limits).
"""
from __future__ import annotations
import os
from typing import Optional

import httpx

from .prompts import ADJUDICATOR_TEMPLATE, ADJUDICATOR_TEMPLATE_SHA256


class LLMError(Exception):
    """Raised when the model call fails in a way we want to surface upstream."""


class LLMClient:
    model_id: str

    async def chat(self, system: str, user: str, *, timeout_s: int = 30) -> str:
        raise NotImplementedError

    async def aclose(self) -> None:
        pass


class _OpenAICompatible(LLMClient):
    base_url: str
    api_key: str
    model_id: str

    def __init__(self, base_url: str, model_id: str, api_key: str = ""):
        self.base_url = base_url.rstrip("/")
        self.model_id = model_id
        self.api_key = api_key
        self._client: Optional[httpx.AsyncClient] = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            self._client = httpx.AsyncClient(timeout=60, headers=headers)
        return self._client

    async def chat(self, system: str, user: str, *, timeout_s: int = 30) -> str:
        client = self._get_client()
        body = {
            "model": self.model_id,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0,
            "max_tokens": 200,
        }
        try:
            r = await client.post(
                f"{self.base_url}/chat/completions",
                json=body,
                timeout=timeout_s,
            )
        except Exception as e:
            raise LLMError(f"network error: {type(e).__name__}: {e}") from e
        if r.status_code != 200:
            raise LLMError(f"HTTP {r.status_code}: {r.text[:200]}")
        try:
            data = r.json()
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, ValueError) as e:
            raise LLMError(f"unexpected response shape: {e}") from e

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


class OllamaClient(_OpenAICompatible):
    """Ollama's /v1/chat/completions is OpenAI-compatible. No API key needed."""

    def __init__(self, base_url: str, model_id: str):
        super().__init__(base_url=f"{base_url.rstrip('/')}/v1", model_id=model_id)


class OpenRouterClient(_OpenAICompatible):
    """OpenRouter with fallback chain.

    If the primary model fails (rate limit, cold start, model removed),
    try each fallback in order. Fail only when all are exhausted.
    """

    def __init__(
        self,
        base_url: str,
        model_id: str,
        api_key: str,
        fallback_models: list[str] | None = None,
    ):
        super().__init__(base_url=base_url, model_id=model_id, api_key=api_key)
        self.fallback_models = fallback_models or []

    async def chat(self, system: str, user: str, *, timeout_s: int = 30) -> str:
        models = [self.model_id] + self.fallback_models
        last_error: Exception | None = None
        for model in models:
            old = self.model_id
            self.model_id = model
            try:
                return await super().chat(system, user, timeout_s=timeout_s)
            except LLMError as e:
                last_error = e
                continue
            finally:
                self.model_id = old
        raise LLMError(
            f"all models failed; last error: {last_error}"
        )


def build_client(cfg: dict) -> Optional[LLMClient]:
    """Build the LLM client from config, or None if AI is disabled."""
    ai = cfg.get("ai", {})
    if not ai.get("enabled", False):
        return None
    backend = ai.get("backend", "openrouter")
    if backend == "ollama":
        ol = ai.get("ollama", {})
        return OllamaClient(
            base_url=ol.get("base_url", "http://localhost:11434"),
            model_id=ol.get("model", "llama3.2:3b"),
        )
    if backend == "openrouter":
        orc = ai.get("openrouter", {})
        env_var = orc.get("api_key_env", "OPENROUTER_API_KEY")
        # BYOK: Check config first (injected from headers), then fallback to env
        api_key = orc.get("api_key") or os.environ.get(env_var, "")
        if not api_key:
            raise LLMError(
                f"OpenRouter API key not found in env var '{env_var}'. "
                f"Set it or switch ai.backend to 'ollama'."
            )
        return OpenRouterClient(
            base_url=orc.get("base_url", "https://openrouter.ai/api/v1"),
            model_id=orc.get("model", "meta-llama/llama-3.3-70b-instruct:free"),
            api_key=api_key,
            fallback_models=orc.get("fallback_models", []),
        )
    raise LLMError(f"unknown ai.backend: {backend}")


def verify_adjudicator_template() -> None:
    """Raise if the on-disk adjudicator template hash drifted from the constant."""
    import hashlib
    actual = hashlib.sha256(ADJUDICATOR_TEMPLATE.encode()).hexdigest()
    if actual != ADJUDICATOR_TEMPLATE_SHA256:
        raise LLMError(
            "Adjudicator template has been modified. If this was intentional, "
            "update ADJUDICATOR_TEMPLATE_SHA256 in prompts.py. Refusing to run "
            "with a drifted template."
        )
