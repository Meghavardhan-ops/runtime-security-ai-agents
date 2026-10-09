"""Small asynchronous client for a locally hosted Ollama API."""

from collections.abc import Mapping
from typing import Any, Literal

import httpx
from pydantic import BaseModel, ConfigDict

from backend.core.config import settings


class OllamaError(Exception):
    """Base class for sanitized Ollama failures."""


class OllamaTimeoutError(OllamaError):
    """The Ollama API did not respond before the configured timeout."""


class OllamaUnavailableError(OllamaError):
    """The Ollama API or configured model is unavailable."""


class OllamaHTTPError(OllamaError):
    """Ollama returned an unsuccessful HTTP status."""


class OllamaResponseError(OllamaError):
    """Ollama returned malformed or incomplete response data."""


class OllamaHealth(BaseModel):
    """Safe local service status; no server error body is included."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["available", "unavailable"]
    connected: bool
    model_available: bool
    model: str


class OllamaAdapter:
    """Issue bounded-time HTTP requests to Ollama without downloading models.

    An optional ``AsyncClient`` makes the adapter injectable for tests and for
    applications that manage their own HTTP connection lifecycle. If omitted,
    each request uses a short-lived client and closes it on completion.
    """

    def __init__(
        self,
        *,
        base_url: str | None = None,
        model: str | None = None,
        timeout_seconds: float | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.base_url = (base_url or settings.ollama_base_url).rstrip("/")
        self.model = model or settings.ollama_model
        self.timeout_seconds = (
            settings.ollama_timeout_seconds
            if timeout_seconds is None
            else timeout_seconds
        )
        if not self.base_url.startswith(("http://", "https://")):
            raise ValueError("Ollama base URL must use HTTP or HTTPS")
        if not self.model.strip() or not 0 < self.timeout_seconds <= 300:
            raise ValueError("Ollama model and timeout configuration are invalid")
        self._client = client

    async def chat(self, message: str) -> str:
        """Generate one non-streaming assistant response for a user message."""
        response = await self._request(
            "POST",
            "/api/chat",
            json={
                "model": self.model,
                "messages": [{"role": "user", "content": message}],
                "stream": False,
            },
        )
        if response.status_code == 404:
            raise OllamaUnavailableError("Ollama model is unavailable") from None
        if response.status_code < 200 or response.status_code >= 300:
            raise OllamaHTTPError("Ollama request failed") from None

        try:
            payload: Any = response.json()
        except (ValueError, TypeError, UnicodeError, RecursionError):
            raise OllamaResponseError("Ollama response was malformed") from None
        if not isinstance(payload, Mapping):
            raise OllamaResponseError("Ollama response was malformed") from None
        model_message = payload.get("message")
        if (
            not isinstance(model_message, Mapping)
            or model_message.get("role") != "assistant"
        ):
            raise OllamaResponseError("Ollama response was incomplete") from None
        content = model_message.get("content")
        if not isinstance(content, str) or not content.strip():
            raise OllamaResponseError("Ollama response was incomplete") from None
        return content

    async def health(self) -> OllamaHealth:
        """Check API reachability and configured model presence without pulling."""
        try:
            response = await self._request("GET", "/api/tags")
        except OllamaError:
            return OllamaHealth(
                status="unavailable",
                connected=False,
                model_available=False,
                model=self.model,
            )

        if response.status_code < 200 or response.status_code >= 300:
            return OllamaHealth(
                status="unavailable",
                connected=True,
                model_available=False,
                model=self.model,
            )
        try:
            payload: Any = response.json()
        except (ValueError, TypeError, UnicodeError, RecursionError):
            payload = None

        models = payload.get("models") if isinstance(payload, Mapping) else None
        model_available = False
        if isinstance(models, list):
            model_available = any(
                isinstance(item, Mapping)
                and self.model
                in tuple(
                    candidate
                    for candidate in (item.get("name"), item.get("model"))
                    if isinstance(candidate, str)
                )
                for item in models
            )
        return OllamaHealth(
            status="available" if model_available else "unavailable",
            connected=True,
            model_available=model_available,
            model=self.model,
        )

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        """Send a request and discard unsafe transport exception details."""
        try:
            if self._client is not None:
                return await self._client.request(
                    method,
                    f"{self.base_url}{path}",
                    timeout=self.timeout_seconds,
                    **kwargs,
                )
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                return await client.request(
                    method,
                    f"{self.base_url}{path}",
                    **kwargs,
                )
        except httpx.TimeoutException:
            raise OllamaTimeoutError("Ollama request timed out") from None
        except httpx.RequestError:
            raise OllamaUnavailableError("Ollama service is unavailable") from None
