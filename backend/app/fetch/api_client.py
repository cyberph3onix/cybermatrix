"""HTTP client for fixed threat-intel / CT hosts. Never used for user-supplied targets (use safe_fetch)."""
from __future__ import annotations

import os
from typing import Any

import httpx

ALLOWED_HOSTS = frozenset({"api.certspotter.com", "crt.sh"})
USER_AGENT = "CyberMatrix/0.1"


class ApiUnavailable(Exception):
    """Source down, rate-limited, timed out or misconfigured. Callers turn this into CheckRun(unavailable)."""


class ApiClient:
    def __init__(self, *, timeout: float = 6.0, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._client = httpx.AsyncClient(timeout=httpx.Timeout(timeout), follow_redirects=False, trust_env=False,
                                         headers={"User-Agent": USER_AGENT}, transport=transport)

    async def get_json(self, url: str, *, params: dict[str, Any] | list[tuple[str, Any]] | None = None,
                       bearer_env: str | None = None) -> Any:
        host = httpx.URL(url).host
        if host not in ALLOWED_HOSTS:
            raise ApiUnavailable(f"host {host} not in API allowlist")
        headers = {"Accept": "application/json"}
        key = os.environ.get(bearer_env) if bearer_env else None
        if key:
            headers["Authorization"] = f"Bearer {key}"
        try:
            r = await self._client.get(url, params=params, headers=headers)
        except httpx.HTTPError as e:
            raise ApiUnavailable(f"{host}: {type(e).__name__}") from None  # no key in message
        if r.status_code == 429:
            raise ApiUnavailable(f"{host}: rate limited")
        if r.status_code >= 400:
            raise ApiUnavailable(f"{host}: HTTP {r.status_code}")
        try:
            return r.json()
        except ValueError:
            raise ApiUnavailable(f"{host}: invalid JSON") from None

    async def get_text(self, url: str, *, params: dict[str, Any] | None = None) -> str:
        host = httpx.URL(url).host
        if host not in ALLOWED_HOSTS:
            raise ApiUnavailable(f"host {host} not in API allowlist")
        try:
            r = await self._client.get(url, params=params)
        except httpx.HTTPError as e:
            raise ApiUnavailable(f"{host}: {type(e).__name__}") from None
        if r.status_code >= 400:
            raise ApiUnavailable(f"{host}: HTTP {r.status_code}")
        return r.text

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> ApiClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()
