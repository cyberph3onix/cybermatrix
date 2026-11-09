"""HTTP client for fixed threat-intel / CT / RDAP hosts. Never used for user-supplied targets (use safe_fetch).

API keys are read from the environment at call time and sent as headers, never in the URL, so they can't leak
through logs or error messages.
"""
from __future__ import annotations

import os
from collections.abc import Iterable, Mapping
from typing import Any

import httpx

ALLOWED_HOSTS = frozenset({
    "api.certspotter.com", "crt.sh",
    "safebrowsing.googleapis.com", "urlhaus-api.abuse.ch", "www.virustotal.com",
    "raw.githubusercontent.com", "data.iana.org", "dns.google",
})
USER_AGENT = "CyberMatrix/0.1"
MAX_RESPONSE_BYTES = 8 * 1024 * 1024  # the OpenPhish feed and IANA bootstrap are the largest legitimate bodies


class ApiUnavailable(Exception):
    """Source down, rate-limited, timed out or misconfigured. Callers turn this into CheckRun(unavailable)."""


class ApiNotFound(ApiUnavailable):
    """HTTP 404. For lookup APIs this is an answer ("we have never seen it"), so callers may catch it first."""


class ApiClient:
    def __init__(self, *, timeout: float = 6.0, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._client = httpx.AsyncClient(timeout=httpx.Timeout(timeout), follow_redirects=False, trust_env=False,
                                         headers={"User-Agent": USER_AGENT}, transport=transport)

    def _check_host(self, url: str, extra_hosts: Iterable[str]) -> str:
        parsed = httpx.URL(url)
        host = parsed.host
        if host not in ALLOWED_HOSTS and host not in set(extra_hosts):
            raise ApiUnavailable(f"host {host} not in API allowlist")
        if parsed.scheme != "https":
            raise ApiUnavailable(f"{host}: https required")
        return host

    @staticmethod
    def _headers(bearer_env: str | None, headers_env: Mapping[str, str] | None) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if bearer_env:
            key = os.environ.get(bearer_env)
            if key:
                headers["Authorization"] = f"Bearer {key}"
        for header, env in (headers_env or {}).items():
            key = os.environ.get(env)
            if not key:
                raise ApiUnavailable(f"{env} is not set")
            headers[header] = key
        return headers

    async def _send(self, method: str, url: str, host: str, **kw: Any) -> httpx.Response:
        try:
            r = await self._client.request(method, url, **kw)
        except httpx.HTTPError as e:
            raise ApiUnavailable(f"{host}: {type(e).__name__}") from None  # no key in message
        if r.status_code == 429:
            raise ApiUnavailable(f"{host}: rate limited")
        if r.status_code == 404:
            raise ApiNotFound(f"{host}: HTTP 404")
        if r.status_code in (401, 403):
            raise ApiUnavailable(f"{host}: HTTP {r.status_code} (check the API key)")
        if r.status_code >= 400 or 300 <= r.status_code < 400:  # redirects are never followed, so never success
            raise ApiUnavailable(f"{host}: HTTP {r.status_code}")
        if len(r.content) > MAX_RESPONSE_BYTES:
            raise ApiUnavailable(f"{host}: response too large")
        return r

    async def get_json(self, url: str, *, params: dict[str, Any] | list[tuple[str, Any]] | None = None,
                       bearer_env: str | None = None, headers_env: Mapping[str, str] | None = None,
                       extra_hosts: Iterable[str] = ()) -> Any:
        host = self._check_host(url, extra_hosts)
        r = await self._send("GET", url, host, params=params, headers=self._headers(bearer_env, headers_env))
        return self._json(r, host)

    async def get_bytes(self, url: str, *, params: dict[str, Any] | list[tuple[str, Any]] | None = None,
                        headers_env: Mapping[str, str] | None = None, extra_hosts: Iterable[str] = ()) -> bytes:
        host = self._check_host(url, extra_hosts)
        r = await self._send("GET", url, host, params=params, headers=self._headers(None, headers_env))
        return r.content

    async def post_form_json(self, url: str, data: dict[str, str], *, headers_env: Mapping[str, str] | None = None,
                             extra_hosts: Iterable[str] = ()) -> Any:
        host = self._check_host(url, extra_hosts)
        r = await self._send("POST", url, host, data=data, headers=self._headers(None, headers_env))
        return self._json(r, host)

    @staticmethod
    def _json(r: httpx.Response, host: str) -> Any:
        try:
            return r.json()
        except ValueError:
            raise ApiUnavailable(f"{host}: invalid JSON") from None

    async def get_text(self, url: str, *, params: dict[str, Any] | None = None,
                       extra_hosts: Iterable[str] = ()) -> str:
        host = self._check_host(url, extra_hosts)
        r = await self._send("GET", url, host, params=params)
        return r.text

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> ApiClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()
