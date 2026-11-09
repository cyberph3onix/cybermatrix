"""Shared plumbing for the threat-intel checks (groups intel.*).

Every intel check follows the same shape: look up the submitted URL immediately, then, once the redirect chain is
known, look up where it led. A failure on the second stage degrades to a note in `detail`; a failure on the first
makes the whole group `unavailable`. All network access goes through fetch/api_client.py (fixed hosts only).
"""
from __future__ import annotations

import asyncio
import os
import time
from collections.abc import Awaitable, Callable
from typing import Any

from app.cache import MISS, TTL_S
from app.checks.base import AssessmentContext, CheckResult, make_run
from app.fetch.api_client import ApiClient, ApiUnavailable
from app.schemas import CheckStatus, Finding
from app.urlutil import URLParseError, parse_url

FETCH_WAIT_S = 16.0  # safe_fetch's own total budget is 15 s

Lookup = Callable[[list[str]], Awaitable[list[dict[str, Any]]]]
Build = Callable[[AssessmentContext, list[dict[str, Any]]], list[Finding]]


async def cached_json(ctx: AssessmentContext, source: str, key: str,
                      fetch: Callable[[ApiClient], Awaitable[Any]], *, ttl_s: int = TTL_S) -> Any:
    """Return the cached answer for (source, key), or fetch it and cache it. Only non-None answers are cached."""
    if ctx.cache is not None:
        hit = await ctx.cache.get(source, key)
        if hit is not MISS:
            return hit
    api = ctx.api or ApiClient()
    try:
        value = await fetch(api)
    finally:
        if ctx.api is None:
            await api.aclose()
    if ctx.cache is not None and value is not None:
        await ctx.cache.set(source, key, value, ttl_s)
    return value


async def redirect_targets(ctx: AssessmentContext) -> list[str]:
    """URLs the submitted link led to (excluding the submitted one). Empty if the fetch failed or timed out."""
    try:
        fr = await asyncio.wait_for(ctx.fetch(), FETCH_WAIT_S)
    except Exception:  # noqa: BLE001
        return []
    return [h.url for h in fr.hops[1:]]


def host_of(url: str) -> str | None:
    try:
        return parse_url(url).host
    except URLParseError:
        return None


def host_match_allowed(ctx: AssessmentContext, host: str) -> bool:
    """Host-level threat-intel matches are skipped for allowlisted or abusable hosts.

    Otherwise one malicious file on github.com or a free-hosting page would brand every URL on that host as
    confirmed malicious. Exact-URL matches are always honoured.
    """
    return not (ctx.brands.allowlisted(host) or ctx.brands.is_abusable(host))


async def staged_lookup(ctx: AssessmentContext, lookup: Lookup, *, max_extra: int) -> tuple[list[dict[str, Any]], str | None]:
    first = ctx.url.url_without_userinfo()
    hits = await lookup([first])
    detail = None
    try:
        extra = [u for u in dict.fromkeys(await redirect_targets(ctx)) if u != first]
        if extra:
            hits = hits + await lookup(extra[-max_extra:])
    except ApiUnavailable as e:
        detail = f"redirect targets not checked: {e}"
    return hits, detail


async def run_intel(ctx: AssessmentContext, *, group: str, source: str, lookup: Lookup, build: Build,
                    key_env: str | None = None, max_extra: int = 1) -> CheckResult:
    t0 = time.monotonic()
    if key_env and not os.environ.get(key_env):
        return make_run(group, CheckStatus.UNAVAILABLE, source, t0, f"{key_env} is not set"), []
    try:
        hits, detail = await staged_lookup(ctx, lookup, max_extra=max_extra)
        return make_run(group, CheckStatus.COMPLETED, source, t0, detail), build(ctx, hits)
    except ApiUnavailable as e:
        return make_run(group, CheckStatus.UNAVAILABLE, source, t0, str(e)), []
    except Exception as e:  # noqa: BLE001
        return make_run(group, CheckStatus.FAILED, source, t0, f"error: {type(e).__name__}"), []
