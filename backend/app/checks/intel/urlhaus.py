"""URL.INTEL.URLHAUS: URLhaus URL and host lookups (abuse.ch). Needs URLHAUS_AUTH_KEY.

A match counts when the URL is online, or was added / last seen online within the last 30 days. Host-level
matches are skipped for allowlisted and abusable hosts (see common.host_match_allowed).
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from app.checks.base import AssessmentContext, CheckResult, evidence, make_finding
from app.checks.intel.common import cached_json, host_match_allowed, host_of, run_intel
from app.fetch.api_client import ApiClient, ApiUnavailable
from app.schemas import Finding

GROUP = "intel.urlhaus"
SOURCE = "urlhaus"
KEY_ENV = "URLHAUS_AUTH_KEY"
URL_API = "https://urlhaus-api.abuse.ch/v1/url/"
HOST_API = "https://urlhaus-api.abuse.ch/v1/host/"
RECENT = timedelta(days=30)
MAX_EVIDENCE = 5
_HEADERS = {"Auth-Key": KEY_ENV}


def _ts(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.strptime(s.replace(" UTC", "").strip(), "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
    except ValueError:
        return None


def _status(d: dict[str, Any]) -> str:
    return d.get("query_status") or d.get("query_staus") or ""  # the documented host example has a typo


async def _url_lookup(api: ApiClient, url: str) -> dict[str, Any]:
    d = await api.post_form_json(URL_API, {"url": url}, headers_env=_HEADERS)
    if not isinstance(d, dict):
        raise ApiUnavailable("urlhaus: unexpected response")
    if _status(d) != "ok":
        return {"listed": False}
    return {"listed": True, "url_status": d.get("url_status"), "date_added": d.get("date_added"),
            "last_online": d.get("last_online"), "threat": d.get("threat"), "tags": d.get("tags") or [],
            "reference": d.get("urlhaus_reference")}


async def _host_lookup(api: ApiClient, host: str) -> dict[str, Any]:
    d = await api.post_form_json(HOST_API, {"host": host}, headers_env=_HEADERS)
    if not isinstance(d, dict):
        raise ApiUnavailable("urlhaus: unexpected response")
    if _status(d) != "ok":
        return {"listed": False}
    urls = [u for u in d.get("urls") or [] if isinstance(u, dict)]
    added = [t for t in (_ts(u.get("date_added")) for u in urls) if t]
    return {"listed": True, "url_count": int(d.get("url_count") or len(urls)),
            "online_count": sum(1 for u in urls if u.get("url_status") == "online"),
            "latest_added": max(added).strftime("%Y-%m-%d %H:%M:%S UTC") if added else None,
            "reference": d.get("urlhaus_reference")}


def _recent(now: datetime, *stamps: str | None) -> bool:
    return any(t and now - t <= RECENT for t in map(_ts, stamps))


async def lookup(ctx: AssessmentContext, urls: list[str]) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    hosts_done: set[str] = set()
    for u in urls:
        r = await cached_json(ctx, SOURCE, f"url:{u}", lambda api, u=u: _url_lookup(api, u))
        if r["listed"] and (r.get("url_status") == "online" or _recent(ctx.now, r.get("date_added"), r.get("last_online"))):
            hits.append({"scope": "url", "target": u, **r})
        host = host_of(u)
        if host and host not in hosts_done and host_match_allowed(ctx, host):
            hosts_done.add(host)
            h = await cached_json(ctx, SOURCE, f"host:{host}", lambda api, host=host: _host_lookup(api, host))
            if h["listed"] and (h.get("online_count", 0) > 0 or _recent(ctx.now, h.get("latest_added"))):
                hits.append({"scope": "host", "target": host, **h})
    return hits


def build(ctx: AssessmentContext, hits: list[dict[str, Any]]) -> list[Finding]:
    if not hits:
        return []
    ev = []
    for h in hits[:MAX_EVIDENCE]:
        if h["scope"] == "url":
            desc = f"URLhaus lists {h['target']} (status: {h.get('url_status') or 'unknown'}, added {h.get('date_added')})"
            data = {"url": h["target"], "scope": "url", "url_status": h.get("url_status"), "threat": h.get("threat"),
                    "tags": h.get("tags") or [], "reference": h.get("reference")}
        else:
            desc = (f"URLhaus lists {h['url_count']} malicious URL(s) on host {h['target']} "
                    f"({h['online_count']} online)")
            data = {"url": h["target"], "scope": "host", "url_count": h["url_count"],
                    "online_count": h["online_count"], "reference": h.get("reference")}
        ev.append(evidence("ti_match", desc, SOURCE, data, observed_at=ctx.now))
    return [make_finding(
        "URL.INTEL.URLHAUS", "URLhaus lists this link or its host as distributing malware", ev,
        "abuse.ch's URLhaus tracks addresses actively serving malware; this one (or its host) is on the list.",
        "Do not open the link or download anything from it.")]


async def run(ctx: AssessmentContext) -> CheckResult:
    return await run_intel(ctx, group=GROUP, source=SOURCE, key_env=KEY_ENV, max_extra=1,
                           lookup=lambda urls: lookup(ctx, urls), build=build)
