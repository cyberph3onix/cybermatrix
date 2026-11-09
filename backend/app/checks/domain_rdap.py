"""DOMAIN.YOUNG via RDAP (group domain.rdap).

The RDAP server for a TLD comes from the IANA bootstrap file (cached 24 h); responses are cached 6 h. We check
the submitted domain and, if the link redirected elsewhere, the destination's domain too. Nameservers are saved
on the context so the pipeline can emit `nameserver` indicators for correlation.
"""
from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from app.checks.base import AssessmentContext, CheckResult, evidence, make_finding, make_run
from app.checks.intel.common import FETCH_WAIT_S, cached_json
from app.fetch.api_client import ApiClient, ApiNotFound, ApiUnavailable
from app.schemas import CheckStatus, Finding
from app.urlutil import URLParseError, parse_url, registrable_domain

GROUP = "domain.rdap"
SOURCE = "rdap"
BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
YOUNG = timedelta(days=30)
BOOTSTRAP_TTL_S = 24 * 3600


def _dt(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=UTC)


async def _bootstrap(ctx: AssessmentContext) -> dict[str, str]:
    async def fetch(api: ApiClient) -> dict[str, str]:
        d = await api.get_json(BOOTSTRAP)
        out: dict[str, str] = {}
        try:
            for tlds, urls in d["services"]:
                https = [u for u in urls if u.startswith("https://")]
                if https:
                    out.update({t.lower(): https[0] for t in tlds})
        except (KeyError, TypeError, ValueError):
            raise ApiUnavailable("iana rdap bootstrap: unexpected format") from None
        return out
    return await cached_json(ctx, SOURCE, "bootstrap", fetch, ttl_s=BOOTSTRAP_TTL_S)


async def _query(ctx: AssessmentContext, domain: str) -> dict[str, Any]:
    boot = await _bootstrap(ctx)
    base = boot.get(domain.rsplit(".", 1)[-1])
    if not base:
        raise ApiUnavailable(f"no RDAP server known for .{domain.rsplit('.', 1)[-1]}")
    host = httpx.URL(base).host

    async def fetch(api: ApiClient) -> dict[str, Any]:
        try:
            d = await api.get_json(f"{base.rstrip('/')}/domain/{domain}", extra_hosts=[host])
        except ApiNotFound:
            raise ApiUnavailable(f"{domain} not found in RDAP") from None
        if not isinstance(d, dict):
            raise ApiUnavailable("rdap: unexpected response")
        created = next((e.get("eventDate") for e in d.get("events") or []
                        if isinstance(e, dict) and e.get("eventAction") == "registration"), None)
        ns = sorted({(n.get("ldhName") or "").lower().rstrip(".") for n in d.get("nameservers") or []
                     if isinstance(n, dict)} - {""})
        registrar = next((v for ent in d.get("entities") or [] if isinstance(ent, dict) and "registrar" in (ent.get("roles") or [])
                          for v in [_vcard_fn(ent)] if v), None)
        return {"registered": created, "nameservers": ns, "registrar": registrar}
    return await cached_json(ctx, SOURCE, f"domain:{domain}", fetch)


def _vcard_fn(entity: dict[str, Any]) -> str | None:
    try:
        for item in entity["vcardArray"][1]:
            if item[0] == "fn":
                return str(item[3])
    except (KeyError, IndexError, TypeError):
        pass
    return None


def analyze(domain: str, url: str, info: dict[str, Any], now: datetime) -> list[Finding]:
    reg = _dt(info.get("registered"))
    if reg is None or reg > now:
        return []
    age = now - reg
    if age >= YOUNG:
        return []
    return [make_finding(
        "DOMAIN.YOUNG", f"{domain} was registered {age.days} day(s) ago",
        [evidence("rdap", f"RDAP registration date {reg.date().isoformat()} ({age.days} days before this check)",
                  SOURCE, {"domain": domain, "url": url, "registered": reg.isoformat(), "age_days": age.days,
                           "registrar": info.get("registrar")}, observed_at=now)],
        "Phishing sites are usually set up days before use; legitimate organisations rarely use a brand-new domain.",
        "Be extra careful: verify this site through an official channel.",
        limitation="Many legitimate sites are also new; this signal is only a hint.")]


def _domain_of(url: str) -> str | None:
    try:
        host = parse_url(url).host
    except URLParseError:
        return None
    return None if parse_url(url).ip else registrable_domain(host)


async def run(ctx: AssessmentContext) -> CheckResult:
    t0 = time.monotonic()
    try:
        if ctx.url.ip is not None:
            return make_run(GROUP, CheckStatus.SKIPPED, SOURCE, t0, "IP address host has no domain registration"), []
        first_url = ctx.url.url_without_userinfo()
        domain = registrable_domain(ctx.url.host)
        info = await _query(ctx, domain)
        if not info.get("registered"):
            return make_run(GROUP, CheckStatus.UNAVAILABLE, SOURCE, t0, "RDAP response has no registration date"), []
        ctx.nameservers = list(info.get("nameservers") or [])
        findings = analyze(domain, first_url, info, ctx.now)
        detail = None
        try:  # also check where the link led, e.g. a shortener pointing at a brand-new domain
            fr = await asyncio.wait_for(ctx.fetch(), FETCH_WAIT_S)
            final_domain = _domain_of(fr.final_url) if fr.final_url else None
            if final_domain and final_domain != domain:
                final_info = await _query(ctx, final_domain)
                findings += analyze(final_domain, fr.final_url, final_info, ctx.now)
                ctx.nameservers = sorted(set(ctx.nameservers) | set(final_info.get("nameservers") or []))
        except (ApiUnavailable, TimeoutError) as e:
            detail = f"redirect destination not checked: {e}"
        except Exception:  # noqa: BLE001
            pass
        return make_run(GROUP, CheckStatus.COMPLETED, SOURCE, t0, detail), findings
    except ApiUnavailable as e:
        return make_run(GROUP, CheckStatus.UNAVAILABLE, SOURCE, t0, str(e)), []
    except Exception as e:  # noqa: BLE001
        return make_run(GROUP, CheckStatus.FAILED, SOURCE, t0, f"error: {type(e).__name__}"), []
