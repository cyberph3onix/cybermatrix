"""Certificate Transparency watchlist: "domain monitoring and alerts for suspicious certificate issuance".

POST /watch records the certificates Cert Spotter currently lists for a domain and its subdomains (the baseline).
A background poll (WATCH_POLL_S, default 1 h) then records every certificate it has not seen before as an alert,
marking a CA this domain has never used as `new_issuer`. Passive: only Cert Spotter (a fixed host) is queried.
Cert Spotter lists unexpired certificates; a certificate issued and revoked between polls still appears until it
expires, so nothing is missed by polling hourly.
"""
from __future__ import annotations

import asyncio
import logging
import os
import secrets
from datetime import datetime
from typing import Any

from sqlalchemy import func, select

from app.checks.tls_ct import CERTSPOTTER, _dn_org, _dt
from app.db import Database, WatchAlertRow, WatchRow
from app.fetch.api_client import ApiClient, ApiUnavailable
from app.schemas import utcnow

log = logging.getLogger(__name__)
POLL_S = int(os.environ.get("WATCH_POLL_S", "3600"))
MAX_WATCHES = int(os.environ.get("WATCH_MAX", "200"))
MAX_PAGES = 5


async def issuances(api: ApiClient, domain: str) -> list[dict[str, Any]]:
    """[{cert_sha256, dns_names, issuer, not_before}] for the domain and its subdomains (paginated with `after`)."""
    out: list[dict[str, Any]] = []
    after = None
    for _ in range(MAX_PAGES):
        params = [("domain", domain), ("include_subdomains", "true"), ("expand", "dns_names"), ("expand", "issuer")]
        if after:
            params.append(("after", after))
        rows = await api.get_json(CERTSPOTTER, params=params, bearer_env="CERTSPOTTER_API_KEY")
        if not isinstance(rows, list):
            raise ApiUnavailable("certspotter: unexpected response")
        for r in rows:
            iss = r.get("issuer") or {}
            nb = _dt(r.get("not_before"))
            out.append({"id": str(r.get("id", "")), "cert_sha256": (r.get("cert_sha256") or "").upper(),
                        "dns_names": sorted(r.get("dns_names") or [])[:20],
                        "issuer": _dn_org(iss.get("name")) or iss.get("friendly_name") or "unknown",
                        "not_before": nb.isoformat() if nb else None})
        if len(rows) < 100:
            break
        after = out[-1]["id"]
    return [o for o in out if o["cert_sha256"]]


def new_token() -> str:
    return secrets.token_hex(12)


async def count(db: Database) -> int:
    async with db.session() as s:
        return int((await s.execute(select(func.count()).select_from(WatchRow))).scalar_one())


async def poll_one(db: Database, api: ApiClient, watch_id: str, now: datetime | None = None) -> int:
    """Fetch issuances for one watch; store unseen certificates as alerts. Returns the number of new alerts."""
    now = now or utcnow()
    async with db.session() as s:
        w = await s.get(WatchRow, watch_id)
        if w is None:
            return 0
        domain, known, issuers, baseline = w.domain, set(w.known_certs or []), set(w.known_issuers or []), w.last_checked is None
    certs = await issuances(api, domain)
    added = 0
    async with db.session() as s:
        w = await s.get(WatchRow, watch_id)
        for c in certs:
            if c["cert_sha256"] in known:
                continue
            known.add(c["cert_sha256"])
            if not baseline:
                s.add(WatchAlertRow(watch_id=watch_id, cert_sha256=c["cert_sha256"], dns_names=c["dns_names"],
                                    issuer=c["issuer"], not_before=c["not_before"],
                                    new_issuer=bool(issuers) and c["issuer"] not in issuers, seen_at=now))
                added += 1
            issuers.add(c["issuer"])
        w.known_certs, w.known_issuers, w.last_checked = sorted(known), sorted(issuers), now
        await s.commit()
    return added


async def poll_all(db: Database, api: ApiClient) -> int:
    async with db.session() as s:
        ids = [r for (r,) in (await s.execute(select(WatchRow.watch_id).order_by(WatchRow.last_checked.asc().nulls_first())))]
    total = 0
    for wid in ids:
        try:
            total += await poll_one(db, api, wid)
        except ApiUnavailable as e:
            log.info("watch poll paused: %s", e)
            break  # rate-limited or down: resume next round
    return total


async def poll_loop(db: Database, api: ApiClient) -> None:
    while True:
        await asyncio.sleep(POLL_S)
        try:
            n = await poll_all(db, api)
            if n:
                log.info("CT watch: %d new certificate(s)", n)
        except Exception as e:  # noqa: BLE001
            log.warning("CT watch poll failed: %s", type(e).__name__)
