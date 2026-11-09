"""Threat-intelligence sharing feed: high-risk links and domains as STIX 2.1 and as a plain-text blocklist.

What goes in, and why it is safe to publish:
- Only `url` indicators, i.e. links someone actually submitted (or that appeared in a submitted message). Redirect
  hops and infrastructure (IPs, nameservers, certificates) are left out: a phishing link that redirects to
  `victim.com` must not put `victim.com` on a blocklist.
- Query strings and fragments are dropped, because they can carry an email address, a token or a phone number.
  Messages themselves never appear, only links found in them.
- Hosts on the allowlist (official brand domains, Tranco top 10k) are never listed, so a mistaken or framed report
  cannot blocklist a major site. Shortener and abusable hosts (bit.ly, sites.google.com) list the URL, never the
  domain.
- Reports a validator rejected on-chain are left out. Registered reports carry their on-chain hash and status.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.brands import BrandIndex
from app.db import IndicatorRow, RegistryRow, ReportRow
from app.schemas import utcnow
from app.urlutil import URLParseError, parse_url, registrable_domain

LEVELS = {
    "suspicious": ("suspicious", "high_risk", "confirmed_malicious"),
    "high_risk": ("high_risk", "confirmed_malicious"),
    "confirmed_malicious": ("confirmed_malicious",),
}
CONFIDENCE = {"confirmed_malicious": 85, "high_risk": 70, "suspicious": 40}
MAX_ITEMS = 2000
# Fixed namespace so the same indicator keeps the same STIX id across downloads (consumers de-duplicate on it).
NAMESPACE = uuid.UUID("6f1c1b5e-1e7b-4c55-9b0e-63796265726d")
IDENTITY = "identity--" + str(uuid.uuid5(NAMESPACE, "cybermatrix"))


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _ts(dt: datetime) -> str:
    return _aware(dt).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def strip_url(url: str) -> str | None:
    """http(s) URL without userinfo, query or fragment; None if it isn't one."""
    try:
        p = urlsplit(url.strip())
    except ValueError:
        return None
    if p.scheme.lower() not in ("http", "https") or not p.hostname:
        return None
    host = p.hostname.lower()
    netloc = f"[{host}]" if ":" in host else host
    if p.port:
        netloc += f":{p.port}"
    return urlunsplit((p.scheme.lower(), netloc, p.path or "/", "", ""))


async def collect(db: AsyncSession, idx: BrandIndex, *, level: str = "high_risk", since: datetime | None = None
                  ) -> list[dict]:
    """One entry per distinct value: {type: url|domain, value, classification, first_seen, last_seen, report_ids,
    report_hash, onchain_status}. Worst classification and newest report win."""
    classes = LEVELS[level]
    q = (select(IndicatorRow.normalized, ReportRow.report_id, ReportRow.classification, ReportRow.created_at,
                ReportRow.report_hash, RegistryRow.status)
         .join(ReportRow, ReportRow.report_id == IndicatorRow.report_id)
         .outerjoin(RegistryRow, RegistryRow.report_id == ReportRow.report_id)
         .where(IndicatorRow.type == "url", ReportRow.classification.in_(classes))
         .order_by(ReportRow.created_at.desc()))
    if since is not None:
        q = q.where(ReportRow.created_at >= since)
    rank = {c: i for i, c in enumerate(("suspicious", "high_risk", "confirmed_malicious"))}
    items: dict[tuple[str, str], dict] = {}

    def add(kind: str, value: str, rid: str, cls: str, created: datetime, rhash: str, status: str | None) -> None:
        cur = items.get((kind, value))
        if cur is None:
            items[(kind, value)] = {"type": kind, "value": value, "classification": cls, "first_seen": created,
                                    "last_seen": created, "report_ids": [rid], "report_hash": rhash if status else None,
                                    "onchain_status": status}
            return
        if rank[cls] > rank[cur["classification"]]:
            cur["classification"] = cls
        cur["first_seen"] = min(cur["first_seen"], created)
        if rid not in cur["report_ids"] and len(cur["report_ids"]) < 5:
            cur["report_ids"].append(rid)
        if cur["onchain_status"] is None and status:
            cur["report_hash"], cur["onchain_status"] = rhash, status

    for norm, rid, cls, created, rhash, status in (await db.execute(q)).all():
        if status == "rejected":  # a validator ruled this report wrong
            continue
        url = strip_url(norm)
        if url is None:
            continue
        try:
            u = parse_url(url)
        except URLParseError:
            continue
        path = u.path or "/"
        if idx.allowlisted(u.host, path):
            continue
        created = _aware(created)
        add("url", url, rid, cls, created, rhash, status)
        if u.ip is None and not idx.is_shortener(u.host) and not idx.is_abusable(u.host, path):
            add("domain", registrable_domain(u.host), rid, cls, created, rhash, status)
        if len(items) >= MAX_ITEMS:
            break
    return sorted(items.values(), key=lambda i: i["last_seen"], reverse=True)


def _pattern(kind: str, value: str) -> str:
    esc = value.replace("\\", "\\\\").replace("'", "\\'")
    return f"[url:value = '{esc}']" if kind == "url" else f"[domain-name:value = '{esc}']"


def stix_bundle(items: list[dict], *, now: datetime | None = None) -> dict:
    now = now or utcnow()
    objects: list[dict] = [{
        "type": "identity", "spec_version": "2.1", "id": IDENTITY, "created": _ts(datetime(2026, 11, 1, tzinfo=UTC)),
        "modified": _ts(datetime(2026, 11, 1, tzinfo=UTC)), "name": "CyberMatrix", "identity_class": "system"}]
    for it in items:
        sid = "indicator--" + str(uuid.uuid5(NAMESPACE, f"{it['type']}:{it['value']}"))
        refs = [{"source_name": "cybermatrix", "external_id": rid, "description": "CyberMatrix report id"}
                for rid in it["report_ids"]]
        obj = {
            "type": "indicator", "spec_version": "2.1", "id": sid, "created_by_ref": IDENTITY,
            "created": _ts(it["first_seen"]), "modified": _ts(it["last_seen"]),
            "name": f"{it['classification'].replace('_', ' ')} {it['type']}: {it['value']}",
            "indicator_types": ["malicious-activity"] if it["classification"] != "suspicious" else ["anomalous-activity"],
            "pattern": _pattern(it["type"], it["value"]), "pattern_type": "stix", "valid_from": _ts(it["first_seen"]),
            "confidence": CONFIDENCE[it["classification"]], "labels": [it["classification"]],
            "external_references": refs,
        }
        if it["onchain_status"]:
            obj["x_cybermatrix_registry"] = {"report_hash": it["report_hash"], "status": it["onchain_status"]}
        objects.append(obj)
    return {"type": "bundle", "id": "bundle--" + str(uuid.uuid4()), "objects": objects}


def blocklist(items: list[dict], *, now: datetime | None = None) -> str:
    now = now or utcnow()
    lines = [f"# CyberMatrix blocklist, generated {_ts(now)}",
             "# One URL or domain per line. Query strings removed; allowlisted sites never listed.",
             "# Built from reports on this server; a listing is evidence-based, not a guarantee."]
    lines += [it["value"] for it in items]
    return "\n".join(lines) + "\n"
