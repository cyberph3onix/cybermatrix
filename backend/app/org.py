"""Organisation-level website security dashboard.

An organisation is a named list of its domains (at most 20). For each domain the dashboard shows:
- security posture and risk class from the latest assessment of the domain's home page (POST /orgs/{id}/scan
  re-assesses all of them; it is the normal passive assessment, so nothing extra is sent to the sites);
- Certificate Transparency alerts: every domain gets a CT watch (app/watch.py) when the organisation is created;
- impersonation: reports on this server at suspicious or worse that imitate the domain (lookalike findings that
  name it) or its brand (brand_claimed indicators), excluding the organisation's own sites.
Like CT watches, the id is a random token and is the only way to open the dashboard. Everything shown is derived
from public information about the domains, so no ownership proof is needed.
"""
from __future__ import annotations

import json
import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import ownership, store
from app.brands import BrandIndex
from app.db import IndicatorRow, OrgRow, ReportRow, WatchAlertRow, WatchRow
from app.schemas import (
    OrgDashboard,
    OrgDomain,
    OrgImpersonation,
    OrgLatestReport,
    PostureCount,
    RiskClass,
    utcnow,
)
from app.urlutil import URLParseError, parse_url, registrable_domain, split_domain

MAX_DOMAINS = 20
SCAN_COOLDOWN = timedelta(minutes=10)
IMPERSONATION_WINDOW = timedelta(days=90)
IMPERSONATION_SCAN = 500
BAD = ("suspicious", "high_risk", "confirmed_malicious")


class OrgError(ValueError):
    """Bad input. The message is safe to show."""


def new_token() -> str:
    return secrets.token_hex(12)


def normalize_domains(raw: list[str]) -> list[str]:
    out: list[str] = []
    for d in raw:
        d = d.strip()
        if not d:
            continue
        try:
            dom = ownership.domain_of(d)
        except ownership.OwnershipError as e:
            raise OrgError(f"{d[:80]}: {e}") from None
        if dom not in out:
            out.append(dom)
    if not out:
        raise OrgError("Add at least one domain.")
    if len(out) > MAX_DOMAINS:
        raise OrgError(f"At most {MAX_DOMAINS} domains per organisation.")
    return out


def _aware(dt: datetime | None) -> datetime | None:
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=UTC)


def _subject_domain(normalized_subject: str) -> str | None:
    try:
        u = parse_url(normalized_subject)
    except URLParseError:
        return None
    return None if u.ip else registrable_domain(u.host)


async def _latest(db: AsyncSession, domain: str) -> OrgLatestReport | None:
    q = (select(ReportRow).join(IndicatorRow, IndicatorRow.report_id == ReportRow.report_id)
         .where(IndicatorRow.type == "domain", IndicatorRow.normalized == domain,
                ReportRow.subject_type.in_(["url", "domain"]))
         .order_by(ReportRow.created_at.desc()).limit(20))
    for row in (await db.execute(q)).scalars():
        if _subject_domain(row.normalized_subject) != domain:
            continue  # the domain only appeared as a redirect hop
        r = store.parse_report(row)
        counts = PostureCount()
        for f in r.security_posture:
            sev = str(f.severity)
            if sev in ("high", "critical"):
                counts.high += 1
            elif sev == "medium":
                counts.medium += 1
            elif sev == "low":
                counts.low += 1
        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        titles = [f.title for f in sorted(r.security_posture, key=lambda f: rank.get(str(f.severity), 5))][:5]
        return OrgLatestReport(report_id=r.report_id, classification=RiskClass(r.classification),
                               coverage_percent=r.coverage.percent, created_at=_aware(r.created_at),
                               posture=counts, posture_titles=titles)
    return None


async def _impersonation(db: AsyncSession, idx: BrandIndex, domains: list[str], now: datetime
                         ) -> dict[str, OrgImpersonation]:
    """Reports imitating each domain: lookalike evidence naming it, or a brand claim for the brand it belongs to."""
    own = set(domains)
    brand_of = {d: b.id for d in domains if (b := idx.official_brand(d)) is not None}
    found: dict[str, list[tuple[datetime, str, str]]] = {d: [] for d in domains}
    q = (select(ReportRow).where(ReportRow.classification.in_(BAD),
                                 ReportRow.created_at >= now - IMPERSONATION_WINDOW)
         .order_by(ReportRow.created_at.desc()).limit(IMPERSONATION_SCAN))
    rows = list((await db.execute(q)).scalars())
    claimed: dict[str, set[str]] = {}
    if brand_of and rows:
        ids = [r.report_id for r in rows]
        bq = select(IndicatorRow.report_id, IndicatorRow.normalized).where(
            IndicatorRow.type == "brand_claimed", IndicatorRow.report_id.in_(ids))
        for rid, bid in (await db.execute(bq)).all():
            claimed.setdefault(rid, set()).add(bid)
    for row in rows:
        subj = _subject_domain(row.normalized_subject)
        if subj in own:
            continue
        hits: set[str] = {d for d, bid in brand_of.items() if bid in claimed.get(row.report_id, set())}
        canon = row.canonical
        if any(d.encode() in canon for d in domains):  # cheap prefilter before parsing
            for f in json.loads(canon).get("findings", []):
                if not str(f.get("check_id", "")).startswith("URL.LOOKALIKE"):
                    continue
                for e in f.get("evidence", []):
                    target = str((e.get("data") or {}).get("lookalike_of", "")).lower()
                    if target:  # a domain ("paypal.com") or a bare label ("paypal")
                        hits |= {d for d in domains
                                 if (registrable_domain(target) == d if "." in target else split_domain(d)[1] == target)}
        for d in hits:
            found[d].append((_aware(row.created_at), row.report_id, subj or row.normalized_subject[:80]))
    out = {}
    for d, items in found.items():
        items.sort(reverse=True)
        out[d] = OrgImpersonation(reports=len(items), report_ids=[i[1] for i in items[:5]],
                                  lookalike_domains=list(dict.fromkeys(i[2] for i in items))[:10])
    return out


async def dashboard(db: AsyncSession, idx: BrandIndex, org: OrgRow, now: datetime | None = None) -> OrgDashboard:
    now = now or utcnow()
    imp = await _impersonation(db, idx, list(org.domains), now)
    out: list[OrgDomain] = []
    for d in org.domains:
        wid = (org.watch_ids or {}).get(d)
        alerts = new_issuer = 0
        last_checked = None
        if wid:
            w = await db.get(WatchRow, wid)
            last_checked = _aware(w.last_checked) if w else None
            alerts = int((await db.execute(select(func.count()).select_from(WatchAlertRow)
                                           .where(WatchAlertRow.watch_id == wid))).scalar_one())
            new_issuer = int((await db.execute(select(func.count()).select_from(WatchAlertRow)
                                               .where(WatchAlertRow.watch_id == wid,
                                                      WatchAlertRow.new_issuer.is_(True)))).scalar_one())
        out.append(OrgDomain(domain=d, latest=await _latest(db, d), watch_id=wid, ct_alerts=alerts,
                             ct_new_issuer_alerts=new_issuer, ct_last_checked=last_checked, impersonation=imp[d]))
    return OrgDashboard(org_id=org.org_id, name=org.name, created_at=_aware(org.created_at),
                        last_scan=_aware(org.last_scan), domains=out)


def scan_wait(org: OrgRow, now: datetime | None = None) -> int | None:
    """Seconds until another scan is allowed, or None if it is allowed now."""
    now = now or utcnow()
    last = _aware(org.last_scan)
    if last is None or now - last >= SCAN_COOLDOWN:
        return None
    return int((SCAN_COOLDOWN - (now - last)).total_seconds()) + 1
