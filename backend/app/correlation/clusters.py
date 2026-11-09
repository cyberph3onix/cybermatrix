"""Clusters: reports at `suspicious` or worse that share a *specific* indicator.

Specific = registrable domain, certificate fingerprint, email, phone, UPI id, crypto address. IPs, ASNs and
nameservers are deliberately excluded: shared hosting and CDNs would glue unrelated sites together. Domains of
allowlisted sites and URL shorteners are ignored for the same reason (everything redirects through bit.ly).
"""
from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import datetime

from app.brands import BrandIndex, get_index
from app.schemas import Cluster, ClusterEdge, ClusterIndicator, ImpersonationTrend, RiskClass, TrendTechnique

SPECIFIC_TYPES = frozenset({"domain", "cert_sha256", "email", "phone", "upi_id", "crypto_address", "message_family"})
SEVERITY = {"suspicious": 1, "high_risk": 2, "confirmed_malicious": 3}
LABEL_BY_TYPE = {"domain": "domain", "cert_sha256": "TLS certificate", "email": "email address", "phone": "phone number",
                 "upi_id": "UPI ID", "crypto_address": "crypto address", "message_family": "message wording"}

MAX_EDGES = 50
Row = tuple[str, str, str, str, datetime]  # report_id, type, normalized, classification, created_at


# check_id prefix -> impersonation technique (M4-3: group by claimed brand AND technique)
TECHNIQUES = (
    ("URL.LOOKALIKE.", "lookalike_domain"), ("URL.PUNYCODE_MIXED_SCRIPT", "lookalike_domain"),
    ("URL.BRAND_IN_SUBDOMAIN", "brand_in_subdomain"), ("URL.USERINFO_TRICK", "brand_in_subdomain"),
    ("PAGE.CREDENTIAL_FORM", "fake_login_page"), ("PAGE.BRAND_MISMATCH", "fake_login_page"),
    ("MSG.SENDER_DOMAIN_MISMATCH", "spoofed_sender"), ("MSG.DMARC_FAIL", "spoofed_sender"),
    ("MSG.SPF_DKIM_FAIL", "spoofed_sender"), ("MSG.CREDENTIAL_REQUEST", "credential_request"),
    ("MSG.PAYMENT_REQUEST", "payment_request"), ("MSG.REMOTE_ACCESS_REQUEST", "remote_access"),
    ("MSG.REWARD_LURE", "reward_lure"), ("MSG.INVESTMENT_LURE", "reward_lure"),
)


def techniques_of(check_ids: list[str]) -> set[str]:
    return {t for cid in check_ids for prefix, t in TECHNIQUES if cid.startswith(prefix)}


def impersonation_trends(rows: list[Row], subject_types: dict[str, str], idx: BrandIndex | None = None,
                         min_reports: int = 2, techniques: dict[str, set[str]] | None = None) -> list[ImpersonationTrend]:
    """Brands that several suspicious-or-worse reports impersonate (brand_claimed indicators), busiest first, with
    how they do it (`techniques`: report_id -> technique set, from techniques_of)."""
    idx = idx or get_index()
    names = {b.id: b.name for b in idx.brands}
    by_brand: dict[str, dict[str, datetime]] = defaultdict(dict)
    for rid, typ, norm, _cls, created in rows:
        if typ == "brand_claimed":
            by_brand[norm][rid] = created
    out = []
    for bid, reps in by_brand.items():
        if len(reps) < min_reports:
            continue
        ordered = sorted(reps, key=lambda r: reps[r], reverse=True)
        msgs = sum(subject_types.get(r) == "message" for r in reps)
        out.append(ImpersonationTrend(brand_id=bid, brand=names.get(bid, bid), reports=len(reps), messages=msgs,
                                      links=len(reps) - msgs, first_seen=min(reps.values()), last_seen=max(reps.values()),
                                      report_ids=ordered[:10], techniques=_count_techniques(reps, techniques or {})))
    out.sort(key=lambda t: (t.reports, t.last_seen), reverse=True)
    return out


def _count_techniques(report_ids, techniques: dict[str, set[str]]) -> list[TrendTechnique]:
    counts: dict[str, int] = defaultdict(int)
    for r in report_ids:
        for t in techniques.get(r, ()):
            counts[t] += 1
    return [TrendTechnique(technique=t, reports=n) for t, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))]


def _ignored(typ: str, norm: str, idx: BrandIndex) -> bool:
    return typ == "domain" and (idx.allowlisted(norm) or idx.is_shortener(norm))


def build_clusters(rows: list[Row], idx: BrandIndex | None = None) -> list[Cluster]:
    idx = idx or get_index()
    reports: dict[str, tuple[str, datetime]] = {}
    by_indicator: dict[tuple[str, str], set[str]] = defaultdict(set)
    for rid, typ, norm, cls, created in rows:
        reports[rid] = (cls, created)
        if typ in SPECIFIC_TYPES and not _ignored(typ, norm, idx):
            by_indicator[(typ, norm)].add(rid)

    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    shared = {k: v for k, v in by_indicator.items() if len(v) >= 2}
    for members in shared.values():
        first, *rest = sorted(members)
        for r in rest:
            parent[find(r)] = find(first)

    groups: dict[str, set[str]] = defaultdict(set)
    for members in shared.values():
        for r in members:
            groups[find(r)].add(r)

    clusters = []
    for members in groups.values():
        inds = sorted(((k, v & members) for k, v in shared.items() if v & members), key=lambda kv: (-len(kv[1]), kv[0]))
        shared_inds = [ClusterIndicator(type=t, value=n, report_count=len(m)) for (t, n), m in inds]
        top = max((reports[r][0] for r in members), key=lambda c: SEVERITY[c])
        seen = sorted(reports[r][1] for r in members)
        domains = sorted({n for (t, n), v in by_indicator.items() if t == "domain" and v & members})
        edges = []
        for (t, n), m in inds:  # a star per shared indicator: enough to show why every member is here
            first, *rest = sorted(m)
            what = "near-identical message wording" if t == "message_family" else f"{LABEL_BY_TYPE[t]} {n[:60]}"
            edges += [ClusterEdge(from_report=first, to_report=r, type=t, value=n, reason=f"both contain {what}")
                      for r in rest]
        lead = shared_inds[0]
        key = hashlib.sha256("|".join(f"{i.type}:{i.value}" for i in shared_inds).encode()).hexdigest()[:12]
        clusters.append(Cluster(
            cluster_id=f"c-{key}", label=(f"{len(members)} reports with near-identical message wording"
                                          if lead.type == "message_family" else
                                          f"{len(members)} reports sharing a {LABEL_BY_TYPE[lead.type]}: {lead.value[:40]}"),
            first_seen=seen[0], last_seen=seen[-1], report_ids=sorted(members), top_classification=RiskClass(top),
            shared_indicators=shared_inds, member_domains=domains, edges=edges[:MAX_EDGES]))
    clusters.sort(key=lambda c: (c.last_seen, len(c.report_ids)), reverse=True)
    return clusters
