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
from app.schemas import Cluster, ClusterIndicator, RiskClass

SPECIFIC_TYPES = frozenset({"domain", "cert_sha256", "email", "phone", "upi_id", "crypto_address"})
SEVERITY = {"suspicious": 1, "high_risk": 2, "confirmed_malicious": 3}
LABEL_BY_TYPE = {"domain": "domain", "cert_sha256": "TLS certificate", "email": "email address", "phone": "phone number",
                 "upi_id": "UPI ID", "crypto_address": "crypto address"}

Row = tuple[str, str, str, str, datetime]  # report_id, type, normalized, classification, created_at


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
        lead = shared_inds[0]
        key = hashlib.sha256("|".join(f"{i.type}:{i.value}" for i in shared_inds).encode()).hexdigest()[:12]
        clusters.append(Cluster(
            cluster_id=f"c-{key}", label=f"{len(members)} reports sharing a {LABEL_BY_TYPE[lead.type]}: {lead.value[:40]}",
            first_seen=seen[0], last_seen=seen[-1], report_ids=sorted(members), top_classification=RiskClass(top),
            shared_indicators=shared_inds, member_domains=domains))
    clusters.sort(key=lambda c: (c.last_seen, len(c.report_ids)), reverse=True)
    return clusters
