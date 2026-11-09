"""CORR.* findings: compare a fresh report's indicators with the reports already stored (docs/RISK_ENGINE.md).

Deliberately conservative, because a false CORR finding makes a legitimate site look bad:
- only reports at `suspicious` or worse count as "prior" (a site that was merely assessed many times is not a lead);
- allowlisted domains and URL shorteners never correlate;
- IP / ASN / nameserver / certificate matches are only ever CORR.SHARED_INFRA (low, heuristic): shared hosting
  and CDNs make them weak;
- CORR.VALIDATED_MATCH needs a *specific* indicator and a registry row whose status is `validated`. That status
  is the last one this server saw (it refreshes when the report's registration is viewed), not a live chain read.
Evidence names the matching report IDs, never the matching email / phone / UPI / crypto value.
"""
from __future__ import annotations

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.brands import BrandIndex, get_index
from app.checks.base import evidence, make_finding
from app.correlation import similarity
from app.db import IndicatorRow, RegistryRow, ReportRow
from app.engine import risk
from app.schemas import AssessmentReport, Coverage, Finding, Indicator, RiskClass, SubjectType
from app.urlutil import URLParseError, parse_url, registrable_domain

SOURCE = "local:correlation"
SPECIFIC = ("domain", "email", "phone", "upi_id", "crypto_address")
INFRA = ("ip", "asn", "nameserver", "cert_sha256")
OPEN_VALUE = ("domain", "ip", "asn", "nameserver", "cert_sha256")  # infrastructure values may appear in evidence
BAD = ("suspicious", "high_risk", "confirmed_malicious")
MIN_PRIOR = 2
MAX_IDS = 5
LIMITATION = ("Correlation compares against reports stored on this server only. A shared indicator is a lead, "
              "not proof of a common operator.")


def _eligible(report: AssessmentReport, idx: BrandIndex) -> list[tuple[str, str]]:
    out = []
    for ind in report.indicators:
        if ind.type not in SPECIFIC + INFRA:
            continue
        if ind.type == "domain" and (idx.allowlisted(ind.normalized) or idx.is_shortener(ind.normalized)):
            continue
        out.append((ind.type, ind.normalized))
    return list(dict.fromkeys(out))


async def _matches(db: AsyncSession, pairs: list[tuple[str, str]], own_id: str):
    cond = or_(*[and_(IndicatorRow.type == t, IndicatorRow.normalized == n) for t, n in pairs])
    q = (select(IndicatorRow.report_id, IndicatorRow.type, IndicatorRow.normalized, ReportRow.classification,
                RegistryRow.status)
         .join(ReportRow, ReportRow.report_id == IndicatorRow.report_id)
         .join(RegistryRow, RegistryRow.report_id == IndicatorRow.report_id, isouter=True)
         .where(cond, IndicatorRow.report_id != own_id))
    return (await db.execute(q)).all()


async def _drop_redirect_only_domains(db: AsyncSession, rows):
    """Keep a prior report's `domain` match only if that domain was a *subject* of the prior report (the host of a
    URL that was submitted or appeared in a submitted message), not merely a host its redirect chain passed through.
    Anyone can make a phishing URL redirect to a victim's homepage; without this, validating that phishing report
    would make the victim's own domain CORR.VALIDATED_MATCH (confirmed_malicious)."""
    ids = {r[0] for r in rows if r[1] == "domain"}
    if not ids:
        return rows
    q = select(IndicatorRow.report_id, IndicatorRow.normalized).where(
        IndicatorRow.type == "url", IndicatorRow.report_id.in_(ids))
    subjects: dict[str, set[str]] = {}
    for rid, url in (await db.execute(q)).all():
        try:
            subjects.setdefault(rid, set()).add(registrable_domain(parse_url(url).host))
        except URLParseError:
            continue
    return [r for r in rows if r[1] != "domain" or r[2] in subjects.get(r[0], set())]


def _ev(kind_desc: str, matches: list[tuple[str, str, str]]) -> list:
    """matches: (report_id, type, normalized). One evidence item per indicator type."""
    out = []
    for typ in dict.fromkeys(m[1] for m in matches):
        rows = [m for m in matches if m[1] == typ]
        ids = sorted({m[0] for m in rows})[:MAX_IDS]
        data = {"indicator_type": typ, "matching_reports": len(ids), "report_ids": ids}
        if typ in OPEN_VALUE:
            data["indicator"] = rows[0][2]
        out.append(evidence("db_match", f"{kind_desc}: {len(ids)} stored report(s) share the same {typ}.",
                            SOURCE, data))
    return out


async def correlation_findings(db: AsyncSession, report: AssessmentReport, idx: BrandIndex | None = None
                               ) -> tuple[list[Finding], list[str]]:
    idx = idx or get_index()
    pairs = _eligible(report, idx)
    if not pairs:
        return [], []
    rows = await _matches(db, pairs, report.report_id)
    rows = await _drop_redirect_only_domains(db, rows)
    findings: list[Finding] = []
    related: list[str] = []

    validated = [(r, t, n) for r, t, n, _c, st in rows if st == "validated" and t in SPECIFIC]
    if validated:
        findings.append(make_finding(
            "CORR.VALIDATED_MATCH", "Shares an indicator with a community-validated threat report",
            _ev("Validated match", validated),
            "A report with the same indicator was reviewed and validated in the community registry.",
            "Do not open the link or engage with this sender.", limitation=LIMITATION))
        related += [r for r, _, _ in validated]

    vids = {r for r, _, _ in validated}
    prior = [(r, t, n) for r, t, n, c, st in rows if c in BAD and t in SPECIFIC and r not in vids]
    if len({r for r, _, _ in prior}) >= MIN_PRIOR:
        findings.append(make_finding(
            "CORR.PRIOR_REPORTS", "Shares indicators with several earlier suspicious reports", _ev("Prior reports", prior),
            "The same domain, contact detail or payment handle has already shown up in other reports that looked "
            "suspicious or worse.", "Treat this with extra caution and verify through an official channel.",
            limitation=LIMITATION))
        related += [r for r, _, _ in prior]

    infra = [(r, t, n) for r, t, n, c, _st in rows if c in BAD and t in INFRA]
    if infra:
        findings.append(make_finding(
            "CORR.SHARED_INFRA", "Runs on infrastructure seen in an earlier suspicious report", _ev("Shared infrastructure", infra),
            "Shared hosting is common, so this is a weak hint on its own.",
            "Weigh it only together with the other findings.", limitation=LIMITATION))
        related += [r for r, _, _ in infra]

    return findings, list(dict.fromkeys(related))[:10]


async def similar_messages(db: AsyncSession, report: AssessmentReport) -> tuple[str, list[tuple[str, int]]]:
    """(message_family, [(report_id, similarity %)]) against recent suspicious-or-worse messages, most similar first."""
    own = similarity.shingles(report.subject)
    family = similarity.template_hash(report.subject)
    if len(own) < similarity.MIN_SHINGLES:
        return family, []
    q = (select(ReportRow).where(ReportRow.subject_type == SubjectType.MESSAGE.value, ReportRow.classification.in_(BAD),
                                 ReportRow.report_id != report.report_id)
         .order_by(ReportRow.created_at.desc()).limit(similarity.RECENT_LIMIT))
    hits: list[tuple[int, str, str]] = []
    for row in (await db.execute(q)).scalars():
        prior = AssessmentReport.model_validate_json(row.canonical)
        pct = similarity.jaccard_pct(own, similarity.shingles(prior.subject))
        if pct >= similarity.SIMILAR:
            fam = next((i.normalized for i in prior.indicators if i.type == "message_family"),
                       similarity.template_hash(prior.subject))
            hits.append((pct, row.report_id, fam))
    hits.sort(key=lambda h: -h[0])
    return (hits[0][2] if hits else family), [(rid, pct) for pct, rid, _ in hits[:MAX_IDS]]


def _similar_finding(matches: list[tuple[str, int]]) -> Finding:
    ids = [r for r, _ in matches]
    return make_finding(
        "CORR.SIMILAR_MESSAGE", f"Wording matches {len(ids)} earlier suspicious message(s)",
        [evidence("text_similarity", f"Up to {matches[0][1]}% of the message's phrasing matches {len(ids)} stored suspicious "
                  "report(s), ignoring links, numbers and amounts.", SOURCE,
                  {"matching_reports": len(ids), "report_ids": ids, "best_similarity_pct": matches[0][1]})],
        "Scam campaigns reuse the same text with different links or numbers.",
        "Treat it as part of the same campaign: do not use its links or numbers.", limitation=LIMITATION)


async def apply_correlation(db: AsyncSession, report: AssessmentReport) -> AssessmentReport:
    """Add derived indicators (brand_claimed, message_family) and CORR findings, then re-run the deterministic
    classifier over all findings."""
    from app.pipeline import ACTIONS  # local import: pipeline imports engine, not correlation

    idx = get_index()
    derived: list[Indicator] = similarity.brand_indicators(report, idx)
    extra, related = await correlation_findings(db, report, idx)
    if str(getattr(report.subject_type, "value", report.subject_type)) == SubjectType.MESSAGE.value:
        family, similar = await similar_messages(db, report)
        derived.append(Indicator(type="message_family", value=family[:12], normalized=family))
        if similar:
            extra.append(_similar_finding(similar))
            related += [r for r, _ in similar]
    have = {(i.type, i.normalized) for i in report.indicators}
    report = report.model_copy(update={"indicators": report.indicators + [i for i in derived if (i.type, i.normalized) not in have]})
    if not extra:
        return report
    findings = report.findings + extra
    cov: Coverage = report.coverage
    v = risk.classify(findings, cov.percent)
    return report.model_copy(update={
        "findings": findings, "classification": RiskClass(v.classification).value, "classification_reason": v.reason,
        "score": v.score, "confidence": str(getattr(v.confidence, "value", v.confidence)),
        "related_report_ids": list(dict.fromkeys(related))[:10],
        "recommended_actions": ACTIONS[RiskClass(v.classification)],
        "limitations": report.limitations + [LIMITATION]})
