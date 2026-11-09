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
from app.db import IndicatorRow, RegistryRow, ReportRow
from app.engine import risk
from app.schemas import AssessmentReport, Coverage, Finding, RiskClass

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


async def apply_correlation(db: AsyncSession, report: AssessmentReport) -> AssessmentReport:
    """Add CORR findings, then re-run the deterministic classifier over all findings. No-op without matches."""
    from app.pipeline import ACTIONS  # local import: pipeline imports engine, not correlation

    extra, related = await correlation_findings(db, report)
    if not extra:
        return report
    findings = report.findings + extra
    cov: Coverage = report.coverage
    v = risk.classify(findings, cov.percent)
    return report.model_copy(update={
        "findings": findings, "classification": RiskClass(v.classification).value, "classification_reason": v.reason,
        "score": v.score, "confidence": str(getattr(v.confidence, "value", v.confidence)), "related_report_ids": related,
        "recommended_actions": ACTIONS[RiskClass(v.classification)],
        "limitations": report.limitations + [LIMITATION]})
