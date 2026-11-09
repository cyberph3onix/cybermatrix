"""REDIRECT.* checks, on top of the shared safe_fetch result (ctx.fetch())."""
from __future__ import annotations

import time

from app.brands import BrandIndex
from app.checks.base import AssessmentContext, CheckResult, evidence, make_finding, make_run
from app.fetch.safe_fetch import FetchResult
from app.schemas import CheckStatus, Finding
from app.urlutil import parse_url, registrable_domain

SOURCE = "local:safe_fetch"
GROUP = "fetch.redirects"


def _same_brand_official(a_host: str, b_host: str, idx: BrandIndex) -> bool:
    """Both hosts are official domains of the same brand (sbi.co.in → sbi.bank.in)."""
    ba, bb = idx.official_brand(a_host), idx.official_brand(b_host)
    return ba is not None and bb is not None and ba.id == bb.id


def analyze(submitted_host: str, fr: FetchResult, idx: BrandIndex) -> list[Finding]:
    if not fr.hops:
        return []
    out: list[Finding] = []
    hosts = [parse_url(h.url).host for h in fr.hops]
    final_host = hosts[-1]
    final_path = parse_url(fr.hops[-1].url).path or "/"
    sub_reg, fin_reg = registrable_domain(submitted_host), registrable_domain(final_host)

    cross_hops = []
    for prev, cur in zip(hosts, hosts[1:], strict=False):
        if registrable_domain(prev) != registrable_domain(cur) and not _same_brand_official(prev, cur, idx):
            cross_hops.append(f"{registrable_domain(prev)} → {registrable_domain(cur)}")

    if sub_reg != fin_reg and not _same_brand_official(submitted_host, final_host, idx):
        out.append(make_finding(
            "REDIRECT.CROSS_DOMAIN", f"Link leads to a different site: {fin_reg}",
            [evidence("http_redirect", f"Submitted {sub_reg}, landed on {fin_reg} after {len(fr.hops) - 1} redirect(s)",
                      SOURCE, {"submitted_domain": sub_reg, "final_domain": fin_reg, "final_host": final_host,
                               "final_path": final_path, "hops": len(fr.hops)})],
            "The page you end up on is not the one the link names.",
            f"Judge the destination ({fin_reg}) on its own, not the link text."))
    if len(cross_hops) >= 3:
        out.append(make_finding(
            "REDIRECT.LONG_CHAIN", f"Link bounces through {len(cross_hops)} different sites",
            [evidence("http_redirect", "Cross-domain hops: " + "; ".join(cross_hops), SOURCE,
                      {"cross_domain_hops": cross_hops})],
            "Long redirect chains are used to evade blocklists and hide the real destination.",
            "Do not open links that bounce through many unrelated sites."))
    return out


async def run(ctx: AssessmentContext) -> CheckResult:
    t0 = time.monotonic()
    try:
        fr = await ctx.fetch()
        if not fr.hops:
            status = CheckStatus.FAILED
            return make_run(GROUP, status, SOURCE, t0, f"fetch did not complete: {fr.error}"), []
        findings = analyze(ctx.url.host, fr, ctx.brands)
        detail = None
        if fr.blocked:
            detail = f"redirect chain stopped by fetch policy at hop {len(fr.hops) + 1}: {fr.error}"
        return make_run(GROUP, CheckStatus.COMPLETED, SOURCE, t0, detail), findings
    except Exception as e:  # noqa: BLE001
        return make_run(GROUP, CheckStatus.FAILED, SOURCE, t0, f"error: {type(e).__name__}"), []
