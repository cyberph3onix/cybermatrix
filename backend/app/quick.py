"""Quick pre-navigation check for the browser extension's real-time protection (POST /quick-check).

Runs only what needs no contact with the site: URL structure, lookalike detection, Google Safe Browsing (hash
prefixes only), the local OpenPhish feed, and earlier reports on this server (CORR.*). The page is never fetched,
so it is fast enough to run on every navigation, and the result is never stored (it would be browsing history).

The classification still comes from engine/risk.py. Groups that did not run are counted as unavailable, so a URL
with no findings comes out `inconclusive` (coverage ~30%), never `low_risk`: a quick check is not an assessment.
"""
from __future__ import annotations

import os
import time
from collections import OrderedDict
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

from app.brands import BrandIndex, get_index
from app.checks import lookalike, url_structure
from app.checks.base import AssessmentContext, make_run
from app.checks.intel import gsb, openphish
from app.correlation.checks import apply_correlation
from app.engine import coverage as cov
from app.engine import risk
from app.fetch.api_client import ApiUnavailable
from app.pipeline import Deps, warm_up
from app.schemas import (
    AssessmentReport,
    CheckRun,
    CheckStatus,
    Indicator,
    QuickCheck,
    QuickFinding,
    RiskClass,
    SubjectType,
    utcnow,
)
from app.urlutil import ParsedURL, registrable_domain

CACHE_S = 600
CACHE_MAX = 5000


class _Cache:
    """Small in-memory TTL cache keyed by the normalized URL (the result is the same for ten minutes)."""

    def __init__(self) -> None:
        self._d: OrderedDict[str, tuple[float, QuickCheck]] = OrderedDict()

    def get(self, key: str) -> QuickCheck | None:
        hit = self._d.get(key)
        if hit is None or time.monotonic() - hit[0] > CACHE_S:
            return None
        return hit[1]

    def put(self, key: str, value: QuickCheck) -> None:
        self._d[key] = (time.monotonic(), value)
        self._d.move_to_end(key)
        while len(self._d) > CACHE_MAX:
            self._d.popitem(last=False)


CACHE = _Cache()


async def _intel(ctx: AssessmentContext, group: str, source: str, lookup, build, key_env: str | None):
    t0 = time.monotonic()
    if key_env and not os.environ.get(key_env):
        return make_run(group, CheckStatus.UNAVAILABLE, source, t0, f"{key_env} is not set"), []
    try:
        hits = await lookup(ctx, [ctx.url.url_without_userinfo()])
        return make_run(group, CheckStatus.COMPLETED, source, t0), build(ctx, hits)
    except ApiUnavailable as e:
        return make_run(group, CheckStatus.UNAVAILABLE, source, t0, str(e)), []
    except Exception as e:  # noqa: BLE001
        return make_run(group, CheckStatus.FAILED, source, t0, f"error: {type(e).__name__}"), []


async def _openphish(ctx: AssessmentContext):
    t0 = time.monotonic()
    if not openphish.FEED.loaded:
        return make_run(openphish.GROUP, CheckStatus.UNAVAILABLE, openphish.SOURCE, t0, "feed not loaded"), []
    hits = await openphish.lookup(ctx, [ctx.url.url_without_userinfo()])
    return make_run(openphish.GROUP, CheckStatus.COMPLETED, openphish.SOURCE, t0), openphish.build(ctx, hits)


async def quick_check(db: AsyncSession, parsed: ParsedURL, *, deps: Deps, now: datetime | None = None) -> QuickCheck:
    key = parsed.url_without_userinfo()
    cached = CACHE.get(key)
    if cached is not None:
        return cached
    now = now or utcnow()
    idx: BrandIndex = deps.brands or get_index()
    await warm_up()
    ctx = AssessmentContext(url=parsed, brands=idx, now=now, api=deps.api, cache=deps.cache)

    results = [await url_structure.run(ctx), await lookalike.run(ctx),
               await _intel(ctx, gsb.GROUP, gsb.SOURCE, gsb.lookup, gsb.build, gsb.KEY_ENV),
               await _openphish(ctx)]
    runs: list[CheckRun] = [r for r, _ in results]
    findings = [f for _, fs in results for f in fs]
    ran = {r.check_group for r in runs}
    runs += [CheckRun(check_group=g, status=CheckStatus.UNAVAILABLE, source="local:quick", duration_ms=0,
                      weight=w, detail="not run in a quick check") for g, w in cov.WEIGHTS.items() if g not in ran]
    findings = risk.dampen(findings, idx, parsed.host, parsed.path or "/").kept
    coverage = cov.compute(runs)
    v = risk.classify(findings, coverage.percent)

    # Earlier reports on this server (validated reports, repeated reports, shared infrastructure).
    probe = AssessmentReport(
        created_at=now, subject_type=SubjectType.URL, subject=key, normalized_subject=key,
        classification=v.classification, classification_reason=v.reason, score=v.score, confidence=v.confidence,
        coverage=coverage, findings=findings, check_runs=runs, limitations=["quick check"],
        indicators=[Indicator(type="url", value=key, normalized=key)]
        + ([] if parsed.ip else [Indicator(type="domain", value=parsed.host, normalized=registrable_domain(parsed.host))]))
    probe = await apply_correlation(db, probe)

    out = QuickCheck(
        url=key, classification=RiskClass(probe.classification), classification_reason=probe.classification_reason,
        coverage_percent=coverage.percent,
        findings=[QuickFinding(check_id=f.check_id, title=f.title, severity=f.severity)
                  for f in sorted(probe.findings, key=lambda f: -risk.SEV_RANK[str(f.severity)])])
    CACHE.put(key, out)
    return out
