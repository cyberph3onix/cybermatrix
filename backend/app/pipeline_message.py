"""Message / email assessment: local extraction + signals, optional LLM signals, then the URL pipeline per link.

Redaction happens first; only the redacted text can reach the LLM. The classification still comes from
engine.risk over deterministic findings (LLM findings are heuristic and capped).
"""
from __future__ import annotations

import asyncio
import time

from app.ai.llm import LlmClient, LlmUnavailable
from app.ai.message_signals import llm_signals
from app.ai.redact import redact
from app.brands import get_index
from app.checks import message as msg
from app.engine import coverage as cov
from app.engine import risk
from app.pipeline import ACTIONS, FIXED_LIMITATIONS, Deps, assess_url
from app.schemas import (
    AssessmentReport,
    CheckRun,
    CheckStatus,
    Coverage,
    Finding,
    RiskClass,
    SubjectType,
    utcnow,
)

MAX_URLS = 3
W_EXTRACT, W_LLM, W_URLS = 20, 30, 50


def _run(group: str, status: CheckStatus, source: str, t0: float, weight: int, detail: str | None = None) -> CheckRun:
    return CheckRun(check_group=group, status=status, source=source, duration_ms=int((time.monotonic() - t0) * 1000),
                    weight=weight, detail=detail)


async def assess_message(text: str, *, deps: Deps | None = None, llm: LlmClient | None = None,
                         subject_type: SubjectType = SubjectType.MESSAGE) -> AssessmentReport:
    deps, idx, now = deps or Deps(), get_index(), utcnow()
    red = redact(text)
    t0 = time.monotonic()
    ex = msg.extract(text)
    findings: list[Finding] = msg.regex_signals(text, idx) + msg.header_findings(text, idx)
    indicators = ex.indicators(idx)
    has_urls = bool(ex.urls)
    w_extract, w_llm, w_urls = (W_EXTRACT, W_LLM, W_URLS) if has_urls else (W_EXTRACT * 100 // 50, W_LLM * 100 // 50, 0)
    runs = [_run("message.extract", CheckStatus.COMPLETED, msg.SOURCE, t0, w_extract)]

    t1 = time.monotonic()
    if llm is None:
        runs.append(_run("message.signals", CheckStatus.UNAVAILABLE, "llm", t1, w_llm, "no LLM key set (GEMINI_API_KEY or ANTHROPIC_API_KEY)"))
    else:
        try:
            have = {f.check_id for f in findings}
            findings += [f for f in await llm_signals(llm, red.text) if f.check_id not in have]
            runs.append(_run("message.signals", CheckStatus.COMPLETED, f"llm:{llm.model}", t1, w_llm))
        except LlmUnavailable as e:
            runs.append(_run("message.signals", CheckStatus.UNAVAILABLE, f"llm:{llm.model}", t1, w_llm, str(e)))

    limitations = list(FIXED_LIMITATIONS) + [
        "Names are only masked after a salutation or title; other personal details are masked by pattern.",
        "Message wording alone cannot prove fraud; it is reported as a weak (heuristic) signal.",
    ]
    if red.counts:
        limitations.append("Before any AI call, these were masked: " + ", ".join(f"{k} ×{v}" for k, v in red.counts.items()) + ".")
    url_pcts: list[int] = []
    if has_urls:
        t2 = time.monotonic()
        subs = await asyncio.gather(*(assess_url(u, deps=deps) for u in ex.urls[:MAX_URLS]))
        for u, sub in zip(ex.urls[:MAX_URLS], subs, strict=True):
            ref = msg.parse_url(u).url_without_userinfo() if u else u
            findings += [f.model_copy(update={"indicator_ref": ref}) for f in sub.findings]
            url_pcts.append(sub.coverage.percent)
            # the link's own indicators (redirect hops incl. the final destination, IPs, nameservers, certificate)
            # so campaigns using different links to the same infrastructure correlate. A hop's domain is not a
            # `url` indicator, so correlation/checks.py still never treats it as something the user submitted.
            have = {(i.type, i.normalized) for i in indicators}
            for i in sub.indicators:
                if i.type != "url" and (i.type, i.normalized) not in have:
                    have.add((i.type, i.normalized))
                    indicators.append(i)
            limitations += [f"{u[:60]}: {x}" for x in sub.limitations if x not in FIXED_LIMITATIONS and "AI explanation" not in x]
        if len(ex.urls) > MAX_URLS:
            limitations.append(f"Only the first {MAX_URLS} of {len(ex.urls)} links were checked.")
        pct = sum(url_pcts) // len(url_pcts)
        status = CheckStatus.COMPLETED if pct >= 50 else CheckStatus.FAILED
        runs.append(_run("message.urls", status, "pipeline:assess_url", t2, w_urls, f"average link coverage {pct}%"))

    coverage = _coverage(runs, url_pcts)
    verdict = risk.classify(findings, coverage.percent)
    limitations += [f"{r.check_group} {r.status.value if isinstance(r.status, CheckStatus) else r.status}: {r.detail}"
                    for r in runs if str(getattr(r.status, "value", r.status)) not in ("completed",)]
    limitations.append("AI explanation not generated; classification is rule-based.")
    return AssessmentReport(
        created_at=now, subject_type=subject_type, subject=red.text, normalized_subject=red.text[:200],
        classification=verdict.classification, classification_reason=verdict.reason, score=verdict.score,
        confidence=verdict.confidence, coverage=coverage, findings=findings, check_runs=runs,
        indicators=indicators, recommended_actions=ACTIONS[RiskClass(verdict.classification)], limitations=limitations)


def _coverage(runs: list[CheckRun], url_pcts: list[int]) -> Coverage:
    """Weighted share of completed groups; the link group counts in proportion to how much of it completed."""
    total = sum(r.weight for r in runs)
    done = 0
    for r in runs:
        if r.check_group == "message.urls" and url_pcts:
            done += r.weight * (sum(url_pcts) // len(url_pcts)) // 100
        elif r.status == CheckStatus.COMPLETED or r.status == CheckStatus.COMPLETED.value:
            done += r.weight
    base = cov.compute(runs)
    return base.model_copy(update={"percent": (done * 100) // total if total else 0})


async def assess_email(address: str, *, deps: Deps | None = None, owns_site: bool = False) -> AssessmentReport:
    """An email address alone can only be judged by its domain: run the URL pipeline on it and add the address as an indicator."""
    from app.schemas import Indicator
    addr = address.strip()
    domain = addr.rsplit("@", 1)[1].lower()
    rep = await assess_url(domain, deps=deps, owns_site=owns_site)
    inds = [*rep.indicators, Indicator(type="email", value=addr, normalized=addr.lower())]
    lim = [*rep.limitations, "Only the sender's domain was assessed; an address cannot be verified as genuine or forged."]
    return rep.model_copy(update={"subject_type": SubjectType.EMAIL, "subject": addr, "normalized_subject": addr.lower(),
                                  "indicators": inds, "limitations": lim})
