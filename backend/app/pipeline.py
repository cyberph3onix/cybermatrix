"""URL assessment pipeline: run every check concurrently with per-check timeouts, then classify deterministically."""
from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime

from app.brands import BrandIndex, get_index
from app.checks import domain_rdap, headers, lookalike, page, redirects, tls_chain, tls_ct, url_structure
from app.checks.base import AssessmentContext, CheckResult, make_run
from app.checks.intel import gsb, openphish, urlhaus, virustotal
from app.engine import coverage as cov
from app.engine import risk
from app.schemas import (
    AssessmentReport,
    CheckRun,
    CheckStatus,
    Finding,
    Indicator,
    RiskClass,
    SubjectType,
    utcnow,
)
from app.urlutil import URLParseError, parse_url, registrable_domain

CheckFn = Callable[[AssessmentContext], Awaitable[CheckResult]]


@dataclass(frozen=True)
class CheckSpec:
    group: str
    fn: CheckFn
    timeout_s: float
    source: str


# TLS checks first wait for the fetch (≤ 15 s) to learn the final host, then scan (≤ 10 s).
CHECKS: list[CheckSpec] = [
    CheckSpec("url.structure", url_structure.run, 2, url_structure.SOURCE),
    CheckSpec("url.lookalike", lookalike.run, 2, lookalike.SOURCE),
    CheckSpec("fetch.redirects", redirects.run, 20, redirects.SOURCE),
    CheckSpec("page.content", page.run, 20, page.SOURCE),
    CheckSpec("tls.chain", tls_chain.run, 30, tls_chain.SOURCE),
    CheckSpec("tls.revocation", tls_chain.run_revocation, 40, tls_chain.SOURCE),
    CheckSpec("tls.ct", tls_ct.run, 36, "certspotter"),
    # Intel checks look up the submitted URL at once, then wait (≤ 16 s) for the redirect chain to look up the
    # destination too.
    CheckSpec(gsb.GROUP, gsb.run, 30, gsb.SOURCE),
    CheckSpec(urlhaus.GROUP, urlhaus.run, 30, urlhaus.SOURCE),
    CheckSpec(openphish.GROUP, openphish.run, 30, openphish.SOURCE),
    CheckSpec(virustotal.GROUP, virustotal.run, 30, virustotal.SOURCE),
    CheckSpec(domain_rdap.GROUP, domain_rdap.run, 30, domain_rdap.SOURCE),
    # Posture (weight 0): waits for the fetch and the TLS scan, reports into security_posture only.
    CheckSpec(headers.GROUP, headers.run, 50, headers.SOURCE),
]

FIXED_LIMITATIONS = [
    "Absence of threat-intel listings does not prove safety.",
    tls_chain.CA_LIMITATION,
    "Only passive checks were run: no JavaScript was executed and nothing was submitted to the site.",
]

ACTIONS = {
    RiskClass.CONFIRMED_MALICIOUS: [
        "Do not open the link or enter any information.",
        "If you already entered details, contact your bank and call 1930 (National Cyber Crime Helpline) now.",
        "Report the link at cybercrime.gov.in.",
    ],
    RiskClass.HIGH_RISK: [
        "Do not enter passwords, OTPs, PINs or card details on this site.",
        "Reach the organisation through its official app or a typed-in address instead.",
        "Report the link at cybercrime.gov.in if it arrived unsolicited.",
    ],
    RiskClass.SUSPICIOUS: [
        "Be cautious: verify the site through an official channel before entering any information.",
        "Do not share OTPs or PINs; no bank or government office asks for them.",
    ],
    RiskClass.INCONCLUSIVE: [
        "Too few checks completed to judge this link. Treat it with caution and try again later.",
    ],
    RiskClass.LOW_RISK: [
        "No significant malicious indicators were found, but stay alert: never share OTPs or PINs.",
    ],
}


@dataclass
class Deps:
    brands: BrandIndex | None = None
    fetcher: Callable | None = None
    tls_scanner: Callable | None = None
    api: object | None = None
    cache: object | None = None
    checks: list[CheckSpec] = field(default_factory=lambda: list(CHECKS))


async def run_check(spec: CheckSpec, ctx: AssessmentContext) -> CheckResult:
    """Run one check with a timeout. Checks shouldn't raise; if one does, it becomes a failed run."""
    t0 = time.monotonic()
    try:
        return await asyncio.wait_for(spec.fn(ctx), spec.timeout_s)
    except TimeoutError:
        return make_run(spec.group, CheckStatus.FAILED, spec.source, t0, f"timed out after {spec.timeout_s:g}s"), []
    except Exception as e:  # noqa: BLE001
        return make_run(spec.group, CheckStatus.FAILED, spec.source, t0, f"check error: {type(e).__name__}"), []


def _warm() -> None:
    lookalike.permutation_index()


async def warm_up() -> None:
    """Build the dnstwist permutation set off the event loop (first build ~5 s, then cached on disk)."""
    await asyncio.to_thread(_warm)


async def assess_url(url: str, *, now: datetime | None = None, deps: Deps | None = None,
                     owns_site: bool = False) -> AssessmentReport:
    deps = deps or Deps()
    now = now or utcnow()
    brands = deps.brands or get_index()
    try:
        parsed = parse_url(url)
    except URLParseError as e:
        return _unparseable(url, str(e), now)
    await warm_up()

    ctx = AssessmentContext(url=parsed, brands=brands, now=now, fetcher=deps.fetcher, tls_scanner=deps.tls_scanner,
                            api=deps.api, cache=deps.cache, owns_site=owns_site)
    try:
        results = await asyncio.gather(*(run_check(s, ctx) for s in deps.checks))
    finally:
        for t in (ctx._fetch_task, ctx._tls_task):
            if t is not None and not t.done():
                t.cancel()

    runs: list[CheckRun] = [r for r, _ in results]
    findings: list[Finding] = [f for _, fs in results for f in fs]
    ran = {r.check_group for r in runs}
    for group in cov.WEIGHTS:  # every coverage group gets a run, so gaps always show up in limitations
        if group not in ran:
            runs.append(CheckRun(check_group=group, status=CheckStatus.UNAVAILABLE,
                                 source="local:pipeline", duration_ms=0, weight=cov.weight(group),
                                 detail="not run"))

    # Re-run structural checks on the final URL (that is what "always expand shorteners" is for).
    fr = None
    t = ctx._fetch_task
    if t is not None and t.done() and not t.cancelled() and t.exception() is None:
        fr = t.result()
    final_url = fr.final_url if fr and fr.final_url else None
    if final_url:
        try:
            final = parse_url(final_url)
        except URLParseError:
            final = None
        if final and final.host != parsed.host:
            have = {f.check_id for f in findings}
            for f in url_structure.analyze(final, brands) + lookalike.analyze(final, brands):
                if f.check_id not in have:
                    findings.append(f)
                    have.add(f.check_id)

    findings = _post_process(findings)
    posture = [f for f in findings if f.category == "security_posture"]
    findings = [f for f in findings if f.category != "security_posture"]
    damp = risk.dampen(findings, brands, parsed.host, parsed.path or "/")
    findings = damp.kept

    coverage = cov.compute(runs)
    verdict = risk.classify(findings, coverage.percent)

    certificate = ctx.certificate
    if certificate is not None:
        certificate = certificate.model_copy(update={
            "ocsp_status": ctx.revocation_status if ctx.revocation_status in ("good", "revoked", "unknown")
            else "unchecked",
            "ct_logged_in_crtsh": ctx.ct_logged})

    limitations = list(FIXED_LIMITATIONS)
    for r in runs:
        status = r.status.value if isinstance(r.status, CheckStatus) else r.status
        if status != CheckStatus.COMPLETED.value:
            limitations.append(f"{r.check_group} {status}" + (f": {r.detail}" if r.detail else "."))
    if damp.dropped:
        limitations.append("Suppressed low-trust signals on an allowlisted domain: "
                           + ", ".join(dict.fromkeys(damp.dropped_ids)) + ".")
    if not brands.tranco_loaded:
        limitations.append("Tranco top-10k allowlist not loaded; false-positive dampening limited to brand domains.")
    limitations.append("AI explanation not generated; classification is rule-based.")

    return AssessmentReport(
        created_at=now,
        subject_type=SubjectType.URL,
        subject=url,
        normalized_subject=parsed.url_without_userinfo(),
        classification=verdict.classification,
        classification_reason=verdict.reason,
        score=verdict.score,
        confidence=verdict.confidence,
        coverage=coverage,
        findings=findings,
        security_posture=posture,
        check_runs=runs,
        indicators=_indicators(parsed, fr, certificate, ctx.nameservers),
        redirect_chain=list(fr.hops) if fr else [],
        certificate=certificate,
        ai=None,
        recommended_actions=ACTIONS[RiskClass(verdict.classification)],
        limitations=limitations,
    )


def _post_process(findings: list[Finding]) -> list[Finding]:
    ids = {f.check_id for f in findings}
    out = []
    for f in findings:
        if f.check_id == "TLS.NO_HTTPS" and "PAGE.CREDENTIAL_FORM" in ids:
            f = f.model_copy(update={"severity": "high",
                                     "title": "Login form served without HTTPS"})
        out.append(f)
    return out


def _indicators(parsed, fr, certificate, nameservers=()) -> list[Indicator]:
    out: list[Indicator] = [
        Indicator(type="url", value=parsed.raw, normalized=parsed.url_without_userinfo()),
    ]
    hosts = [parsed.host]
    if fr:
        for h in fr.hops:
            try:
                hosts.append(parse_url(h.url).host)
            except URLParseError:
                continue
    seen: set[tuple[str, str]] = set()
    for h in hosts:
        if parsed.ip is not None and h == parsed.host:
            key = ("ip", h)
        else:
            key = ("domain", registrable_domain(h))
        if key not in seen:
            seen.add(key)
            out.append(Indicator(type=key[0], value=h, normalized=key[1]))
    if fr:
        for h in fr.hops:
            if h.resolved_ip and ("ip", h.resolved_ip) not in seen:
                seen.add(("ip", h.resolved_ip))
                out.append(Indicator(type="ip", value=h.resolved_ip, normalized=h.resolved_ip))
    for ns in nameservers:
        out.append(Indicator(type="nameserver", value=ns, normalized=ns))
    if certificate is not None:
        out.append(Indicator(type="cert_sha256", value=certificate.sha256_fingerprint,
                             normalized=certificate.sha256_fingerprint))
    return out


def _unparseable(url: str, error: str, now: datetime) -> AssessmentReport:
    runs = [CheckRun(check_group=g, status=CheckStatus.FAILED, source="local:pipeline", duration_ms=0,
                     weight=w, detail="input is not a valid URL") for g, w in cov.WEIGHTS.items()]
    coverage = cov.compute(runs)
    return AssessmentReport(
        created_at=now, subject_type=SubjectType.URL, subject=url, normalized_subject=url.strip(),
        classification=RiskClass.INCONCLUSIVE, classification_reason=f"R4: coverage {coverage.percent}% is below 50%",
        score=0, confidence="low", coverage=coverage, check_runs=runs,
        recommended_actions=ACTIONS[RiskClass.INCONCLUSIVE],
        limitations=[f"The input could not be parsed as a URL ({error})."] + FIXED_LIMITATIONS)
