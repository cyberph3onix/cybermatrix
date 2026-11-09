"""Seed a database with demo reports built from RECORDED data (no live feeds, no DNS, no real scam sites).

    cd backend && DATABASE_URL=postgresql+asyncpg://cybermatrix:cybermatrix@localhost:5432/cybermatrix \
        uv run python -m demo.seed

The reports go through the real pipeline (real checks, real risk engine, real correlation). Only the network is
replaced: page fetches, the TLS handshake, threat-intel answers and RDAP come from fixtures defined below, and each
report says so in its limitations. Scam domains are made-up names that do not exist. The eMudhra case uses the real
public intermediate certificate from tests/fixtures/certs, behind a throwaway leaf; nothing is signed with a real key.

Dev tool: it imports the throwaway PKI from tests/, so run it from backend/ (it is not in the Docker image).
"""
from __future__ import annotations

import asyncio
import os
import sys
import time
from datetime import timedelta
from pathlib import Path

from cryptography import x509

from app import store
from app.checks import headers, lookalike, page, redirects, tls_chain, url_structure
from app.checks.base import make_run
from app.checks.intel import gsb, openphish, urlhaus, virustotal
from app.checks.tls_chain import TlsScan
from app.correlation.checks import apply_correlation
from app.db import Database
from app.fetch.safe_fetch import FetchResult
from app.pipeline import CheckSpec, Deps, assess_url
from app.pipeline_message import assess_message
from app.schemas import AssessmentReport, CheckStatus, RedirectHop, SubjectType, utcnow
from app.urlutil import parse_url
from tests.certgen import make_ca, make_leaf

FIX = Path(__file__).resolve().parent.parent / "tests" / "fixtures"
EMUDHRA_EV = FIX / "certs" / "emudhra" / "em_ev_tls_ca_g3b.pem"
NOTE = ("Demo fixture: page, TLS handshake, threat-intel and registration data are recorded, not live. The domain is "
        "invented and does not exist.")

SAMPLE_ID = "5f0c2a8e-6b1d-4c43-9a0e-2f3b7d9c1a11"  # the id the /verify page suggests ("Try 5f0c2a8e…1a11")
PAYPAL_A = "https://paypa1-secure-login.xyz/signin"
PAYPAL_B = "https://paypa1-verify-account.top/webapps/auth"
EMUDHRA_SITE = "https://esign-verify.in/"
LEGIT = "https://www.sbi.co.in/"
LEGIT_GOV = "https://www.incometax.gov.in/iec/foportal/"
SHORT = "https://bit.ly/3demoAmz"
SHORT_DEST = "https://www.amazon.in/dp/B0DEMO1234"
SMS = ("PayPal alert: your account is limited. Confirm now or it will be closed within 24 hours. Enter your card "
       f"number and the OTP sent to you at {PAYPAL_A}")
# A real-shaped, legitimate bank OTP: urgent wording and a code, but no link and no request to share anything.
LEGIT_SMS = ("123456 is your OTP for a transaction of Rs. 1,250.00 at AMAZON on your HDFC Bank card ending 4321. "
             "Valid for 5 minutes. Do not share this OTP with anyone. - HDFC Bank")


def page_bytes(name: str) -> bytes:
    return (FIX / "pages" / name).read_bytes()


PAGES = {
    "paypa1-secure-login.xyz": page_bytes("fake_paypal_login.html"),
    "paypa1-verify-account.top": page_bytes("fake_paypal_login.html"),
    "esign-verify.in": page_bytes("legit_login.html"),
    "www.sbi.co.in": page_bytes("news_article.html"),
    "www.incometax.gov.in": page_bytes("incometax_login.html"),
    "www.amazon.in": page_bytes("amazon_product.html"),
}
REDIRECTS = {SHORT: SHORT_DEST}  # recorded 301 from the shortener


IPS = {"paypa1-secure-login.xyz": "203.0.113.10", "paypa1-verify-account.top": "203.0.113.10",  # same cheap host
       "esign-verify.in": "198.51.100.20", "www.sbi.co.in": "192.0.2.30", "www.incometax.gov.in": "192.0.2.40",
       "bit.ly": "192.0.2.50", "www.amazon.in": "192.0.2.60"}


async def fetcher(url: str) -> FetchResult:
    hops: list[RedirectHop] = []
    final = url
    while final in REDIRECTS:
        hops.append(RedirectHop(url=final, status_code=301, resolved_ip=IPS[parse_url(final).host]))
        final = REDIRECTS[final]
    host = parse_url(final).host
    hops.append(RedirectHop(url=final, status_code=200, resolved_ip=IPS[host]))
    return FetchResult(requested_url=url, final_url=final, status=200, headers={"content-type": "text/html"},
                       content_type="text/html", body=PAGES[host], hops=hops)


def make_tls(now):
    """host -> TlsScan. The two PayPal clones share one certificate (so they cluster); eMudhra uses the real
    public intermediate behind a throwaway leaf; the legitimate site has an ordinary long-lived certificate."""
    ca, ca_key = make_ca("Demo Test Root")
    shared, _ = make_leaf(ca, ca_key, host="paypa1-secure-login.xyz",
                          san=["paypa1-secure-login.xyz", "paypa1-verify-account.top"],
                          nb=now - timedelta(days=2), na=now + timedelta(days=88))
    legit, _ = make_leaf(ca, ca_key, host="www.sbi.co.in", nb=now - timedelta(days=200), na=now + timedelta(days=165))
    gov, _ = make_leaf(ca, ca_key, host="www.incometax.gov.in", nb=now - timedelta(days=120), na=now + timedelta(days=245))
    amz, _ = make_leaf(ca, ca_key, host="www.amazon.in", nb=now - timedelta(days=60), na=now + timedelta(days=300))
    em_leaf, _ = make_leaf(ca, ca_key, host="esign-verify.in", nb=now - timedelta(days=20), na=now + timedelta(days=70))
    emudhra = x509.load_pem_x509_certificates(EMUDHRA_EV.read_bytes())[0]
    chains = {"paypa1-secure-login.xyz": ([shared, ca], True), "paypa1-verify-account.top": ([shared, ca], True),
              "esign-verify.in": ([em_leaf, emudhra], False), "www.sbi.co.in": ([legit, ca], True),
              "www.incometax.gov.in": ([gov, ca], True), "www.amazon.in": ([amz, ca], True)}

    async def scan(host: str, port: int) -> TlsScan:
        chain, trusted = chains[host]
        return TlsScan(hostname=host, port=port, ip=IPS[host], received_chain=list(chain),
                       store_results={"mozilla": trusted, "apple": trusted, "chrome": trusted},
                       sct_count=2, tls_version="TLSv1.3")
    return scan


def recorded(group: str, source: str, build):
    async def run(ctx):
        t0 = time.monotonic()
        return make_run(group, CheckStatus.COMPLETED, f"recorded:{source}", t0), build(ctx)
    return run


def recorded_rdap(young_days: dict[str, int]):
    from app.checks import domain_rdap

    async def run(ctx):
        t0 = time.monotonic()
        host = ctx.url.host
        days = young_days.get(host, 4000)
        info = {"registered": (ctx.now - timedelta(days=days)).isoformat(), "registrar": "Demo Registrar Ltd"}
        ctx.nameservers = ["ns1.demo-dns.net", "ns2.demo-dns.net"] if days < 30 else []
        return (make_run(domain_rdap.GROUP, CheckStatus.COMPLETED, "recorded:rdap", t0),
                domain_rdap.analyze(domain_rdap.icann_registrable_domain(host), ctx.url.raw, info, ctx.now))
    return run


def gsb_listed(*urls: str):
    def build(ctx):
        hits = [{"url": u, "threat_types": ["SOCIAL_ENGINEERING"]} for u in urls if ctx.url.raw == u]
        return gsb.build(ctx, hits)
    return build


def make_deps(now) -> Deps:
    specs = [
        CheckSpec("url.structure", url_structure.run, 5, url_structure.SOURCE),
        CheckSpec("url.lookalike", lookalike.run, 5, lookalike.SOURCE),
        CheckSpec("fetch.redirects", redirects.run, 5, redirects.SOURCE),
        CheckSpec("page.content", page.run, 5, page.SOURCE),
        CheckSpec("tls.chain", tls_chain.run, 5, tls_chain.SOURCE),
        CheckSpec(gsb.GROUP, recorded(gsb.GROUP, gsb.SOURCE, gsb_listed(PAYPAL_A)), 5, gsb.SOURCE),
        CheckSpec(urlhaus.GROUP, recorded(urlhaus.GROUP, urlhaus.SOURCE, lambda c: []), 5, urlhaus.SOURCE),
        CheckSpec(openphish.GROUP, recorded(openphish.GROUP, openphish.SOURCE, lambda c: []), 5, openphish.SOURCE),
        CheckSpec(virustotal.GROUP, recorded(virustotal.GROUP, virustotal.SOURCE, lambda c: []), 5, virustotal.SOURCE),
        CheckSpec("domain.rdap", recorded_rdap({"paypa1-secure-login.xyz": 3, "paypa1-verify-account.top": 2}), 5, "rdap"),
        CheckSpec(headers.GROUP, headers.run, 5, headers.SOURCE),
    ]
    return Deps(fetcher=fetcher, tls_scanner=make_tls(now), checks=specs)


def with_note(r: AssessmentReport) -> AssessmentReport:
    return r.model_copy(update={"limitations": r.limitations + [NOTE]})


async def main(database_url: str) -> None:
    now = utcnow()
    deps = make_deps(now)
    db = Database(database_url)
    await db.create_all()
    rows: list[AssessmentReport] = []
    try:
        for url in (PAYPAL_A, PAYPAL_B, EMUDHRA_SITE, LEGIT, LEGIT_GOV, SHORT):
            rows.append(await assess_url(url, deps=deps, now=now))
        rows.append(await assess_message(LEGIT_SMS, deps=deps, llm=None))
        # the message goes last so its link correlates with the stored PayPal clones
        rows.append(await assess_message(SMS, deps=deps, llm=None))
        for i, r in enumerate(rows):
            async with db.session() as s:
                if i == 0 and await store.get_report_row(s, SAMPLE_ID) is None:
                    r = r.model_copy(update={"report_id": SAMPLE_ID})  # fixed id; skipped when re-seeding
                r = with_note(await apply_correlation(s, r))
                await store.save_report(s, r)
            kind = "message" if r.subject_type == SubjectType.MESSAGE else "url"
            print(f"{r.report_id}  {kind:7} {str(r.classification):20} cov {r.coverage.percent:3}%  "
                  f"{r.classification_reason[:70]}")
    finally:
        await db.aclose()


if __name__ == "__main__":
    url = os.environ.get("DATABASE_URL")
    if not url:
        sys.exit("Set DATABASE_URL (see the docstring).")
    asyncio.run(main(url))
