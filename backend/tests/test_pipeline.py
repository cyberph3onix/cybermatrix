import asyncio
import json
from datetime import timedelta

import httpx
import pytest
import respx

from app import pipeline
from app.checks import tls_ct
from app.checks.tls_chain import TlsScan, cert_sha256, spki_sha256
from app.engine import coverage as cov
from app.fetch.api_client import ApiClient
from app.fetch.safe_fetch import FetchResult
from app.pipeline import CheckSpec, Deps, assess_url
from app.schemas import AssessmentReport, canonical_bytes, report_hash
from tests.certgen import NOW, make_ca, make_leaf
from tests.conftest import fake_fetcher, fetch_result, page

PHISH = "https://sbi.co.in.kyc-verify-now.top/login?ref=sms"


@pytest.fixture(scope="module")
def pki():
    return make_ca("Test Issuing CA")


def scanner_for(leaf, ca, sct=2, error=None):
    async def scan(host, port):
        if error:
            return TlsScan(hostname=host, port=port, error=error)
        return TlsScan(hostname=host, port=port, ip="203.0.113.7", received_chain=[leaf, ca],
                       store_results={"mozilla": True}, sct_count=sct, tls_version="TLSv1.3")
    return scan


def ct_mock(leaf):
    respx.get(tls_ct.CERTSPOTTER).mock(return_value=httpx.Response(200, json=[{
        "cert_sha256": cert_sha256(leaf).lower(), "pubkey_sha256": spki_sha256(leaf).lower(),
        "issuer": {"name": "O=Test, CN=Test Issuing CA"},
        "not_before": leaf.not_valid_before_utc.isoformat()}]))


def deps(fetch, scanner, **kw):
    return Deps(fetcher=fake_fetcher(fetch), tls_scanner=scanner, api=ApiClient(timeout=6), **kw)


def assert_contract(rep: AssessmentReport):
    assert rep.limitations
    groups = {r.check_group for r in rep.check_runs}
    assert set(cov.WEIGHTS) <= groups
    assert all(f.evidence and all(e.source for e in f.evidence) for f in rep.findings)
    raw = canonical_bytes(rep)
    assert b"." not in json.dumps([r.weight for r in rep.check_runs]).encode()
    _no_floats(json.loads(raw))
    assert report_hash(rep).startswith("0x") and len(report_hash(rep)) == 66
    AssessmentReport.model_validate_json(rep.model_dump_json())
    text = " ".join([rep.classification, rep.classification_reason, *rep.recommended_actions]).lower()
    assert " safe " not in f" {text} " and rep.classification != "safe"


def _no_floats(o):
    if isinstance(o, float):
        raise AssertionError(f"float in report: {o}")
    if isinstance(o, dict):
        for v in o.values():
            _no_floats(v)
    if isinstance(o, list):
        for v in o:
            _no_floats(v)


@respx.mock
async def test_phishing_page_r1b(pki):
    ca, key = pki
    leaf, _ = make_leaf(ca, key, host="sbi.co.in.kyc-verify-now.top", nb=NOW - timedelta(days=2))
    ct_mock(leaf)
    fr = fetch_result(["https://bit.ly/3xYz", PHISH], page("fake_sbi_login.html"))
    rep = await assess_url(PHISH, now=NOW, deps=deps(fr, scanner_for(leaf, ca)))
    assert_contract(rep)
    assert rep.classification == "confirmed_malicious"
    assert rep.classification_reason == "R1b: URL.BRAND_IN_SUBDOMAIN + PAGE.CREDENTIAL_FORM + TLS.CERT_VERY_NEW"
    assert rep.certificate is not None and rep.certificate.ct_logged_in_crtsh is True
    assert rep.coverage.percent == 50 and rep.confidence == "medium"
    assert "intel.gsb" in rep.coverage.unavailable
    assert any("intel.gsb unavailable: GSB_API_KEY is not set" in x for x in rep.limitations)
    assert {i.type for i in rep.indicators} >= {"url", "domain", "ip", "cert_sha256"}
    assert len(rep.redirect_chain) == 2


@respx.mock
async def test_legit_site_low_risk(pki):
    ca, key = pki
    leaf, _ = make_leaf(ca, key, host="shop.example.com")
    ct_mock(leaf)
    fr = fetch_result(["https://shop.example.com/login"], page("legit_login.html"))
    rep = await assess_url("https://shop.example.com/login", now=NOW, deps=deps(fr, scanner_for(leaf, ca)))
    assert_contract(rep)
    assert rep.classification == "low_risk" and rep.classification_reason.startswith("R5: No significant")
    assert rep.findings == [] or all(f.severity in ("low", "info") for f in rep.findings)


@respx.mock
async def test_shortener_to_amazon_is_dampened(pki):
    ca, key = pki
    leaf, _ = make_leaf(ca, key, host="www.amazon.in")
    ct_mock(leaf)
    fr = fetch_result(["https://bit.ly/abc", "https://www.amazon.in/dp/B0"], b"<html><title>Amazon.in</title></html>")
    rep = await assess_url("https://bit.ly/abc", now=NOW, deps=deps(fr, scanner_for(leaf, ca)))
    ids = {f.check_id for f in rep.findings}
    assert "REDIRECT.CROSS_DOMAIN" not in ids
    assert rep.classification == "low_risk"
    assert any("REDIRECT.CROSS_DOMAIN" in x for x in rep.limitations)


@respx.mock
async def test_final_url_structure_rechecked(pki):
    ca, key = pki
    leaf, _ = make_leaf(ca, key, host="hdfcbank-verify.com")
    ct_mock(leaf)
    fr = fetch_result(["https://bit.ly/abc", "https://hdfcbank-verify.com/"], b"<html></html>")
    rep = await assess_url("https://bit.ly/abc", now=NOW, deps=deps(fr, scanner_for(leaf, ca)))
    ids = {f.check_id for f in rep.findings}
    assert {"URL.LOOKALIKE.TYPOSQUAT", "REDIRECT.CROSS_DOMAIN", "URL.SHORTENER"} <= ids
    assert rep.classification == "suspicious"


@respx.mock
async def test_no_https_raised_with_credential_form(pki):
    fr = fetch_result(["http://sbi-kyc.example.top/login"], page("fake_sbi_login.html"))
    respx.get(tls_ct.CERTSPOTTER).mock(return_value=httpx.Response(200, json=[]))
    rep = await assess_url("http://sbi-kyc.example.top/login", now=NOW,
                           deps=deps(fr, scanner_for(None, None, error="unused")))
    nh = next(f for f in rep.findings if f.check_id == "TLS.NO_HTTPS")
    assert nh.severity == "high"
    assert "tls.chain" in rep.coverage.skipped
    assert rep.classification == "high_risk"


async def test_everything_unavailable_is_inconclusive():
    fr = FetchResult(requested_url="https://unknown-site.example.org/", error="timeout")

    async def ct_down(*a, **k):
        raise AssertionError
    rep = await assess_url("https://unknown-site.example.org/", now=NOW,
                           deps=deps(fr, scanner_for(None, None, error="TLS connection failed")))
    assert_contract(rep)
    assert rep.classification == "inconclusive" and rep.confidence == "low"
    assert rep.coverage.percent < 50


async def test_hanging_check_becomes_failed_run():
    async def hang(ctx):
        await asyncio.sleep(10)

    async def boom(ctx):
        raise RuntimeError("bad")
    specs = [CheckSpec("url.structure", hang, 0.05, "t"), CheckSpec("url.lookalike", boom, 1, "t")]
    rep = await assess_url("https://example.com/", now=NOW, deps=Deps(checks=specs))
    runs = {r.check_group: r for r in rep.check_runs}
    assert runs["url.structure"].status == "failed" and "timed out" in runs["url.structure"].detail
    assert runs["url.lookalike"].status == "failed" and "RuntimeError" in runs["url.lookalike"].detail
    assert any("url.structure failed: timed out" in x for x in rep.limitations)
    assert_contract(rep)


async def test_missing_scheme_and_unparseable():
    rep = await assess_url("http://[::1", now=NOW, deps=Deps(checks=[]))
    assert rep.classification == "inconclusive" and rep.limitations
    rep = await assess_url("example.com", now=NOW, deps=Deps(checks=pipeline.CHECKS[:2]))
    assert rep.normalized_subject == "https://example.com/"


async def test_ssrf_target_never_fetched(monkeypatch):
    async def must_not_send(*a, **k):
        raise AssertionError("network send attempted")
    monkeypatch.setattr("app.fetch.safe_fetch._send_hop", must_not_send)
    monkeypatch.setattr("app.checks.tls_chain._sslyze_scan", lambda s: (_ for _ in ()).throw(AssertionError()))
    rep = await assess_url("http://169.254.169.254/latest/meta-data/", now=NOW, deps=Deps(api=ApiClient()))
    assert {f.check_id for f in rep.findings} >= {"URL.IP_HOST"}
    runs = {r.check_group: r for r in rep.check_runs}
    assert "blocked" in (runs["fetch.redirects"].detail or "")
