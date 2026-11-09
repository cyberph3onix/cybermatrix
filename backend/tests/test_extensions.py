"""Optional extensions: real-time quick check, threat-intel feed, screenshot impersonation, organisation dashboard."""
import asyncio
import io

import pytest
from fastapi.testclient import TestClient
from PIL import Image
from sqlalchemy import func, select

from app import watch
from app.ai.llm import LlmUnavailable
from app.brands import get_index
from app.db import Database, RegistryRow, ReportRow
from app.engine import risk
from app.main import create_app
from app.schemas import (
    AssessmentReport,
    CheckRun,
    Coverage,
    Indicator,
    RegistryRecord,
    utcnow,
)
from app.screenshot import VisualClaim, decide
from app.store import save_registry, save_report
from tests.conftest import page as page_fixture
from tests.test_api import PHISH, FakeChain, assess, make_deps


class VisionLlm:
    """Answers only the screenshot tool; every other LLM call is unavailable (so it can't affect other checks)."""
    model = "fake-vision"

    def __init__(self, out=None):
        self.out = out or {"claimed_brand": "PayPal", "seeks_credentials": True}
        self.images = []

    async def call_tool(self, *, system, user, tool_name, schema, max_tokens=700, image=None):
        if tool_name != "report_screenshot_claim":
            raise LlmUnavailable("not in this test")
        self.images.append(image)
        return self.out


def _app(tmp_path, *, llm=None, fetcher_guard=False):
    deps = make_deps(page_fixture("fake_sbi_login.html"))
    if fetcher_guard:
        async def no_fetch(url):
            raise AssertionError("the quick check must not fetch the page")
        deps.fetcher = no_fetch
    return create_app(database=Database(f"sqlite+aiosqlite:///{tmp_path / 'x.db'}"), deps=deps, chain=FakeChain(),
                      background_feeds=False, use_env_llm=False, llm=llm)


@pytest.fixture
def client(tmp_path):
    with TestClient(_app(tmp_path)) as c:
        yield c


def _count_reports(c) -> int:
    async def go():
        async with c.app.state.cm.db.session() as s:
            return int((await s.execute(select(func.count()).select_from(ReportRow))).scalar_one())
    return asyncio.run(go())


def _store(c, report):
    async def go():
        async with c.app.state.cm.db.session() as s:
            await save_report(s, report)
    asyncio.run(go())


def _report(subject: str, cls: str, indicators: list[Indicator]) -> AssessmentReport:
    return AssessmentReport(subject_type="url", subject=subject, normalized_subject=subject, classification=cls,
                            classification_reason="R2: test", score=60, confidence="medium",
                            coverage=Coverage(percent=90), indicators=indicators, limitations=["test"])


# ---------- real-time protection ----------

def test_quick_check_never_fetches_never_stores_and_flags_brand_in_subdomain(tmp_path):
    with TestClient(_app(tmp_path, fetcher_guard=True)) as c:
        before = _count_reports(c)
        r = c.post("/quick-check", json={"url": PHISH})
        assert r.status_code == 200, r.text
        q = r.json()
        assert q["classification"] in ("suspicious", "high_risk", "confirmed_malicious")
        assert "URL.BRAND_IN_SUBDOMAIN" in {f["check_id"] for f in q["findings"]}
        assert q["coverage_percent"] < 50 and "not fetched" in q["note"]
        assert _count_reports(c) == before  # browsing history is never stored


def test_quick_check_with_no_findings_is_inconclusive_never_low_risk(tmp_path):
    with TestClient(_app(tmp_path, fetcher_guard=True)) as c:
        q = c.post("/quick-check", json={"url": "https://quiet-example-shop.org/"}).json()
        assert q["classification"] == "inconclusive" and q["findings"] == []
        assert c.post("/quick-check", json={"url": "ftp://x.org/"}).status_code == 422
        assert c.post("/quick-check", json={"url": "javascript:alert(1)"}).status_code == 422


def test_quick_check_sees_earlier_reports_on_this_server(tmp_path):
    with TestClient(_app(tmp_path, fetcher_guard=True)) as c:
        for i in range(2):
            _store(c, _report(f"https://quiet-bad-host.org/p{i}", "high_risk",
                              [Indicator(type="url", value=f"https://quiet-bad-host.org/p{i}",
                                         normalized=f"https://quiet-bad-host.org/p{i}"),
                               Indicator(type="domain", value="quiet-bad-host.org", normalized="quiet-bad-host.org")]))
        q = c.post("/quick-check", json={"url": "https://quiet-bad-host.org/new"}).json()
        assert any(f["check_id"].startswith("CORR.") for f in q["findings"]), q
        assert q["classification"] != "inconclusive"


# ---------- threat-intel feed ----------

def test_feed_lists_submitted_links_without_query_and_stable_stix_ids(client):
    assess(client)  # PHISH: sbi.co.in.kyc-verify-now.top/login?ref=sms
    stix = client.get("/feeds/stix", params={"level": "suspicious"})
    assert stix.status_code == 200 and stix.headers["content-type"].startswith("application/stix+json")
    b = stix.json()
    assert b["type"] == "bundle" and b["objects"][0]["type"] == "identity"
    inds = [o for o in b["objects"] if o["type"] == "indicator"]
    patterns = {o["pattern"] for o in inds}
    assert "[url:value = 'https://sbi.co.in.kyc-verify-now.top/login']" in patterns  # ?ref=sms dropped
    assert "[domain-name:value = 'kyc-verify-now.top']" in patterns
    assert all(o["spec_version"] == "2.1" and o["pattern_type"] == "stix" and o["valid_from"] for o in inds)
    again = {o["id"] for o in client.get("/feeds/stix", params={"level": "suspicious"}).json()["objects"]}
    assert {o["id"] for o in inds} <= again  # consumers de-duplicate on the id
    txt = client.get("/feeds/blocklist.txt", params={"level": "suspicious"}).text
    assert "kyc-verify-now.top\n" in txt and "ref=sms" not in txt
    assert client.get("/feeds/stix", params={"level": "bogus"}).status_code == 422


def test_feed_never_lists_allowlisted_sites_redirect_hops_or_rejected_reports(client):
    _store(client, _report("https://accounts.google.com/x?email=a@b.com", "high_risk",
                           [Indicator(type="url", value="https://accounts.google.com/x?email=a@b.com",
                                      normalized="https://accounts.google.com/x?email=a@b.com")]))
    _store(client, _report("https://evil-redirector.top/a", "confirmed_malicious",
                           [Indicator(type="url", value="https://evil-redirector.top/a",
                                      normalized="https://evil-redirector.top/a"),
                            Indicator(type="domain", value="victim-shop.org", normalized="victim-shop.org")]))
    rejected = _report("https://was-wrong.top/", "high_risk",
                       [Indicator(type="url", value="https://was-wrong.top/", normalized="https://was-wrong.top/")])
    _store(client, rejected)

    async def reject():
        async with client.app.state.cm.db.session() as s:
            await save_registry(s, RegistryRecord(report_id=rejected.report_id, report_hash="0x" + "11" * 32,
                                                  chain_id=1, contract_address="0x" + "22" * 20, onchain_id=9,
                                                  status="rejected"))
    asyncio.run(reject())
    txt = client.get("/feeds/blocklist.txt").text
    assert "evil-redirector.top" in txt
    for absent in ("google.com", "a@b.com", "victim-shop.org", "was-wrong.top"):
        assert absent not in txt


# ---------- screenshot impersonation ----------

def _jpeg_with_exif() -> bytes:
    img = Image.new("RGB", (2400, 1600), (240, 240, 240))
    exif = Image.Exif()
    exif[0x010F] = "SecretCameraMaker"
    out = io.BytesIO()
    img.save(out, format="JPEG", exif=exif.tobytes())
    return out.getvalue()


def test_screenshot_brand_mismatch_is_heuristic_and_image_is_reencoded(tmp_path):
    llm = VisionLlm()
    with TestClient(_app(tmp_path, llm=llm)) as c:
        before = _count_reports(c)
        r = c.post("/assess/screenshot", data={"url": PHISH, "consent": "true"},
                   files={"file": ("s.jpg", _jpeg_with_exif(), "image/jpeg")})
        assert r.status_code == 200, r.text
        rep = AssessmentReport.model_validate_json(c.get(f"/reports/{r.json()['report_id']}").content)
        f = next(f for f in rep.findings if f.check_id == "PAGE.SCREENSHOT_BRAND_MISMATCH")
        assert (f.severity, f.strength) == ("high", "heuristic")
        assert f.evidence[0].data["page_domain"] == "kyc-verify-now.top" and "paypal.com" in f.evidence[0].data["official_domains"]
        run = next(x for x in rep.check_runs if x.check_group == "page.screenshot")
        assert run.status == "completed" and run.weight == 0
        assert any("not stored" in x for x in rep.limitations)
        assert _count_reports(c) == before + 1
        img, mime = llm.images[0]
        assert mime == "image/jpeg" and b"SecretCameraMaker" not in img and b"Exif" not in img
        assert max(Image.open(io.BytesIO(img)).size) <= 1280


def test_screenshot_requires_consent_an_llm_and_an_image(tmp_path):
    with TestClient(_app(tmp_path, llm=VisionLlm())) as c:
        files = {"file": ("s.jpg", _jpeg_with_exif(), "image/jpeg")}
        assert c.post("/assess/screenshot", data={"url": PHISH}, files=files).status_code == 422
        bad = c.post("/assess/screenshot", data={"url": PHISH, "consent": "true"},
                     files={"file": ("s.txt", b"not an image", "text/plain")})
        assert bad.status_code == 422
    (tmp_path / "n").mkdir()
    with TestClient(_app(tmp_path / "n")) as c:
        r = c.post("/assess/screenshot", data={"url": PHISH, "consent": "true"},
                   files={"file": ("s.jpg", _jpeg_with_exif(), "image/jpeg")})
        assert r.status_code == 503


def test_screenshot_decision_rules():
    idx = get_index()
    paypal = VisualClaim(claimed_brand="PayPal", seeks_credentials=True)
    assert decide(paypal, "https://www.paypal.com/signin", idx, model="m") == []  # the brand's own site
    assert decide(paypal, "https://accounts.google.com/", idx, model="m") == []  # allowlisted host
    f = decide(paypal, "https://paypal-help-desk.top/", idx, model="m")
    assert f and f[0].severity == "high"
    shown_only = decide(VisualClaim(claimed_brand="PayPal"), "https://paypal-help-desk.top/", idx, model="m")
    assert shown_only and shown_only[0].severity == "medium"
    unknown = VisualClaim(claimed_brand="Zorblax Credit Union")
    assert decide(unknown, "https://zz-portal.top/", idx, model="m") == []  # unknown name, asks for nothing
    asks = unknown.model_copy(update={"seeks_credentials": True})
    assert decide(asks, "https://zz-portal.top/", idx, model="m")
    assert decide(asks, "https://zorblax-online.top/", idx, model="m") == []  # name is in the domain
    # an AI reading alone never makes a link high_risk
    v = risk.classify(f, 90)
    assert v.classification == "suspicious"


# ---------- organisation dashboard ----------

@pytest.fixture
def org_client(tmp_path, monkeypatch):
    async def fake_issuances(api, domain):
        return [{"id": "1", "cert_sha256": "A" * 64, "dns_names": [domain], "issuer": "Let's Encrypt", "not_before": None}]
    monkeypatch.setattr(watch, "issuances", fake_issuances)
    with TestClient(_app(tmp_path)) as c:
        yield c


def test_org_create_dedupes_domains_and_starts_ct_watches(org_client):
    r = org_client.post("/orgs", json={"name": "Example Bank",
                                       "domains": ["https://www.mybank-example.com/x", "mybank-example.com", "paypal.com"]})
    assert r.status_code == 200, r.text
    d = r.json()
    assert [x["domain"] for x in d["domains"]] == ["mybank-example.com", "paypal.com"]
    assert all(x["watch_id"] and x["ct_alerts"] == 0 and x["latest"] is None for x in d["domains"])
    assert org_client.get(f"/orgs/{d['org_id']}").json()["name"] == "Example Bank"
    assert org_client.get("/orgs/nothex").status_code == 404
    assert org_client.post("/orgs", json={"name": "x", "domains": ["10.0.0.1"]}).status_code == 422
    assert org_client.post("/orgs", json={"name": "x", "domains": [f"d{i}.com" for i in range(21)]}).status_code == 422


def test_org_scan_fills_posture_and_is_throttled(org_client):
    oid = org_client.post("/orgs", json={"name": "Shop", "domains": ["mybank-example.com"]}).json()["org_id"]
    r = org_client.post(f"/orgs/{oid}/scan")
    assert r.status_code == 200, r.text
    latest = r.json()["domains"][0]["latest"]
    assert latest and latest["classification"] and 0 <= latest["coverage_percent"] <= 100
    assert set(latest["posture"]) == {"high", "medium", "low"}
    again = org_client.post(f"/orgs/{oid}/scan")
    assert again.status_code == 429 and "Retry-After" in again.headers


def test_org_shows_impersonation_of_its_brand_but_not_its_own_sites(org_client):
    oid = org_client.post("/orgs", json={"name": "PayPal", "domains": ["paypal.com"]}).json()["org_id"]
    rid = assess(org_client, "https://paypa1.com/signin")  # lookalike of paypal.com
    imp = org_client.get(f"/orgs/{oid}").json()["domains"][0]["impersonation"]
    assert imp["reports"] >= 1 and rid in imp["report_ids"] and "paypa1.com" in imp["lookalike_domains"]
    assess(org_client, "https://www.paypal.com/")  # the org's own site never counts as impersonation
    imp2 = org_client.get(f"/orgs/{oid}").json()["domains"][0]["impersonation"]
    assert "paypal.com" not in imp2["lookalike_domains"]


def test_unused_imports_are_real():  # keep CheckRun/RegistryRow/utcnow referenced for type checkers
    assert CheckRun and RegistryRow and utcnow
