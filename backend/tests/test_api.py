"""API tests: real FastAPI app + SQLite, fake fetcher/TLS scanner, fake chain. Fully offline."""
import io
import json
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
import zxingcpp
from fastapi.testclient import TestClient
from PIL import Image

from app.checks import headers, lookalike, page, redirects, url_structure
from app.checks.intel import gsb, openphish, urlhaus, virustotal
from app.checks.tls_chain import TlsScan
from app.db import Database
from app.main import create_app
from app.pipeline import CheckSpec, Deps
from app.ratelimit import RateLimiter
from app.registry.chain import ChainError
from app.schemas import AssessmentReport, RegistryRecord, RegistryStatus, report_hash
from app.store import hash_bytes
from tests.conftest import fake_fetcher, fetch_result
from tests.conftest import page as page_fixture

PHISH = "https://sbi.co.in.kyc-verify-now.top/login?ref=sms"


class FakeChain:
    def __init__(self):
        self.reports: dict[str, SimpleNamespace] = {}
        self.submits = 0

    async def chain_id(self):
        return 11155111

    async def explorer_url(self, tx=None):
        return f"https://sepolia.etherscan.io/tx/{tx}" if tx else "https://sepolia.etherscan.io/address/0xREG"

    async def find_by_hash(self, h):
        return self.reports.get(h)

    async def get_report(self, onchain_id):
        return next(r for r in self.reports.values() if r.id == onchain_id)

    async def submit_report(self, report, parent_hash=None):
        self.submits += 1
        h = report_hash(report)
        r = SimpleNamespace(id=len(self.reports) + 1, report_hash=h, reporter="0xRELAYER",
                            created_at=datetime(2026, 11, 9, tzinfo=UTC), status=RegistryStatus.SUBMITTED)
        self.reports[h] = r
        return RegistryRecord(report_id=report.report_id, report_hash=h, chain_id=11155111, contract_address="0xREG",
                              onchain_id=r.id, tx_hash="0x" + "ab" * 32, reporter_address=r.reporter)

    async def aclose(self):
        pass


def make_deps(body=b"", urls=(PHISH,)):
    async def scan(host, port):
        return TlsScan(hostname=host, port=port, error="no TLS in tests")
    specs = [CheckSpec("url.structure", url_structure.run, 5, url_structure.SOURCE),
             CheckSpec("url.lookalike", lookalike.run, 5, lookalike.SOURCE),
             CheckSpec("fetch.redirects", redirects.run, 5, redirects.SOURCE),
             CheckSpec("page.content", page.run, 5, page.SOURCE),
             CheckSpec(gsb.GROUP, gsb.run, 5, gsb.SOURCE), CheckSpec(urlhaus.GROUP, urlhaus.run, 5, urlhaus.SOURCE),
             CheckSpec(virustotal.GROUP, virustotal.run, 5, virustotal.SOURCE),
             CheckSpec(openphish.GROUP, openphish.run, 5, openphish.SOURCE),
             CheckSpec(headers.GROUP, headers.run, 5, headers.SOURCE)]
    return Deps(fetcher=fake_fetcher(fetch_result(list(urls), body)), tls_scanner=scan, checks=specs)


@pytest.fixture
def chain():
    return FakeChain()


@pytest.fixture
def client(tmp_path, chain):
    db = Database(f"sqlite+aiosqlite:///{tmp_path / 'test.db'}")
    app = create_app(database=db, deps=make_deps(page_fixture("fake_sbi_login.html")), chain=chain,
                     background_feeds=False, use_env_llm=False)
    with TestClient(app) as c:
        yield c


def assess(client, text=PHISH, **kw):
    r = client.post("/assess", json={"input": text, **kw})
    assert r.status_code == 200, r.text
    return r.json()["report_id"]


def test_assess_then_get_report_is_byte_stable(client):
    rid = assess(client)
    r = client.get(f"/reports/{rid}")
    assert r.status_code == 200 and r.headers["content-type"] == "application/json"
    rep = AssessmentReport.model_validate_json(r.content)
    assert rep.report_id == rid and rep.subject == PHISH and rep.limitations
    assert not any(f.category == "security_posture" for f in rep.findings)
    assert report_hash(rep) == hash_bytes(r.content)  # the stored bytes ARE the canonical form
    groups = {c.check_group for c in rep.check_runs}
    assert {"intel.gsb", "intel.urlhaus", "intel.virustotal", "intel.openphish"} <= groups
    assert "intel.gsb" in rep.coverage.unavailable  # no API key in tests → honest gap, not "safe"


def test_domain_input_is_detected_and_assessed(client):
    rid = assess(client, "kyc-verify-now.top")
    assert client.get(f"/reports/{rid}").json()["subject"] == "kyc-verify-now.top"


def test_message_is_assessed_with_redacted_subject(client):
    text = "Dear Ramesh, URGENT: share your OTP 482913 now or your SBI account will be blocked. Call +91 98765 43210"
    rid = assess(client, text)
    rep = client.get(f"/reports/{rid}").json()
    assert rep["subject_type"] == "message"
    assert "482913" not in rep["subject"] and "98765" not in rep["subject"] and "[OTP]" in rep["subject"]
    ids = {f["check_id"] for f in rep["findings"]}
    assert {"MSG.CREDENTIAL_REQUEST", "MSG.URGENCY"} <= ids
    assert rep["classification"] in ("suspicious", "inconclusive") and rep["classification"] != "high_risk"
    assert any("message.signals" in x for x in rep["limitations"])  # no LLM key → honest gap


def test_email_address_assesses_domain(client):
    rep = client.get(f"/reports/{assess(client, 'help@sbi-kyc-verify.top')}").json()
    assert rep["subject_type"] == "email" and ("email", "help@sbi-kyc-verify.top") in [(i["type"], i["normalized"]) for i in rep["indicators"]]


def test_wrong_subject_type_for_input_is_422(client):
    assert client.post("/assess", json={"input": "not an email", "subject_type": "email"}).status_code == 422


@pytest.mark.parametrize("bad", ["", "ftp://example.org/x", "https://", "http://[::1"])
def test_bad_urls_rejected(client, bad):
    r = client.post("/assess", json={"input": bad, "subject_type": "url"})
    assert r.status_code == 422


def test_unknown_extra_field_rejected(client):
    assert client.post("/assess", json={"input": "example.org", "evil": 1}).status_code == 422


def test_unknown_and_malformed_report_ids(client):
    assert client.get("/reports/00000000-0000-0000-0000-000000000000").status_code == 404
    assert client.get("/reports/not-a-uuid").status_code == 404


def test_rate_limit_per_ip(client):
    client.app.state.cm.assess_limiter = RateLimiter(2, 60)
    assess(client)
    assess(client)
    r = client.post("/assess", json={"input": PHISH})
    assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1
    assert client.get("/health").status_code == 200  # only /assess is limited


def test_rate_limiter_window():
    t = [0.0]
    rl = RateLimiter(2, 60, clock=lambda: t[0])
    assert rl.check("a") is None and rl.check("a") is None
    assert rl.check("a") == 60 and rl.check("b") is None
    t[0] = 61
    assert rl.check("a") is None


# ---------- QR ----------

def qr_png(text):
    z = zxingcpp.write_barcode_to_image(zxingcpp.create_barcode(text, zxingcpp.BarcodeFormat.QRCode), scale=6)
    h, w = z.shape
    buf = io.BytesIO()
    Image.frombytes("L", (w, h), bytes(memoryview(z))).save(buf, "PNG")
    return buf.getvalue()


def post_qr(client, data, name="q.png", ctype="image/png"):
    return client.post("/assess/qr", files={"file": (name, data, ctype)})


def test_qr_link_is_assessed_as_qr_subject(client):
    r = post_qr(client, qr_png(PHISH))
    assert r.status_code == 200, r.text
    rep = client.get(f"/reports/{r.json()['report_id']}").json()
    assert rep["subject_type"] == "qr" and rep["subject"] == PHISH


def test_qr_rejections(client):
    assert post_qr(client, qr_png("WIFI:S:home;T:WPA;P:secret;;")).status_code == 422  # not a link
    assert post_qr(client, qr_png("javascript:alert(1)")).status_code == 422
    blank = io.BytesIO()
    Image.new("RGB", (50, 50), "white").save(blank, "PNG")
    assert "No QR code" in post_qr(client, blank.getvalue()).json()["detail"]
    assert post_qr(client, b"%PDF-1.4 not an image").status_code == 422
    assert post_qr(client, b"x" * (5 * 1024 * 1024 + 10)).status_code == 422


# ---------- registry ----------

def test_register_is_idempotent_and_verifiable(client, chain):
    rid = assess(client)
    assert client.get(f"/reports/{rid}/registration").json() is None
    first = client.post(f"/reports/{rid}/register")
    assert first.status_code == 200 and first.json()["onchain_id"] == 1 and first.json()["status"] == "submitted"
    assert client.post(f"/reports/{rid}/register").json() == first.json() and chain.submits == 1
    assert client.get(f"/reports/{rid}/registration").json()["tx_hash"] == "0x" + "ab" * 32

    v = client.get(f"/reports/{rid}/verify").json()
    assert v["match"] is True and v["onchain_status"] == "submitted"
    assert v["tx_hash"] == first.json()["tx_hash"] and v["explorer_url"].endswith(first.json()["tx_hash"])
    assert v["computed_hash"] == first.json()["report_hash"]


def test_registration_reflects_onchain_status_change(client, chain):
    rid = assess(client)
    client.post(f"/reports/{rid}/register")
    next(iter(chain.reports.values())).status = RegistryStatus.VALIDATED
    assert client.get(f"/reports/{rid}/registration").json()["status"] == "validated"


def test_verify_unregistered_report_is_no_match(client):
    rid = assess(client)
    v = client.get(f"/reports/{rid}/verify").json()
    assert v["match"] is False and v["onchain_hash"] is None and v["onchain_status"] is None


def test_verify_uploaded_file_match_and_tamper(client):
    rid = assess(client)
    client.post(f"/reports/{rid}/register")
    original = client.get(f"/reports/{rid}").json()
    assert client.post("/verify", json=original).json()["match"] is True
    tampered = {**original, "score": original["score"] + 1}
    r = client.post("/verify", json=tampered).json()
    assert r["match"] is False and r["report_id"] == rid
    assert client.post("/verify", content=json.dumps([1]), headers={"content-type": "application/json"}).status_code == 422


def test_registry_unconfigured_is_503(tmp_path, monkeypatch):
    monkeypatch.delenv("SEPOLIA_RPC_URL", raising=False)
    monkeypatch.delenv("REGISTRY_ADDRESS", raising=False)
    app = create_app(database=Database(f"sqlite+aiosqlite:///{tmp_path / 'x.db'}"), deps=make_deps(), background_feeds=False, use_env_llm=False)
    with TestClient(app) as c:
        rid = assess(c)
        r = c.post(f"/reports/{rid}/register")
        assert r.status_code == 503 and "not configured" in r.json()["detail"]
        assert c.get(f"/reports/{rid}/verify").status_code == 503


def test_contract_revert_is_502_without_leaking_detail(client, chain):
    async def boom(report, parent_hash=None):
        raise ChainError("OwnerOnly", "rpc secret detail")
    chain.submit_report = boom
    rid = assess(client)
    r = client.post(f"/reports/{rid}/register")
    assert r.status_code == 502 and "OwnerOnly" in r.json()["detail"] and "secret" not in r.text


# ---------- persistence / clusters ----------

def test_indicators_persisted_and_clusters_endpoint(client):
    assess(client)
    assert client.get("/clusters").json() == []  # one report can't form a cluster


# ---------- UPI QR + correlation through the API ----------

SCAM_SMS = "URGENT: your SBI account is blocked. Share the OTP now and pay Rs 10 to scammer@oksbi to unblock."


def test_upi_qr_with_unknown_payee_is_inconclusive_and_keeps_only_the_payee(client):
    r = post_qr(client, qr_png("upi://pay?pa=Shop.Owner@okhdfc&pn=Some%20Name&am=10&tn=secret%20note"))
    assert r.status_code == 200, r.text
    rep = client.get(f"/reports/{r.json()['report_id']}").json()
    assert rep["subject_type"] == "qr" and rep["subject"] == "upi://pay?pa=shop.owner@okhdfc"
    assert rep["classification"] == "inconclusive" and rep["classification_reason"].startswith("R4: a payment QR")
    assert rep["indicators"] == [{"type": "upi_id", "value": "shop.owner@okhdfc", "normalized": "shop.owner@okhdfc"}]
    assert "Some Name" not in json.dumps(rep) and "secret note" not in json.dumps(rep)
    assert "receive money" in " ".join(rep["recommended_actions"])
    assert rep["ai"] is None


def test_upi_qr_rejects_missing_or_invalid_payee(client):
    assert post_qr(client, qr_png("upi://pay?pn=NoPayee")).status_code == 422
    assert post_qr(client, qr_png("upi://pay?pa=not-a-vpa")).status_code == 422


def test_upi_payee_seen_in_two_suspicious_messages_becomes_suspicious_via_correlation(client):
    for _ in range(2):
        rid = client.post("/assess", json={"input": SCAM_SMS}).json()["report_id"]
        assert client.get(f"/reports/{rid}").json()["classification"] in ("suspicious", "high_risk")
    r = post_qr(client, qr_png("upi://pay?pa=scammer@oksbi&pn=X"))
    rep = client.get(f"/reports/{r.json()['report_id']}").json()
    assert [f["check_id"] for f in rep["findings"]] == ["CORR.PRIOR_REPORTS"]
    assert rep["classification"] == "suspicious" and len(rep["related_report_ids"]) == 2
    assert "scammer@oksbi" not in json.dumps(rep["findings"])
    assert rep["recommended_actions"][0].startswith("Check that the payee")
