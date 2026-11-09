"""Compliance audit, Module 4: the brief's campaign scenario end to end (M4-5), per-edge reasons in /clusters (M4-4),
brand + technique trends (M4-3) and similar-message detection on redacted text (M4-2). Offline."""
import pytest
from fastapi.testclient import TestClient

from app.checks import redirects, url_structure
from app.db import Database
from app.main import create_app
from app.pipeline import CheckSpec, Deps
from tests.conftest import fetch_result
from tests.test_api import FakeChain

FINAL = "https://sbi-secure-pay.top/collect"  # the shared destination of three different links
LINKS = ["https://bit.ly/sbi-kyc-1", "https://tinyurl.com/sbi-kyc-2", "https://sbi-alerts.in/r/3"]
MESSAGES = [
    f"URGENT: your SBI account will be blocked today. Update your KYC at {LINKS[0]}",
    f"Dear SBI customer, your YONO access expires tonight. Verify immediately: {LINKS[1]}",
    f"SBI alert: account frozen. Complete your KYC within 24 hours at {LINKS[2]}",
]


async def _fetch(url: str):
    return fetch_result([url, FINAL], b"<html><title>Pay</title></html>")


@pytest.fixture
def client(tmp_path):
    deps = Deps(fetcher=_fetch, checks=[CheckSpec("url.structure", url_structure.run, 5, url_structure.SOURCE),
                                        CheckSpec("fetch.redirects", redirects.run, 5, redirects.SOURCE)])
    app = create_app(database=Database(f"sqlite+aiosqlite:///{tmp_path / 't.db'}"), deps=deps, chain=FakeChain(),
                     background_feeds=False, use_env_llm=False)
    with TestClient(app) as c:
        yield c


def _assess(client, text):
    r = client.post("/assess", json={"input": text})
    assert r.status_code == 200, r.text
    return r.json()["report_id"]


def test_three_bank_messages_different_links_same_destination_form_one_cluster(client):
    rids = [_assess(client, m) for m in MESSAGES]
    for rid in rids:
        rep = client.get(f"/reports/{rid}").json()
        assert rep["classification"] in ("suspicious", "high_risk", "confirmed_malicious"), rep["classification_reason"]
        assert {"type": "domain", "value": "sbi-secure-pay.top", "normalized": "sbi-secure-pay.top"} in rep["indicators"]
    clusters = client.get("/clusters").json()
    [c] = [c for c in clusters if set(rids) <= set(c["report_ids"])]
    assert set(c["report_ids"]) == set(rids)
    assert ("domain", "sbi-secure-pay.top", 3) in {(i["type"], i["value"], i["report_count"]) for i in c["shared_indicators"]}
    # M4-4/M4-5: every member is reached by an edge that names the shared indicator
    reached = {e["from_report"] for e in c["edges"]} | {e["to_report"] for e in c["edges"]}
    assert reached == set(rids)
    assert all(e["reason"].startswith("both contain ") and e["value"] in e["reason"] for e in c["edges"])
    # the AI summary is optional decoration; the cluster exists without it
    assert c["summary"] is None


def test_three_messages_same_upi_payee_form_one_cluster(client):
    texts = ["URGENT: SBI account blocked. Pay Rs 10 to verify-sbi@ybl to unblock today.",
             "SBI KYC pending: send Rs 1 to verify-sbi@ybl immediately or your account will be frozen.",
             "Dear SBI customer, refund of Rs 4,999 approved. Approve the collect request from verify-sbi@ybl now."]
    rids = [_assess(client, t) for t in texts]
    [c] = [c for c in client.get("/clusters").json() if set(rids) <= set(c["report_ids"])]
    assert any(i["type"] == "upi_id" and i["value"] == "verify-sbi@ybl" for i in c["shared_indicators"])
    # no raw message text from other users in the shared view (SEC-9)
    body = str(c)
    assert "refund of Rs" not in body and "account blocked" not in body


def test_trends_group_by_brand_and_technique(client):
    for m in MESSAGES:
        _assess(client, m)
    [sbi] = [t for t in client.get("/trends/impersonation").json() if t["brand_id"] == "sbi"]
    assert sbi["reports"] >= 3 and sbi["messages"] >= 3
    techniques = {t["technique"]: t["reports"] for t in sbi["techniques"]}
    assert techniques.get("credential_request") == 2  # "update/complete your KYC" in messages 1 and 3 only
    assert techniques.get("lookalike_domain", 0) >= 1 and list(techniques.values()) == sorted(techniques.values(), reverse=True)


def test_hop_domain_still_never_counts_as_submitted(client):
    """Merging a link's redirect-hop domains into message indicators must not let a destination inherit
    CORR.PRIOR_REPORTS (the victim-framing guard in correlation/checks.py)."""
    for m in MESSAGES:
        _assess(client, m)
    rep = client.get(f"/reports/{_assess(client, 'sbi-secure-pay.top')}").json()
    assert "CORR.PRIOR_REPORTS" not in [f["check_id"] for f in rep["findings"]]


def test_a_cluster_can_be_registered_as_a_campaign_and_verified(client):
    import rfc8785
    from eth_hash.auto import keccak
    rids = [_assess(client, m) for m in MESSAGES]
    [c] = [c for c in client.get("/clusters").json() if set(rids) <= set(c["report_ids"])]
    r = client.post(f"/clusters/{c['cluster_id']}/register")
    assert r.status_code == 200, r.text
    rec = r.json()
    assert rec["onchain_id"] and rec["tx_hash"]
    raw = client.get(f"/campaigns/{rec['campaign_id']}").content
    manifest = __import__("json").loads(raw)
    # the committed hash is keccak256(JCS(manifest)), the same rule verify.py applies to any file
    assert "0x" + keccak(rfc8785.dumps(manifest)).hex() == rec["manifest_hash"]
    member_hashes = sorted(client.get(f"/reports/{x}/evidence").json()["report_hash"] for x in rids)
    assert manifest["report_hashes"] == member_hashes and manifest["edges"]
    # the manifest holds report hashes and shared indicators, never message text
    assert "URGENT" not in raw.decode() and "YONO" not in raw.decode()
    # idempotent, and /verify accepts the uploaded manifest
    assert client.post(f"/clusters/{c['cluster_id']}/register").json()["campaign_id"] == rec["campaign_id"]
    v = client.post("/verify", json=manifest).json()
    assert v["match"] and v["computed_hash"] == rec["manifest_hash"]
    manifest["label"] += "!"
    assert client.post("/verify", json=manifest).json()["match"] is False
    assert client.get("/campaigns/not-a-uuid").status_code == 404
    assert client.post("/clusters/c-doesnotexist/register").status_code == 404
