"""The demo seed must keep producing the demo story (offline, deterministic)."""
from sqlalchemy import select

from app import store
from app.correlation.clusters import build_clusters
from app.db import Database, ReportRow
from demo.seed import SAMPLE_ID, main


async def test_demo_seed_tells_the_demo_story(tmp_path):
    url = f"sqlite+aiosqlite:///{tmp_path / 'demo.db'}"
    await main(url)
    db = Database(url)
    try:
        async with db.session() as s:
            rows = (await s.execute(select(ReportRow))).scalars().all()
            parsed = [store.parse_report(r) for r in rows]
            reports = {r.normalized_subject.split("/")[2] if r.subject_type == "url" else
                       ("legit_message" if "HDFC" in p.subject else "message"): p for r, p in zip(rows, parsed, strict=True)}
            clusters = build_clusters(await store.indicator_rows(s))
            sample = await store.get_report_row(s, SAMPLE_ID)
    finally:
        await db.aclose()
    assert sample is not None and "paypa1-secure-login.xyz" in sample.normalized_subject  # the /verify page's "Try" hint
    assert {k: str(v.classification) for k, v in reports.items()} == {
        "paypa1-secure-login.xyz": "confirmed_malicious", "paypa1-verify-account.top": "suspicious",
        "esign-verify.in": "confirmed_malicious", "www.sbi.co.in": "low_risk", "www.incometax.gov.in": "low_risk",
        "bit.ly": "low_risk", "message": "confirmed_malicious",
        # a genuine bank OTP is never flagged: without the LLM its coverage is 40%, so it is honestly inconclusive
        "legit_message": "inconclusive"}
    assert all(any("Demo fixture" in x for x in v.limitations) for v in reports.values())
    assert all(v.coverage.percent >= 60 for k, v in reports.items() if k != "legit_message")
    assert not {"MSG.CREDENTIAL_REQUEST", "MSG.PAYMENT_REQUEST"} & {f.check_id for f in reports["legit_message"].findings}
    assert "www.amazon.in" in reports["bit.ly"].redirect_chain[-1].url  # the shortener is expanded, not trusted
    ids = lambda r: {f.check_id for f in r.findings}  # noqa: E731
    assert "TLS.DISTRUSTED_CA" in ids(reports["esign-verify.in"])
    assert {"URL.LOOKALIKE.TYPOSQUAT", "PAGE.CREDENTIAL_FORM", "DOMAIN.YOUNG"} <= ids(reports["paypa1-verify-account.top"])
    assert "CORR.SHARED_INFRA" in ids(reports["paypa1-verify-account.top"])
    assert not [f for f in reports["www.sbi.co.in"].findings]
    [cluster] = clusters  # two PayPal clones share a certificate, and the scam SMS links to one of them
    assert len(cluster.report_ids) == 3 and cluster.shared_indicators[0].type == "cert_sha256"
    assert sorted(cluster.member_domains) == ["paypa1-secure-login.xyz", "paypa1-verify-account.top"]
