"""The demo seed must keep producing the demo story (offline, deterministic)."""
from sqlalchemy import select

from app import store
from app.correlation.clusters import build_clusters
from app.db import Database, ReportRow
from demo.seed import main


async def test_demo_seed_tells_the_demo_story(tmp_path):
    url = f"sqlite+aiosqlite:///{tmp_path / 'demo.db'}"
    await main(url)
    db = Database(url)
    try:
        async with db.session() as s:
            rows = (await s.execute(select(ReportRow))).scalars().all()
            reports = {r.normalized_subject.split("/")[2] if r.subject_type == "url" else "message": store.parse_report(r)
                       for r in rows}
            clusters = build_clusters(await store.indicator_rows(s))
    finally:
        await db.aclose()
    assert {k: str(v.classification) for k, v in reports.items()} == {
        "paypa1-secure-login.xyz": "confirmed_malicious", "paypa1-verify-account.top": "suspicious",
        "esign-verify.in": "confirmed_malicious", "www.sbi.co.in": "low_risk", "message": "confirmed_malicious"}
    assert all(v.coverage.percent >= 60 and any("Demo fixture" in x for x in v.limitations) for v in reports.values())
    ids = lambda r: {f.check_id for f in r.findings}  # noqa: E731
    assert "TLS.DISTRUSTED_CA" in ids(reports["esign-verify.in"])
    assert {"URL.LOOKALIKE.TYPOSQUAT", "PAGE.CREDENTIAL_FORM", "DOMAIN.YOUNG"} <= ids(reports["paypa1-verify-account.top"])
    assert "CORR.SHARED_INFRA" in ids(reports["paypa1-verify-account.top"])
    assert not [f for f in reports["www.sbi.co.in"].findings]
    [cluster] = clusters  # two PayPal clones share a certificate, and the scam SMS links to one of them
    assert len(cluster.report_ids) == 3 and cluster.shared_indicators[0].type == "cert_sha256"
    assert sorted(cluster.member_domains) == ["paypa1-secure-login.xyz", "paypa1-verify-account.top"]
