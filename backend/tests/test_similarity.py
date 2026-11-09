"""Message similarity (CORR.SIMILAR_MESSAGE, message_family clusters) and impersonation trends."""
import pytest

from app import store
from app.brands import get_index
from app.correlation import similarity
from app.correlation.checks import apply_correlation
from app.correlation.clusters import build_clusters, impersonation_trends
from app.db import Database
from app.pipeline_message import assess_message

A = ("Dear customer your SBI account will be blocked today. Update your KYC immediately at sbi-kyc-help.xyz/upd "
     "or call 9876543210. Ref 55123")
B = ("Dear customer your SBI account will be blocked today. Update your KYC immediately at sbi-secure-kyc.top/a "
     "or call 9123456780. Ref 99001")  # same campaign, different link, phone and reference
UNRELATED = "Congratulations! You have won Rs 25,00,000 in the KBC lucky draw. Claim now at kbc-claim.com"


@pytest.fixture
async def db(tmp_path):
    d = Database(f"sqlite+aiosqlite:///{tmp_path / 's.db'}")
    await d.create_all()
    yield d
    await d.aclose()


def test_template_ignores_links_numbers_and_amounts():
    assert similarity.template(A) == similarity.template(B)
    assert similarity.jaccard_pct(similarity.shingles(A), similarity.shingles(B)) == 100
    assert similarity.jaccard_pct(similarity.shingles(A), similarity.shingles(UNRELATED)) < similarity.SIMILAR
    assert similarity.shingles("Call me") == frozenset()  # too short to compare


async def _store(db, text):
    r = await assess_message(text, llm=None, deps=None)
    async with db.session() as s:
        r = await apply_correlation(s, r)
        await store.save_report(s, r)
    return r


async def test_second_message_of_a_campaign_is_linked_and_clusters(db, monkeypatch):
    import app.pipeline_message as pm

    async def no_links(url, deps=None, **kw):  # keep the test offline: link checks are not what is tested here
        from app.pipeline import Deps, assess_url
        return await assess_url(url, deps=Deps(checks=[]))
    monkeypatch.setattr(pm, "assess_url", no_links)

    first = await _store(db, A)
    second = await _store(db, B)
    assert str(first.classification) in ("suspicious", "high_risk", "confirmed_malicious")
    sim = [f for f in second.findings if f.check_id == "CORR.SIMILAR_MESSAGE"]
    assert sim and sim[0].evidence[0].data["report_ids"] == [first.report_id]
    assert (sim[0].severity, sim[0].strength) == ("low", "heuristic")
    fam = lambda r: next(i.normalized for i in r.indicators if i.type == "message_family")  # noqa: E731
    assert fam(first) == fam(second)
    assert {"sbi"} <= {i.normalized for i in second.indicators if i.type == "brand_claimed"}

    async with db.session() as s:
        rows = await store.indicator_rows(s)
    clusters = build_clusters(rows)
    assert any(set(c.report_ids) == {first.report_id, second.report_id} and "message wording" in c.label for c in clusters)
    [trend] = [t for t in impersonation_trends(rows, {first.report_id: "message", second.report_id: "message"}, get_index())
               if t.brand_id == "sbi"]
    assert (trend.reports, trend.messages, trend.links) == (2, 2, 0)

    third = await _store(db, UNRELATED)
    assert not any(f.check_id == "CORR.SIMILAR_MESSAGE" for f in third.findings)
