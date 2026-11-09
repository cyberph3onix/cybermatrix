from datetime import UTC, datetime

from app.brands import get_index
from app.correlation.clusters import build_clusters

T = [datetime(2026, 11, d, tzinfo=UTC) for d in range(1, 10)]


def rows(*specs):
    return [(rid, typ, norm, cls, T[i]) for i, (rid, typ, norm, cls) in enumerate(specs)]


def test_reports_sharing_a_cert_or_email_cluster_transitively():
    cs = build_clusters(rows(
        ("r1", "cert_sha256", "AA", "high_risk"), ("r2", "cert_sha256", "AA", "suspicious"),
        ("r2", "email", "x@evil.top", "suspicious"), ("r3", "email", "x@evil.top", "confirmed_malicious"),
        ("r4", "cert_sha256", "ZZ", "high_risk")), get_index())
    [c] = cs
    assert c.report_ids == ["r1", "r2", "r3"] and c.top_classification == "confirmed_malicious"
    assert {(i.type, i.value, i.report_count) for i in c.shared_indicators} == {("cert_sha256", "AA", 2), ("email", "x@evil.top", 2)}
    assert c.first_seen < c.last_seen and c.cluster_id.startswith("c-")


def test_weak_and_generic_indicators_do_not_cluster():
    cs = build_clusters(rows(
        ("r1", "ip", "93.184.216.34", "high_risk"), ("r2", "ip", "93.184.216.34", "high_risk"),
        ("r1", "nameserver", "ns1.cloudflare.com", "high_risk"), ("r2", "nameserver", "ns1.cloudflare.com", "high_risk"),
        ("r3", "domain", "bit.ly", "suspicious"), ("r4", "domain", "bit.ly", "suspicious"),
        ("r5", "domain", "google.com", "suspicious"), ("r6", "domain", "google.com", "suspicious")), get_index())
    assert cs == []


def test_shared_scam_domain_clusters_and_lists_member_domains():
    cs = build_clusters(rows(("r1", "domain", "kyc-verify-now.top", "high_risk"),
                             ("r2", "domain", "kyc-verify-now.top", "high_risk")), get_index())
    assert cs[0].member_domains == ["kyc-verify-now.top"] and "domain" in cs[0].label


async def test_cluster_summaries_cached_validated_and_never_say_safe():
    from app.ai.cluster_summary import add_summaries
    from tests.test_message import FakeLlm
    cs = build_clusters(rows(("r1", "domain", "kyc-verify-now.top", "high_risk"),
                             ("r2", "domain", "kyc-verify-now.top", "high_risk")), get_index())
    assert (await add_summaries(None, cs, {}))[0].summary is None
    llm, cache = FakeLlm({"summary": "Two reports may point to one operator. Both involve kyc-verify-now.top."}), {}
    out = await add_summaries(llm, cs, cache)
    assert out[0].summary.startswith("Two reports") and out[0].summary_model == "claude-haiku-5-5"
    await add_summaries(llm, cs, cache)
    assert len(llm.calls) == 1  # second call served from the cache
    assert "<untrusted_input>" in llm.calls[0][1] and "kyc-verify-now.top" in llm.calls[0][1]
    for bad in ({"summary": "This domain is safe."}, {"nope": 1}, {"summary": "x" * 600}):
        assert (await add_summaries(FakeLlm(bad), cs, {}))[0].summary is None
