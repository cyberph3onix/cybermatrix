"""domain.dns: fast-flux, free DNS and email-authentication posture, from recorded DNS-over-HTTPS answers."""
import httpx
import respx

from app.brands import get_index
from app.cache import MemoryIntelCache
from app.checks import dns
from app.checks.base import AssessmentContext
from app.fetch.api_client import ApiClient
from app.urlutil import parse_url
from tests.certgen import NOW


def ctx_for(url):
    return AssessmentContext(url=parse_url(url), brands=get_index(), now=NOW, api=ApiClient(timeout=3),
                             cache=MemoryIntelCache())


def answer(rtype, rows, status=0):
    return {"Status": status, "Answer": [{"name": "x.", "type": dns.TYPES[rtype], "TTL": ttl, "data": d} for d, ttl in rows]}


def mock_doh(records: dict[tuple[str, str], dict]):
    def handler(request):
        key = (request.url.params["name"], request.url.params["type"])
        return httpx.Response(200, json=records.get(key, {"Status": 0, "Answer": []}))
    respx.get(dns.DOH).mock(side_effect=handler)


GOOD_TXT = answer("TXT", [('"v=spf1 include:_spf.example.net -all"', 300)])
GOOD_DMARC = answer("TXT", [('"v=DMARC1; p=reject; rua=mailto:d@example.net"', 300)])


@respx.mock
async def test_ordinary_domain_has_no_findings_and_records_nameservers():
    mock_doh({("www.shop-example.com", "A"): answer("A", [("93.184.216.34", 3600)]),
              ("shop-example.com", "NS"): answer("NS", [("ns1.registrar-dns.net.", 3600), ("ns2.registrar-dns.net.", 3600)]),
              ("shop-example.com", "TXT"): GOOD_TXT, ("_dmarc.shop-example.com", "TXT"): GOOD_DMARC})
    ctx = ctx_for("https://www.shop-example.com/")
    run, findings = await dns.run(ctx)
    assert (run.check_group, run.status, findings) == ("domain.dns", "completed", [])
    assert ctx.nameservers == ["ns1.registrar-dns.net", "ns2.registrar-dns.net"]


@respx.mock
async def test_fast_flux_and_free_dns():
    ips = [("45.12.1.1", 120), ("91.200.3.4", 120), ("185.7.9.9", 120), ("103.5.6.7", 120), ("5.188.1.2", 120)]
    mock_doh({("paypa1-verify.top", "A"): answer("A", ips),
              ("paypa1-verify.top", "NS"): answer("NS", [("ns1.afraid.org.", 3600)]),
              ("paypa1-verify.top", "TXT"): GOOD_TXT, ("_dmarc.paypa1-verify.top", "TXT"): GOOD_DMARC})
    _run, findings = await dns.run(ctx_for("https://paypa1-verify.top/login"))
    by = {f.check_id: f for f in findings}
    assert set(by) == {"DOMAIN.FAST_FLUX", "DOMAIN.FREE_DNS"}
    assert (by["DOMAIN.FAST_FLUX"].severity, by["DOMAIN.FAST_FLUX"].strength) == ("medium", "heuristic")
    assert by["DOMAIN.FAST_FLUX"].evidence[0].data["min_ttl"] == 120


@respx.mock
async def test_cdn_with_long_ttl_is_not_fast_flux():
    ips = [(f"104.16.{i}.1", 3600) for i in range(6)]  # one /16 and long TTL
    mock_doh({("cdn-example.com", "A"): answer("A", ips), ("cdn-example.com", "TXT"): GOOD_TXT,
              ("_dmarc.cdn-example.com", "TXT"): GOOD_DMARC})
    _run, findings = await dns.run(ctx_for("https://cdn-example.com/"))
    assert findings == []


@respx.mock
async def test_email_auth_posture():
    mock_doh({("nomail-example.com", "A"): answer("A", [("93.184.216.34", 3600)]),
              ("nomail-example.com", "TXT"): answer("TXT", [('"google-site-verification=abc"', 300)]),
              ("_dmarc.nomail-example.com", "TXT"): answer("TXT", [], status=3)})
    _run, findings = await dns.run(ctx_for("https://nomail-example.com/"))
    assert {f.check_id for f in findings} == {"POSTURE.NO_SPF", "POSTURE.NO_DMARC"}
    assert all(f.category == "security_posture" for f in findings)  # never feeds the phishing score


@respx.mock
async def test_dmarc_p_none_is_reported():
    mock_doh({("lax-example.com", "A"): answer("A", [("93.184.216.34", 3600)]), ("lax-example.com", "TXT"): GOOD_TXT,
              ("_dmarc.lax-example.com", "TXT"): answer("TXT", [('"v=DMARC1; p=none"', 300)])})
    _run, findings = await dns.run(ctx_for("https://lax-example.com/"))
    assert [f.check_id for f in findings] == ["POSTURE.DMARC_NOT_ENFORCED"]


@respx.mock
async def test_nxdomain_and_resolver_outage():
    mock_doh({("gone-example.com", "A"): {"Status": 3}, ("gone-example.com", "NS"): {"Status": 3}})
    run, findings = await dns.run(ctx_for("https://gone-example.com/"))
    assert run.status == "completed" and "NXDOMAIN" in run.detail and findings == []

    respx.get(dns.DOH).mock(return_value=httpx.Response(503))
    run, _ = await dns.run(ctx_for("https://other-example.com/"))
    assert run.status == "unavailable"


async def test_ip_host_is_skipped():
    run, _ = await dns.run(ctx_for("http://203.0.113.9/"))
    assert run.status == "skipped"
