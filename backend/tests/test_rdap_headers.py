from datetime import timedelta

import httpx
import respx

from app.brands import get_index
from app.cache import MemoryIntelCache
from app.checks import domain_rdap, headers
from app.checks.base import AssessmentContext
from app.checks.tls_chain import TlsScan
from app.fetch.api_client import ApiClient
from app.urlutil import parse_url
from tests.certgen import NOW
from tests.conftest import fake_fetcher, fetch_result

RDAP_BASE = "https://rdap.example-registry.net/"
BOOTSTRAP = {"services": [[["top", "xyz"], [RDAP_BASE]], [["com"], ["http://insecure.example/", "https://rdap.verisign.com/com/v1/"]]]}


def make_ctx(url="https://kyc-verify-now.top/login", hops=None, body=b"", ctype="text/html", status=200):
    fr = fetch_result(hops or [url], body, ctype, status)
    return AssessmentContext(url=parse_url(url), brands=get_index(), now=NOW, fetcher=fake_fetcher(fr),
                             api=ApiClient(timeout=3), cache=MemoryIntelCache())


def rdap_body(registered, ns=("ns1.cheap-dns.net", "NS2.cheap-dns.net.")):
    return {"events": [{"eventAction": "last changed", "eventDate": "2026-11-01T00:00:00Z"},
                       {"eventAction": "registration", "eventDate": registered}],
            "nameservers": [{"ldhName": n} for n in ns],
            "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Cheap Registrar Inc"]]]}]}


def mock_rdap(domain, registered):
    respx.get(domain_rdap.BOOTSTRAP).mock(return_value=httpx.Response(200, json=BOOTSTRAP))
    return respx.get(f"{RDAP_BASE}domain/{domain}").mock(return_value=httpx.Response(200, json=rdap_body(registered)))


@respx.mock
async def test_young_domain_flagged_and_nameservers_recorded():
    mock_rdap("kyc-verify-now.top", (NOW - timedelta(days=4)).strftime("%Y-%m-%dT%H:%M:%SZ"))
    ctx = make_ctx()
    run, findings = await domain_rdap.run(ctx)
    assert (run.check_group, run.status) == ("domain.rdap", "completed")
    [f] = findings
    assert (f.check_id, f.severity, f.strength) == ("DOMAIN.YOUNG", "medium", "heuristic")
    assert f.evidence[0].source == "rdap" and f.evidence[0].data["age_days"] == 4
    assert ctx.nameservers == ["ns1.cheap-dns.net", "ns2.cheap-dns.net"]


@respx.mock
async def test_old_domain_not_flagged():
    mock_rdap("kyc-verify-now.top", "2015-01-01T00:00:00Z")
    run, findings = await domain_rdap.run(make_ctx())
    assert run.status == "completed" and findings == []


@respx.mock
async def test_bootstrap_cached_and_only_https_servers_used():
    boot = respx.get(domain_rdap.BOOTSTRAP).mock(return_value=httpx.Response(200, json=BOOTSTRAP))
    respx.get(f"{RDAP_BASE}domain/a.top").mock(return_value=httpx.Response(200, json=rdap_body("2015-01-01T00:00:00Z")))
    respx.get(f"{RDAP_BASE}domain/b.top").mock(return_value=httpx.Response(200, json=rdap_body("2015-01-01T00:00:00Z")))
    cache = MemoryIntelCache()
    for host in ("a.top", "b.top"):
        ctx = make_ctx(f"https://{host}/")
        ctx.cache = cache
        await domain_rdap.run(ctx)
    assert boot.call_count == 1
    assert (await domain_rdap._bootstrap(make_ctx()))["com"] == "https://rdap.verisign.com/com/v1/"


@respx.mock
async def test_young_redirect_destination_flagged():
    respx.get(domain_rdap.BOOTSTRAP).mock(return_value=httpx.Response(200, json=BOOTSTRAP))
    respx.get(f"{RDAP_BASE}domain/old-shortener.top").mock(
        return_value=httpx.Response(200, json=rdap_body("2015-01-01T00:00:00Z")))
    respx.get(f"{RDAP_BASE}domain/fresh-scam.xyz").mock(
        return_value=httpx.Response(200, json=rdap_body((NOW - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ"))))
    ctx = make_ctx("https://old-shortener.top/a", hops=["https://old-shortener.top/a", "https://fresh-scam.xyz/login"])
    _, findings = await domain_rdap.run(ctx)
    [f] = findings
    assert f.evidence[0].data["domain"] == "fresh-scam.xyz" and f.evidence[0].data["url"] == "https://fresh-scam.xyz/login"


@respx.mock
async def test_unknown_tld_and_unreachable_registry_are_unavailable():
    respx.get(domain_rdap.BOOTSTRAP).mock(return_value=httpx.Response(200, json=BOOTSTRAP))
    run, findings = await domain_rdap.run(make_ctx("https://thing.zzz/"))
    assert (run.status, findings) == ("unavailable", []) and ".zzz" in run.detail
    respx.get(f"{RDAP_BASE}domain/down.top").mock(return_value=httpx.Response(503))
    run, _ = await domain_rdap.run(make_ctx("https://down.top/"))
    assert run.status == "unavailable"


@respx.mock
async def test_missing_registration_event_is_unavailable_not_clean():
    respx.get(domain_rdap.BOOTSTRAP).mock(return_value=httpx.Response(200, json=BOOTSTRAP))
    respx.get(f"{RDAP_BASE}domain/quiet.top").mock(return_value=httpx.Response(200, json={"events": []}))
    run, findings = await domain_rdap.run(make_ctx("https://quiet.top/"))
    assert (run.status, findings) == ("unavailable", [])


async def test_ip_host_skipped():
    run, findings = await domain_rdap.run(make_ctx("http://203.0.113.9/login"))
    assert (run.status, findings) == ("skipped", [])


# ---------- headers ----------

GOOD = {"strict-transport-security": "max-age=31536000", "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "x-content-type-options": "nosniff"}


def ids(findings):
    return [f.check_id for f in findings]


def test_clean_headers_no_findings():
    assert headers.analyze(GOOD, "https://example.org/", b"<html></html>", "text/html", "TLSv1.3", NOW) == []


def test_missing_headers():
    out = headers.analyze({}, "https://example.org/", b"", "text/html", "TLSv1.3", NOW)
    assert ids(out) == ["POSTURE.NO_HSTS", "POSTURE.NO_CSP", "POSTURE.NO_XFO", "POSTURE.NO_XCTO"]
    assert all(f.category == "security_posture" and f.evidence and f.limitation for f in out)


def test_no_hsts_not_reported_for_plain_http_and_frame_ancestors_covers_xfo():
    out = headers.analyze({"content-security-policy": "frame-ancestors 'self'", "x-content-type-options": "nosniff"},
                          "http://example.org/", b"", "text/html", None, NOW)
    assert out == []


def test_mixed_content_old_tls_and_banner():
    body = (b'<html><head><script src="http://cdn.example/a.js"></script><link rel="stylesheet" href="http://c.example/s.css">'
            b'</head><body><img src="https://ok.example/x.png"><a href="http://just-a-link.example/">link</a></body></html>')
    out = headers.analyze({**GOOD, "server": "Apache/2.4.7 (Ubuntu)"}, "https://example.org/", body, "text/html",
                          "TLSv1.0", NOW)
    assert ids(out) == ["POSTURE.MIXED_CONTENT", "POSTURE.OLD_TLS_VERSION", "POSTURE.SERVER_BANNER_VERSION"]
    mixed = out[0].evidence[0].data
    assert mixed["count"] == 2  # the plain <a href> is navigation, not a subresource


def test_banner_without_version_not_flagged():
    assert headers.analyze({**GOOD, "server": "nginx"}, "https://example.org/", b"", "text/html", "TLSv1.3", NOW) == []


async def test_run_reports_into_posture_only_group():
    ctx = make_ctx("https://example.org/", body=b"<html></html>")

    async def scanner(host, port):  # never touch the network in tests
        return TlsScan(hostname=host, port=port, tls_version="TLSv1.1")
    ctx.tls_scanner = scanner
    run, findings = await headers.run(ctx)
    assert (run.check_group, run.status, run.weight) == ("posture.headers", "completed", 0)
    assert "POSTURE.OLD_TLS_VERSION" in [f.check_id for f in findings]
    assert findings and all(f.check_id.startswith("POSTURE.") for f in findings)


async def test_run_failed_fetch():
    ctx = make_ctx("https://example.org/", status=200)
    ctx._fetch_task = None
    fr = fetch_result(["https://example.org/"], error="timeout")
    fr.status = None
    fr.final_url = None
    ctx.fetcher = fake_fetcher(fr)
    run, findings = await headers.run(ctx)
    assert (run.status, findings) == ("failed", [])


def test_end_of_life_software_from_banners():
    from datetime import date
    hits = headers.outdated_software({"server": "Apache/2.2.15 (CentOS) OpenSSL/1.0.2k", "x-powered-by": "PHP/5.6.40"},
                                     date(2026, 11, 9))
    assert {(h[1], h[2]) for h in hits} == {("Apache HTTP Server", "2.2"), ("OpenSSL", "1.0.2"), ("PHP", "5.6")}
    # supported lines (or a patch level inside one) are not flagged; unknown products are ignored
    assert headers.outdated_software({"server": "nginx/1.30.2", "x-powered-by": "PHP/8.4.1"}, date(2026, 11, 9)) == []
    assert headers.outdated_software({"server": "Apache/2.4.6 (CentOS)"}, date(2026, 11, 9)) == []
    assert headers.outdated_software({"server": "cloudflare"}, date(2026, 11, 9)) == []


def test_outdated_software_is_posture_only():
    fs = headers.analyze({"server": "nginx/1.16.1"}, "https://example.com/", b"", "text/html", "TLSv1.3", NOW)
    [f] = [f for f in fs if f.check_id == "POSTURE.OUTDATED_SOFTWARE"]
    assert f.category == "security_posture" and "backport" in f.limitation and f.evidence[0].data["eol"]



def _crtsh(rows):
    return respx.get(domain_rdap.CRTSH).mock(return_value=httpx.Response(200, json=rows))


@respx.mock
async def test_new_site_on_old_hosting_platform_is_young_by_ct_history():
    """Limitation 9: RDAP only knows pages.dev (old); crt.sh's first certificate for the site itself is days old."""
    BOOT = {"services": [[["dev"], [RDAP_BASE]]]}
    respx.get(domain_rdap.BOOTSTRAP).mock(return_value=httpx.Response(200, json=BOOT))
    respx.get(f"{RDAP_BASE}domain/pages.dev").mock(return_value=httpx.Response(200, json=rdap_body("2019-01-01T00:00:00Z")))
    nb = (NOW - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%S")
    _crtsh([{"name_value": "sbi-kyc-update.pages.dev", "not_before": nb},
            {"name_value": "*.pages.dev\npages.dev", "not_before": "2020-01-01T00:00:00"}])  # the platform's wildcard
    run, findings = await domain_rdap.run(make_ctx("https://sbi-kyc-update.pages.dev/login"))
    [f] = findings
    assert (f.check_id, f.evidence[0].source, f.evidence[0].data["age_days"]) == ("DOMAIN.YOUNG", "crt.sh", 3)
    assert "pages.dev itself is old" in f.evidence[0].description


@respx.mock
async def test_hosted_site_with_only_a_wildcard_cert_has_unknown_age():
    BOOT = {"services": [[["io"], [RDAP_BASE]]]}
    respx.get(domain_rdap.BOOTSTRAP).mock(return_value=httpx.Response(200, json=BOOT))
    respx.get(f"{RDAP_BASE}domain/github.io").mock(return_value=httpx.Response(200, json=rdap_body("2013-03-08T00:00:00Z")))
    _crtsh([])
    run, findings = await domain_rdap.run(make_ctx("https://someone.github.io/"))
    assert findings == [] and run.status == "completed" and "age is unknown" in run.detail
