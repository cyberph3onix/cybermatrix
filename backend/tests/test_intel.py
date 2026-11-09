"""Threat-intel checks (GSB, URLhaus, OpenPhish, VirusTotal) against mocked HTTP. No live calls."""
from datetime import timedelta

import httpx
import pytest
import respx

from app.brands import get_index
from app.cache import MemoryIntelCache
from app.checks.base import AssessmentContext
from app.checks.intel import gsb, openphish, urlhaus, virustotal
from app.fetch.api_client import ApiClient
from app.urlutil import parse_url
from tests.certgen import NOW
from tests.conftest import fake_fetcher, fetch_result

URL = "https://kyc-verify-now.top/login"


def make_ctx(url=URL, hops=None, cache=None):
    fr = fetch_result(hops or [url], b"<html></html>")
    return AssessmentContext(url=parse_url(url), brands=get_index(), now=NOW, fetcher=fake_fetcher(fr),
                             api=ApiClient(timeout=3), cache=cache if cache is not None else MemoryIntelCache())


# ---------- Google Safe Browsing ----------

GSB_URL = gsb.SEARCH


@respx.mock
async def test_gsb_hit(monkeypatch):
    monkeypatch.setenv("GSB_API_KEY", "k-secret")
    route = respx.get(GSB_URL).mock(return_value=httpx.Response(200, json={
        "threats": [{"url": URL, "threatTypes": ["SOCIAL_ENGINEERING"]}], "cacheDuration": "300s"}))
    run, findings = await gsb.run(make_ctx())
    assert run.status == "completed" and run.check_group == "intel.gsb"
    [f] = findings
    assert (f.check_id, f.severity, f.strength) == ("URL.INTEL.GSB", "critical", "authoritative")
    assert f.evidence[0].source == "google_safe_browsing" and f.evidence[0].data["threat_types"] == ["SOCIAL_ENGINEERING"]
    # key goes in a header, never the URL
    req = route.calls[0].request
    assert req.headers["x-goog-api-key"] == "k-secret" and "k-secret" not in str(req.url)


@respx.mock
async def test_gsb_clean_and_cached(monkeypatch):
    monkeypatch.setenv("GSB_API_KEY", "k")
    route = respx.get(GSB_URL).mock(return_value=httpx.Response(200, json={"cacheDuration": "300s"}))
    ctx = make_ctx()
    run, findings = await gsb.run(ctx)
    assert run.status == "completed" and findings == []
    assert route.call_count == 1
    await gsb.run(ctx)  # served from the cache (6 h TTL)
    assert route.call_count == 1


@respx.mock
async def test_gsb_checks_redirect_destination(monkeypatch):
    monkeypatch.setenv("GSB_API_KEY", "k")
    dest = "https://evil.example.top/x"

    def handler(request: httpx.Request):
        urls = request.url.params.get_list("urls")
        threats = [{"url": dest, "threatTypes": ["MALWARE"]}] if dest in urls else []
        return httpx.Response(200, json={"threats": threats})
    route = respx.get(GSB_URL).mock(side_effect=handler)
    run, findings = await gsb.run(make_ctx("https://bit.ly/abc", hops=["https://bit.ly/abc", dest]))
    assert [f.check_id for f in findings] == ["URL.INTEL.GSB"]
    assert route.call_count == 2  # submitted URL first, then the destination


async def test_gsb_missing_key_unavailable():
    run, findings = await gsb.run(make_ctx())
    assert (run.status, findings) == ("unavailable", [])
    assert "GSB_API_KEY" in run.detail


@respx.mock
async def test_gsb_rate_limited_unavailable(monkeypatch):
    monkeypatch.setenv("GSB_API_KEY", "k")
    respx.get(GSB_URL).mock(return_value=httpx.Response(429))
    run, findings = await gsb.run(make_ctx())
    assert (run.status, findings) == ("unavailable", [])
    assert "rate limited" in run.detail


# ---------- URLhaus ----------

def haus(url_status="online", added="2026-11-05 10:00:00 UTC"):
    return {"query_status": "ok", "url_status": url_status, "date_added": added, "threat": "malware_download",
            "tags": ["exe"], "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/"}


@respx.mock
async def test_urlhaus_url_hit(monkeypatch):
    monkeypatch.setenv("URLHAUS_AUTH_KEY", "abc")
    url_route = respx.post(urlhaus.URL_API).mock(return_value=httpx.Response(200, json=haus()))
    respx.post(urlhaus.HOST_API).mock(return_value=httpx.Response(200, json={"query_status": "no_results"}))
    run, findings = await urlhaus.run(make_ctx())
    assert run.status == "completed"
    assert [f.check_id for f in findings] == ["URL.INTEL.URLHAUS"]
    assert url_route.calls[0].request.headers["Auth-Key"] == "abc"


@respx.mock
async def test_urlhaus_old_offline_listing_is_not_a_finding(monkeypatch):
    monkeypatch.setenv("URLHAUS_AUTH_KEY", "abc")
    respx.post(urlhaus.URL_API).mock(return_value=httpx.Response(200, json=haus("offline", "2024-01-01 00:00:00 UTC")))
    respx.post(urlhaus.HOST_API).mock(return_value=httpx.Response(200, json={"query_status": "no_results"}))
    run, findings = await urlhaus.run(make_ctx())
    assert run.status == "completed" and findings == []


@respx.mock
async def test_urlhaus_recent_offline_counts(monkeypatch):
    monkeypatch.setenv("URLHAUS_AUTH_KEY", "abc")
    recent = (NOW - timedelta(days=3)).strftime("%Y-%m-%d %H:%M:%S UTC")
    respx.post(urlhaus.URL_API).mock(return_value=httpx.Response(200, json=haus("offline", recent)))
    respx.post(urlhaus.HOST_API).mock(return_value=httpx.Response(200, json={"query_status": "no_results"}))
    _, findings = await urlhaus.run(make_ctx())
    assert len(findings) == 1


@respx.mock
async def test_urlhaus_host_hit_with_documented_typo(monkeypatch):
    monkeypatch.setenv("URLHAUS_AUTH_KEY", "abc")
    respx.post(urlhaus.URL_API).mock(return_value=httpx.Response(200, json={"query_status": "no_results"}))
    respx.post(urlhaus.HOST_API).mock(return_value=httpx.Response(200, json={
        "query_staus": "ok", "url_count": "2", "urlhaus_reference": "https://urlhaus.abuse.ch/host/x/",
        "urls": [{"url_status": "online", "date_added": "2020-01-01 00:00:00 UTC"},
                 {"url_status": "offline", "date_added": "2020-01-02 00:00:00 UTC"}]}))
    _, findings = await urlhaus.run(make_ctx())
    [f] = findings
    assert f.evidence[0].data["scope"] == "host" and f.evidence[0].data["online_count"] == 1


@respx.mock
async def test_urlhaus_skips_host_lookup_for_allowlisted_host(monkeypatch):
    monkeypatch.setenv("URLHAUS_AUTH_KEY", "abc")
    respx.post(urlhaus.URL_API).mock(return_value=httpx.Response(200, json={"query_status": "no_results"}))
    host_route = respx.post(urlhaus.HOST_API).mock(return_value=httpx.Response(200, json={"query_status": "ok"}))
    ctx = make_ctx("https://github.com/someone/repo")
    assert get_index().allowlisted("github.com") or get_index().is_abusable("github.com")
    run, findings = await urlhaus.run(ctx)
    assert run.status == "completed" and findings == [] and host_route.call_count == 0


async def test_urlhaus_missing_key_unavailable():
    run, _ = await urlhaus.run(make_ctx())
    assert run.status == "unavailable" and "URLHAUS_AUTH_KEY" in run.detail


# ---------- VirusTotal ----------

def vt(malicious, harmless=60):
    return {"data": {"attributes": {"last_analysis_date": 1762600000,
                                    "last_analysis_stats": {"malicious": malicious, "suspicious": 0,
                                                            "harmless": harmless, "undetected": 5, "timeout": 0}}}}


def vt_route(url=URL):
    return respx.get(virustotal.API + virustotal.url_id(url))


def test_vt_url_id_is_unpadded_urlsafe_base64():
    assert virustotal.url_id("http://www.example.com/") == "aHR0cDovL3d3dy5leGFtcGxlLmNvbS8"


@respx.mock
@pytest.mark.parametrize("n,check_id,severity,strength", [
    (7, "URL.INTEL.VT_MAJORITY", "critical", "authoritative"),
    (5, "URL.INTEL.VT_MAJORITY", "critical", "authoritative"),
    (4, "URL.INTEL.VT_MINORITY", "medium", "heuristic"),
    (1, "URL.INTEL.VT_MINORITY", "medium", "heuristic"),
])
async def test_vt_thresholds(monkeypatch, n, check_id, severity, strength):
    monkeypatch.setenv("VT_API_KEY", "vk")
    route = vt_route().mock(return_value=httpx.Response(200, json=vt(n)))
    run, findings = await virustotal.run(make_ctx())
    [f] = findings
    assert (f.check_id, f.severity, f.strength) == (check_id, severity, strength)
    assert route.calls[0].request.headers["x-apikey"] == "vk"


@respx.mock
async def test_vt_zero_malicious_no_finding(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "vk")
    vt_route().mock(return_value=httpx.Response(200, json=vt(0)))
    run, findings = await virustotal.run(make_ctx())
    assert run.status == "completed" and findings == []


@respx.mock
async def test_vt_unknown_url_is_completed_not_submitted(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "vk")
    route = vt_route().mock(return_value=httpx.Response(404, json={"error": {"code": "NotFoundError"}}))
    post = respx.post(url__regex=r"https://www\.virustotal\.com/.*").mock(return_value=httpx.Response(200))
    run, findings = await virustotal.run(make_ctx())
    assert run.status == "completed" and findings == [] and route.call_count == 1 and post.call_count == 0


@respx.mock
async def test_vt_rate_limited_unavailable(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "vk")
    vt_route().mock(return_value=httpx.Response(429))
    run, findings = await virustotal.run(make_ctx())
    assert (run.status, findings) == ("unavailable", [])


async def test_vt_missing_key_unavailable():
    run, _ = await virustotal.run(make_ctx())
    assert run.status == "unavailable" and "VT_API_KEY" in run.detail


# ---------- OpenPhish ----------

FEED_TEXT = "https://evil-login.example.top/a/b?x=1\nhttp://kyc-verify-now.top/login/\nnot a url\nhttps://github.com/bad/repo\n"


def loaded_feed(tmp_path, text=FEED_TEXT):
    p = tmp_path / "feed.txt"
    p.write_text(text)
    feed = openphish.OpenPhishFeed(p)
    assert feed.load_file()
    return feed


async def test_openphish_exact_match_ignores_scheme_and_trailing_slash(tmp_path, monkeypatch):
    monkeypatch.setattr(openphish, "FEED", loaded_feed(tmp_path))
    run, findings = await openphish.run(make_ctx(URL))  # feed has http://…/login/, we submit https://…/login
    assert run.status == "completed"
    [f] = findings
    assert (f.check_id, f.evidence[0].data["scope"]) == ("URL.INTEL.OPENPHISH", "url")


async def test_openphish_host_match(tmp_path, monkeypatch):
    monkeypatch.setattr(openphish, "FEED", loaded_feed(tmp_path))
    _, findings = await openphish.run(make_ctx("https://evil-login.example.top/other"))
    assert findings[0].evidence[0].data["scope"] == "host"


async def test_openphish_no_host_match_on_allowlisted_or_abusable_host(tmp_path, monkeypatch):
    monkeypatch.setattr(openphish, "FEED", loaded_feed(tmp_path))
    _, findings = await openphish.run(make_ctx("https://github.com/good/repo"))
    assert findings == []
    _, findings = await openphish.run(make_ctx("https://github.com/bad/repo"))  # exact URL still matches
    assert len(findings) == 1


async def test_openphish_clean(tmp_path, monkeypatch):
    monkeypatch.setattr(openphish, "FEED", loaded_feed(tmp_path))
    run, findings = await openphish.run(make_ctx("https://example.org/"))
    assert run.status == "completed" and findings == []


async def test_openphish_unavailable_when_feed_never_downloaded():
    run, findings = await openphish.run(make_ctx())
    assert (run.status, findings) == ("unavailable", [])


async def test_openphish_stale_feed_unavailable(tmp_path, monkeypatch):
    import os
    feed = loaded_feed(tmp_path)
    old = feed.path.stat().st_mtime - 72 * 3600
    os.utime(feed.path, (old, old))
    feed.load_file()
    monkeypatch.setattr(openphish, "FEED", feed)
    run, _ = await openphish.run(make_ctx())
    assert run.status == "unavailable" and "old" in run.detail


@respx.mock
async def test_openphish_refresh_writes_file_atomically(tmp_path):
    respx.get(openphish.FEED_URL).mock(return_value=httpx.Response(200, text=FEED_TEXT))
    feed = openphish.OpenPhishFeed(tmp_path / "data" / "openphish_feed.txt")
    async with ApiClient() as api:
        assert await feed.refresh(api)
    assert feed.loaded and len(feed.urls) == 3
    assert feed.path.read_text() == FEED_TEXT and not feed.path.with_suffix(".tmp").exists()


@respx.mock
async def test_openphish_failed_refresh_keeps_previous_feed(tmp_path):
    feed = loaded_feed(tmp_path)
    respx.get(openphish.FEED_URL).mock(return_value=httpx.Response(503))
    async with ApiClient() as api:
        assert not await feed.refresh(api)
    assert len(feed.urls) == 3


@respx.mock
async def test_openphish_rejects_garbage_download(tmp_path):
    feed = loaded_feed(tmp_path)
    respx.get(openphish.FEED_URL).mock(return_value=httpx.Response(200, text="<html>captive portal</html>"))
    async with ApiClient() as api:
        assert not await feed.refresh(api)
    assert feed.path.read_text() == FEED_TEXT


@respx.mock
async def test_openphish_redirect_is_not_treated_as_a_feed(tmp_path):
    """openphish.com/feed.txt 302s to GitHub; the client never follows redirects and must not accept the 302 body."""
    feed = loaded_feed(tmp_path)
    respx.get(openphish.FEED_URL).mock(return_value=httpx.Response(302, headers={"location": "https://evil.example/x"},
                                                                  text="<html>302</html>"))
    async with ApiClient() as api:
        assert not await feed.refresh(api)
    assert openphish.FEED_URL.startswith("https://raw.githubusercontent.com/openphish/public_feed/")
    assert len(feed.urls) == 3


@respx.mock
async def test_gsb_binary_protobuf_response(monkeypatch):
    """Recorded from the live service: it answers in protobuf (phishing test URL, SOCIAL_ENGINEERING)."""
    monkeypatch.setenv("GSB_API_KEY", "k")
    body = bytes.fromhex("0a310a2c7465737473616665627" "26f77" "73696e672e617070" "73706f742e636f6d2f732f70" "6869736869" "6e672e68746d6c" "120102" "120308ac02")
    respx.get(GSB_URL).mock(return_value=httpx.Response(200, content=body))
    run, findings = await gsb.run(make_ctx("https://testsafebrowsing.appspot.com/s/phishing.html"))
    assert run.status == "completed" and [f.check_id for f in findings] == ["URL.INTEL.GSB"]
    assert findings[0].evidence[0].data["threat_types"] == ["SOCIAL_ENGINEERING"]
    assert gsb.parse_search_response(bytes.fromhex("1203" "08ac02")) == []
