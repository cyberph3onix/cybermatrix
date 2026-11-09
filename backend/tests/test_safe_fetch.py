import gzip
import ssl

import httpx
import pytest
from httpx_secure import SSRFProtectionError

from app.fetch import safe_fetch as sf
from app.urlutil import parse_url

PUBLIC = "93.184.216.34"


@pytest.fixture
def dns(monkeypatch):
    table: dict[str, list[str]] = {}

    async def fake(host, port):
        if host not in table:
            raise OSError("NXDOMAIN")
        return table[host]

    monkeypatch.setattr(sf, "_getaddrinfo", fake)
    return table


@pytest.fixture
def no_network(monkeypatch):
    calls = []

    async def boom(url, **kw):
        calls.append(url.host)
        raise AssertionError(f"network send attempted for {url.host}")

    monkeypatch.setattr(sf, "_send_hop", boom)
    return calls


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/",
    "http://10.0.0.1/",
    "http://10.255.1.2:8080/x",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]/",
    "http://[::ffff:127.0.0.1]/",
    "http://[::ffff:7f00:1]/",
    "http://2130706433/",
    "http://0177.0.0.1/",
    "http://0x7f000001/",
    "http://0x7f.1/",
    "http://127.1/",
    "http://100.64.0.1/",
    "http://100.100.100.200/",
    "http://0.0.0.0/",
    "http://[fd00::1]/",
    "http://[fe80::1]/",
    "http://[64:ff9b::a00:1]/",
    "http://[2002:0a00:0001::]/",
    "http://224.0.0.1/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://localhost/",
    "http://foo.localhost/",
    "http://printer.local/",
    "https://example.com:22/",
    "https://example.com:6379/",
    "file:///etc/passwd",
    "gopher://example.com/",
    "ftp://example.com/",
])
async def test_blocks_before_any_network(url, dns, no_network):
    dns["example.com"] = [PUBLIC]
    r = await sf.safe_fetch(url)
    assert r.blocked, r.error
    assert not no_network


async def test_hostname_resolving_to_private_is_blocked(dns, no_network):
    dns["evil.test.com"] = ["10.0.0.5"]
    r = await sf.safe_fetch("https://evil.test.com/")
    assert r.blocked and "10.0.0.5" in r.error
    assert not no_network


async def test_any_private_address_in_answer_blocks(dns, no_network):
    dns["mixed.example.com"] = [PUBLIC, "192.168.1.10"]
    r = await sf.safe_fetch("https://mixed.example.com/")
    assert r.blocked


async def test_ipv4_mapped_v6_in_dns_answer_blocked(dns, no_network):
    dns["mapped.example.com"] = ["::ffff:10.0.0.1"]
    r = await sf.safe_fetch("https://mapped.example.com/")
    assert r.blocked


def test_ip_allowed_public():
    import ipaddress
    assert sf.ip_allowed(ipaddress.ip_address(PUBLIC))
    assert sf.ip_allowed(ipaddress.ip_address("2606:4700::1111"))
    assert not sf.ip_allowed(ipaddress.ip_address("168.63.129.16"))


async def test_httpx_secure_layer_blocks_even_if_precheck_bypassed(monkeypatch):
    """Defence in depth: if our pre-check were fooled (e.g. DNS rebinding), the pinned client still refuses."""
    import asyncio

    async def handle(reader, writer):
        writer.write(b"HTTP/1.1 200 OK\r\ncontent-type: text/html\r\ncontent-length: 2\r\n\r\nhi")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        for verify in (True, False):  # verify=False client comes from the same factory and is just as protected
            for host in ("localhost", "127.0.0.1"):
                with pytest.raises(SSRFProtectionError):
                    await sf._send_hop(parse_url(f"http://{host}:{port}/"), verify=verify, method="GET",
                                       body=None, headers={}, allowed_types=sf.TEXT_TYPES)
    finally:
        server.close()
        await server.wait_closed()


def test_both_client_variants_are_ssrf_wrapped():
    for verify in (True, False):
        c = sf.make_client(verify=verify)
        # httpx-secure replaces the transport's network backend; a plain client would not have it
        pools = [t._pool for t in c._mounts.values() if t is not None] + [c._transport._pool]
        assert any("ssrf" in type(p._network_backend).__module__.lower()
                   or "secure" in type(p._network_backend).__module__.lower()
                   or type(p._network_backend).__name__ != "AutoBackend" for p in pools)


def _hop(status=200, headers=None, body=b"", ctype="text/html", ip=PUBLIC):
    h = {"content-type": ctype} | (headers or {})
    return sf._HopResponse(status, h, body, ip, ctype)


@pytest.fixture
def fake_sender(monkeypatch):
    script: dict[str, object] = {}
    sent: list[str] = []

    async def send(url, **kw):
        sent.append(url.url_without_userinfo())
        r = script[url.host]
        if isinstance(r, BaseException):
            raise r
        if callable(r):
            return r(url, **kw)
        return r

    monkeypatch.setattr(sf, "_send_hop", send)
    return script, sent


@pytest.mark.parametrize("location", [
    "http://10.0.0.5/admin",
    "http://2130706433/",
    "http://[::ffff:127.0.0.1]/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/latest/",
    "http://rebind.example.net/",
])
async def test_public_redirect_to_private_is_blocked(location, dns, fake_sender):
    script, sent = fake_sender
    dns["start.example.com"] = [PUBLIC]
    dns["rebind.example.net"] = ["127.0.0.1"]
    script["start.example.com"] = _hop(302, {"location": location})
    r = await sf.safe_fetch("https://start.example.com/")
    assert r.blocked, r.error
    assert len(r.hops) == 1 and r.hops[0].status_code == 302
    assert sent == ["https://start.example.com/"]


async def test_redirect_chain_recorded_and_cross_domain(dns, fake_sender):
    script, _ = fake_sender
    dns.update({"bit.ly": [PUBLIC], "a.example.com": [PUBLIC], "b.example.com": [PUBLIC]})
    script["bit.ly"] = _hop(301, {"location": "https://a.example.com/x"})
    script["a.example.com"] = _hop(302, {"location": "/y"})
    script["b.example.com"] = _hop(200, body=b"<html>hi</html>")
    script["a.example.com"] = lambda url, **kw: (
        _hop(302, {"location": "https://b.example.com/z"}) if url.path == "/x" else _hop(200))
    r = await sf.safe_fetch("https://bit.ly/abc")
    assert r.ok and r.final_url == "https://b.example.com/z"
    assert [h.cross_domain for h in r.hops] == [False, True, False]
    assert r.body == b"<html>hi</html>"


async def test_max_hops(dns, fake_sender):
    script, _ = fake_sender
    dns["loop.example.com"] = [PUBLIC]
    script["loop.example.com"] = _hop(302, {"location": "https://loop.example.com/again"})
    r = await sf.safe_fetch("https://loop.example.com/")
    assert r.blocked and "redirects" in r.error
    assert len(r.hops) == 5


async def test_userinfo_never_sent(dns, fake_sender):
    script, sent = fake_sender
    dns["evil.example.com"] = [PUBLIC]
    script["evil.example.com"] = _hop(200, body=b"ok")
    await sf.safe_fetch("https://sbi.co.in:pw@evil.example.com/login")
    assert sent == ["https://evil.example.com/login"]


async def test_tls_retry_reruns_precheck_and_blocks_private(dns, fake_sender):
    """The verify=False retry path must re-run the pre-check (here: DNS rebinds to private between attempts)."""
    script, sent = fake_sender
    answers = iter([[PUBLIC], ["10.1.2.3"]])

    async def rebinding(host, port):
        return next(answers)
    import app.fetch.safe_fetch as mod
    mod_get = mod._getaddrinfo
    try:
        mod._getaddrinfo = rebinding
        err = httpx.ConnectError("x")
        err.__cause__ = ssl.SSLCertVerificationError("certificate verify failed")
        script["badcert.example.com"] = err
        r = await sf.safe_fetch("https://badcert.example.com/")
    finally:
        mod._getaddrinfo = mod_get
    assert r.blocked and "10.1.2.3" in r.error
    assert sent == ["https://badcert.example.com/"]  # retry never reached the network


async def test_tls_retry_marks_unverified(dns, monkeypatch):
    dns["badcert.example.com"] = [PUBLIC]
    seen = []

    async def send(url, *, verify, **kw):
        seen.append(verify)
        if verify:
            e = httpx.ConnectError("x")
            e.__cause__ = ssl.SSLCertVerificationError("certificate verify failed")
            raise e
        return _hop(200, body=b"<html></html>")
    monkeypatch.setattr(sf, "_send_hop", send)
    r = await sf.safe_fetch("https://badcert.example.com/")
    assert r.ok and r.tls_verified is False and seen == [True, False]


# ---- body caps: exercised through the real _send_hop with a mock transport behind the SSRF wrapper ----

def _mock_client_factory(handler):
    def factory(*, verify):
        return httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)
    return factory


async def _send_with(monkeypatch, handler, allowed=sf.TEXT_TYPES):
    monkeypatch.setattr(sf, "make_client", _mock_client_factory(handler))
    return await sf._send_hop(parse_url("https://example.com/"), verify=True, method="GET", body=None,
                              headers={}, allowed_types=allowed)


async def test_body_cap(monkeypatch):
    big = b"a" * (sf.MAX_BODY_BYTES + 10)
    with pytest.raises(sf._ContentRejected, match="2 MB"):
        await _send_with(monkeypatch, lambda req: httpx.Response(
            200, headers={"content-type": "text/html"}, content=big))


async def test_content_length_cap(monkeypatch):
    with pytest.raises(sf._ContentRejected, match="2 MB"):
        await _send_with(monkeypatch, lambda req: httpx.Response(
            200, headers={"content-type": "text/html", "content-length": str(50_000_000)}, content=b"x"))


async def test_gzip_bomb_capped(monkeypatch):
    bomb = gzip.compress(b"\0" * (10 * 1024 * 1024))
    assert len(bomb) < 100_000
    with pytest.raises(sf._ContentRejected, match="decoded"):
        await _send_with(monkeypatch, lambda req: httpx.Response(
            200, headers={"content-type": "text/html", "content-encoding": "gzip"}, content=bomb))


async def test_non_html_rejected(monkeypatch):
    with pytest.raises(sf._ContentRejected, match="content type"):
        await _send_with(monkeypatch, lambda req: httpx.Response(
            200, headers={"content-type": "application/x-msdownload"}, content=b"MZ"))


async def test_html_accepted(monkeypatch):
    r = await _send_with(monkeypatch, lambda req: httpx.Response(
        200, headers={"content-type": "text/html; charset=utf-8"}, content=b"<p>hi</p>"))
    assert r.body == b"<p>hi</p>" and r.content_type == "text/html"


async def test_safe_fetch_never_raises(dns, monkeypatch):
    dns["x.example.com"] = [PUBLIC]

    async def explode(url, **kw):
        raise RuntimeError("boom")
    monkeypatch.setattr(sf, "_send_hop", explode)
    r = await sf.safe_fetch("https://x.example.com/")
    assert r.error and not r.ok
