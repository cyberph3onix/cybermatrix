"""SSRF-guarded fetcher. ALL outbound HTTP to user-supplied targets goes through here (CLAUDE.md rule 4).

Layers, outermost first:
1. URL policy: http/https only, ports 80/443/8080/8443, userinfo stripped, non-canonical numeric hosts
   (2130706433, 0177.0.0.1) and metadata/internal hostnames rejected.
2. `resolve_and_validate`: resolve once and reject if ANY address is non-global or explicitly blocked.
3. Pinning: the request URL names the IP validated in step 2 (Host header, SNI and certificate checks keep the
   hostname), so there is exactly one DNS lookup per hop. httpx-secure re-validates that literal IP (is_global +
   NAT64) plus our `_connect_policy` (ports + blocklist) at connect time. Handing it a hostname instead would
   make it resolve again and open a TCP probe to the *second* answer before validating it: a DNS-rebinding hole.
4. Manual redirect loop (max 5 hops), re-running 1-3 for every hop; 5 s per hop, 15 s total, 2 MB decoded body
   cap, text/html and text/plain only (binary mode for OCSP/CRL only).
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlunsplit

import httpx
from httpx_secure import SSRFProtectionError, httpx_ssrf_protection

from app.schemas import RedirectHop
from app.urlutil import ParsedURL, URLParseError, parse_url, registrable_domain

ALLOWED_SCHEMES = frozenset({"http", "https"})
ALLOWED_PORTS = frozenset({80, 443, 8080, 8443})
MAX_HOPS = 5
HOP_TIMEOUT_S = 5.0
TOTAL_TIMEOUT_S = 15.0
DNS_TIMEOUT_S = 3.0
MAX_BODY_BYTES = 2 * 1024 * 1024
TEXT_TYPES = ("text/html", "text/plain")
BINARY_TYPES = ("application/ocsp-response", "application/pkix-crl", "application/x-pkcs7-crl",
                "application/octet-stream")
USER_AGENT = "CyberMatrix-Inspector/0.1 (passive security check)"

_BLOCKED_HOSTNAMES = frozenset({
    "localhost", "metadata", "metadata.google.internal", "metadata.goog", "instance-data",
    "instance-data.ec2.internal", "metadata.azure.com", "kubernetes.default", "kubernetes.default.svc",
})
_BLOCKED_SUFFIXES = (".localhost", ".internal", ".local", ".localdomain", ".home.arpa", ".svc", ".cluster.local")
_BLOCKED_IPS = frozenset(ipaddress.ip_address(a) for a in (
    "169.254.169.254", "168.63.129.16", "100.100.100.200", "fd00:ec2::254", "169.254.170.2",
))
_BLOCKED_NETS = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
    "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "2001:db8::/32", "100::/64",
))
_NAT64 = ipaddress.ip_network("64:ff9b::/96")


class FetchBlocked(Exception):
    """Policy refused the request. Never retried."""


@dataclass
class FetchResult:
    requested_url: str
    final_url: str | None = None
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    content_type: str | None = None
    body: bytes = b""
    hops: list[RedirectHop] = field(default_factory=list)
    tls_verified: bool = True
    error: str | None = None
    blocked: bool = False

    @property
    def ok(self) -> bool:
        return self.error is None and self.status is not None


@dataclass
class _HopResponse:
    status: int
    headers: dict[str, str]
    body: bytes
    server_ip: str | None
    content_type: str | None


# ---------------- IP / URL policy ----------------

def ip_allowed(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address):
        embedded = ip.ipv4_mapped or ip.sixtofour or (ip.teredo[1] if ip.teredo else None)
        if embedded is None and ip in _NAT64:
            embedded = ipaddress.IPv4Address(ip.packed[-4:])
        if embedded is not None and not ip_allowed(embedded):
            return False
    if ip in _BLOCKED_IPS:
        return False
    if any(ip in n for n in _BLOCKED_NETS if n.version == ip.version):
        return False
    if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
            or ip.is_unspecified or not ip.is_global):
        return False
    return True


def check_url_policy(u: ParsedURL) -> None:
    if u.scheme not in ALLOWED_SCHEMES:
        raise FetchBlocked(f"scheme {u.scheme!r} not allowed")
    if u.port not in ALLOWED_PORTS:
        raise FetchBlocked(f"port {u.port} not allowed")
    if u.ip is not None:
        if u.ip.non_canonical:
            raise FetchBlocked("non-canonical numeric IP host")
        if not ip_allowed(u.ip.ip):
            raise FetchBlocked(f"address {u.ip.ip} is not a public address")
        return
    h = u.host
    if h in _BLOCKED_HOSTNAMES or h.endswith(_BLOCKED_SUFFIXES) or "." not in h:
        raise FetchBlocked(f"hostname {h!r} is internal")


async def _getaddrinfo(host: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [i[4][0] for i in infos]


async def resolve_and_validate(host: str, port: int) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Resolve once; reject if ANY returned address is not public. Raises FetchBlocked."""
    if port not in ALLOWED_PORTS:
        raise FetchBlocked(f"port {port} not allowed")
    try:
        lit = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        lit = None
    if lit is not None:
        if not ip_allowed(lit):
            raise FetchBlocked(f"address {lit} is not a public address")
        return [lit]
    try:
        async with asyncio.timeout(DNS_TIMEOUT_S):
            raw = await _getaddrinfo(host, port)
    except (TimeoutError, OSError) as e:
        raise FetchBlocked(f"DNS resolution failed for {host}: {type(e).__name__}") from e
    addrs = []
    for a in raw:
        ip = ipaddress.ip_address(a.split("%", 1)[0])
        if not ip_allowed(ip):
            raise FetchBlocked(f"{host} resolves to non-public address {ip}")
        addrs.append(ip)
    if not addrs:
        raise FetchBlocked(f"{host} did not resolve")
    return addrs


def _connect_policy(hostname: str, address: ipaddress.IPv4Address | ipaddress.IPv6Address, port: int) -> bool:
    """httpx-secure validator, applied to the exact IP the socket connects to."""
    return port in ALLOWED_PORTS and ip_allowed(address)


def make_client(*, verify: bool) -> httpx.AsyncClient:
    """The ONLY client factory for user targets. Both the verified and the verify=False path use it."""
    client = httpx.AsyncClient(
        trust_env=False,
        follow_redirects=False,
        verify=verify,
        timeout=httpx.Timeout(HOP_TIMEOUT_S),
        limits=httpx.Limits(max_connections=4, max_keepalive_connections=0),
        headers={"User-Agent": USER_AGENT, "Accept-Encoding": "gzip, deflate"},
    )
    return httpx_ssrf_protection(client, custom_validator=_connect_policy, dns_cache_size=0)


# ---------------- one hop ----------------

def _is_tls_verify_error(e: BaseException) -> bool:
    seen = 0
    cur: BaseException | None = e
    while cur is not None and seen < 8:
        if isinstance(cur, ssl.SSLCertVerificationError):
            return True
        if isinstance(cur, ssl.SSLError) and "CERTIFICATE_VERIFY_FAILED" in str(cur):
            return True
        if "CERTIFICATE_VERIFY_FAILED" in str(cur) or "certificate verify failed" in str(cur):
            return True
        cur = cur.__cause__ or cur.__context__
        seen += 1
    return False


def _pinned_request(url: ParsedURL, pinned_ip: str | None, headers: dict[str, str]
                    ) -> tuple[str, dict[str, str], dict[str, str]]:
    """(request URL, headers, extensions). With a pinned IP the URL names the IP, so httpx-secure validates and
    connects to exactly that address (no second lookup and no TCP probe to whatever a rebinding DNS answers next).
    Host header, SNI and certificate hostname checks still use the original hostname."""
    if pinned_ip is None or url.ip is not None:
        return url.url_without_userinfo(), headers, {}
    ip = ipaddress.ip_address(pinned_ip)
    ip_host = f"[{ip}]" if ip.version == 6 else str(ip)
    netloc = f"{ip_host}:{url.port}" if url.explicit_port else ip_host
    target = urlunsplit((url.scheme, netloc, url.path or "/", url.query, ""))
    host_hdr = f"{url.host}:{url.port}" if url.explicit_port else url.host
    ext = {"sni_hostname": url.host} if url.scheme == "https" else {}
    return target, {k: v for k, v in headers.items() if k.lower() != "host"} | {"Host": host_hdr}, ext


async def _send_hop(url: ParsedURL, *, verify: bool, method: str, body: bytes | None,
                    headers: dict[str, str], allowed_types: tuple[str, ...],
                    pinned_ip: str | None = None) -> _HopResponse:
    target, headers, extensions = _pinned_request(url, pinned_ip, headers)
    async with make_client(verify=verify) as client:
        async with client.stream(method, target, headers=headers, content=body, extensions=extensions) as resp:
            server_ip = None
            ns = resp.extensions.get("network_stream")
            if ns is not None:
                addr = ns.get_extra_info("server_addr")
                if addr:
                    server_ip = str(addr[0])
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            if "set-cookie" in hdrs:  # httpx joins repeats with ", ", which cookie Expires dates also contain
                hdrs["set-cookie"] = "\n".join(resp.headers.get_list("set-cookie"))
            ctype = hdrs.get("content-type", "").split(";", 1)[0].strip().lower() or None
            if 300 <= resp.status_code < 400 and "location" in hdrs:
                return _HopResponse(resp.status_code, hdrs, b"", server_ip, ctype)
            if ctype is None or not any(ctype == t for t in allowed_types):
                raise _ContentRejected(f"content type {ctype!r} not inspected", resp.status_code, hdrs,
                                       server_ip, ctype)
            clen = hdrs.get("content-length")
            if clen and clen.isdigit() and int(clen) > MAX_BODY_BYTES:
                raise _ContentRejected("body exceeds 2 MB cap", resp.status_code, hdrs, server_ip, ctype)
            buf = bytearray()
            async for chunk in resp.aiter_bytes():  # decoded bytes: caps decompressed size
                buf.extend(chunk)
                if len(buf) > MAX_BODY_BYTES:
                    raise _ContentRejected("body exceeds 2 MB cap (decoded)", resp.status_code, hdrs,
                                           server_ip, ctype)
            return _HopResponse(resp.status_code, hdrs, bytes(buf), server_ip, ctype)


class _ContentRejected(Exception):
    def __init__(self, msg: str, status: int, headers: dict[str, str], server_ip: str | None,
                 ctype: str | None) -> None:
        super().__init__(msg)
        self.status, self.headers, self.server_ip, self.ctype = status, headers, server_ip, ctype


async def _attempt(url: ParsedURL, *, verify: bool, method: str, body: bytes | None,
                   headers: dict[str, str], allowed_types: tuple[str, ...]) -> tuple[_HopResponse, str | None]:
    """Policy + DNS pre-check + send. Every attempt (including the verify=False retry) runs the full pre-check."""
    check_url_policy(url)
    addrs = await resolve_and_validate(url.host, url.port)
    # Try IPv4 first (IPv6 egress is often missing), at most two addresses, only on plain connect failures.
    candidates = sorted(addrs, key=lambda a: a.version)[:2]
    async with asyncio.timeout(HOP_TIMEOUT_S):
        for i, ip in enumerate(candidates):
            try:
                resp = await _send_hop(url, verify=verify, method=method, body=body, headers=headers,
                                       allowed_types=allowed_types, pinned_ip=str(ip))
                break
            except (httpx.ConnectError, httpx.ConnectTimeout) as e:
                if i == len(candidates) - 1 or _is_tls_verify_error(e):
                    raise
    return resp, (resp.server_ip or str(ip))


# ---------------- public API ----------------

async def safe_fetch(url: str, *, max_hops: int = MAX_HOPS, allowed_types: tuple[str, ...] = TEXT_TYPES,
                     method: str = "GET", body: bytes | None = None,
                     headers: dict[str, str] | None = None) -> FetchResult:
    """Fetch `url` passively. Never raises; problems are reported in FetchResult.error / .blocked."""
    result = FetchResult(requested_url=url)
    req_headers = {"Accept": ", ".join(allowed_types)} | (headers or {})
    try:
        async with asyncio.timeout(TOTAL_TIMEOUT_S):
            await _loop(url, result, max_hops=max_hops, allowed_types=allowed_types, method=method,
                        body=body, headers=req_headers)
    except FetchBlocked as e:
        result.error, result.blocked = f"blocked: {e}", True
    except SSRFProtectionError as e:
        result.error, result.blocked = f"blocked at connect: {e.__class__.__name__}", True
    except TimeoutError:
        result.error = "timeout"
    except URLParseError as e:
        result.error, result.blocked = f"blocked: unparseable URL ({e})", True
    except httpx.HTTPError as e:
        result.error = f"http error: {type(e).__name__}"
    except Exception as e:  # noqa: BLE001 - the fetcher must never raise into a check
        result.error = f"unexpected error: {type(e).__name__}"
    return result


async def _loop(url: str, result: FetchResult, *, max_hops: int, allowed_types: tuple[str, ...], method: str,
                body: bytes | None, headers: dict[str, str]) -> None:
    current = parse_url(url, default_scheme="https")
    prev_reg: str | None = None
    for hop_no in range(max_hops + 1):
        if hop_no == max_hops:
            raise FetchBlocked(f"more than {max_hops} redirects")
        verify = True
        try:
            resp, ip = await _attempt(current, verify=True, method=method, body=body, headers=headers,
                                      allowed_types=allowed_types)
        except _ContentRejected as e:
            _record(result, current, e.status, e.server_ip, prev_reg)
            result.final_url, result.status, result.headers, result.content_type = (
                current.url_without_userinfo(), e.status, e.headers, e.ctype)
            result.error = str(e)
            return
        except (httpx.ConnectError, ssl.SSLError) as e:
            if current.scheme != "https" or not _is_tls_verify_error(e):
                raise
            # Phishing pages often have broken certs. Read the content anyway (TLS checks report the cert);
            # the retry runs the full policy + DNS pre-check again and uses the same pinned client factory.
            verify = False
            try:
                resp, ip = await _attempt(current, verify=False, method=method, body=body, headers=headers,
                                          allowed_types=allowed_types)
            except _ContentRejected as e2:
                _record(result, current, e2.status, e2.server_ip, prev_reg)
                result.final_url, result.status, result.error = current.url_without_userinfo(), e2.status, str(e2)
                result.tls_verified = False
                return
        if not verify:
            result.tls_verified = False
        _record(result, current, resp.status, ip, prev_reg)
        prev_reg = registrable_domain(current.host)
        loc = resp.headers.get("location")
        if 300 <= resp.status < 400 and loc:
            nxt = urljoin(current.url_without_userinfo(), loc.strip())
            current = parse_url(nxt, default_scheme=current.scheme)
            method, body = "GET", None
            continue
        result.final_url = current.url_without_userinfo()
        result.status, result.headers, result.content_type, result.body = (
            resp.status, resp.headers, resp.content_type, resp.body)
        return


def _record(result: FetchResult, url: ParsedURL, status: int, ip: str | None, prev_reg: str | None) -> None:
    reg = registrable_domain(url.host)
    result.hops.append(RedirectHop(url=url.url_without_userinfo(), status_code=status, resolved_ip=ip,
                                   cross_domain=prev_reg is not None and reg != prev_reg))
