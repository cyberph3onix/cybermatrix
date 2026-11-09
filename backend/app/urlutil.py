"""URL parsing helpers shared by safe_fetch and the URL checks.

Parsing is WHATWG-flavoured where it matters for phishing: backslashes in special schemes are treated as `/`,
userinfo is split out, the host is IDNA-normalised, and numeric IPv4 shorthands (decimal, octal, hex) are
recognised the way browsers and `inet_aton` recognise them.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from functools import cache
from urllib.parse import urlsplit, urlunsplit

import idna
import tldextract

DEFAULT_PORTS = {"http": 80, "https": 443}

# Suffixes the bundled PSL snapshot may lack. bank.in is the RBI-mandated bank namespace.
_EXTRA_SUFFIXES = ["bank.in"]


class URLParseError(ValueError):
    pass


@dataclass(frozen=True)
class IPLiteral:
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    non_canonical: bool  # e.g. 2130706433, 0177.0.0.1, 0x7f.1


@dataclass(frozen=True)
class ParsedURL:
    raw: str
    scheme: str
    host: str  # lowercase, IDNA (A-label) form, no brackets
    port: int  # effective port
    explicit_port: bool
    userinfo: str | None
    path: str
    query: str
    fragment: str
    ip: IPLiteral | None

    @property
    def unicode_host(self) -> str:
        return to_unicode_host(self.host)

    @property
    def registrable(self) -> str:
        return registrable_domain(self.host)

    def url_without_userinfo(self) -> str:
        host = f"[{self.host}]" if self.ip and self.ip.ip.version == 6 else self.host
        netloc = f"{host}:{self.port}" if self.explicit_port else host
        return urlunsplit((self.scheme, netloc, self.path or "/", self.query, ""))


_NUMERIC_HOST = re.compile(r"^(0x[0-9a-f]*|[0-9]+)(\.(0x[0-9a-f]*|[0-9]+)){0,3}\.?$", re.IGNORECASE)


def parse_ip_literal(host: str) -> IPLiteral | None:
    h = host.strip().lower()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    try:
        return IPLiteral(ipaddress.ip_address(h), non_canonical=False)
    except ValueError:
        pass
    if _NUMERIC_HOST.match(h):
        try:
            packed = socket.inet_aton(h.rstrip("."))
        except OSError:
            return None
        return IPLiteral(ipaddress.IPv4Address(packed), non_canonical=True)
    return None


def to_ascii_host(host: str) -> str:
    host = host.strip().rstrip(".").lower()
    if not host:
        raise URLParseError("empty host")
    if all(ord(c) < 128 for c in host):
        return host
    try:
        return idna.encode(host, uts46=True).decode("ascii")
    except idna.IDNAError:
        # Fall back to per-label punycode so mixed-script junk is still analysable.
        try:
            return ".".join(
                lbl if lbl.isascii() else "xn--" + lbl.encode("punycode").decode("ascii")
                for lbl in host.split(".")
            )
        except Exception as e:  # noqa: BLE001
            raise URLParseError(f"bad host: {e}") from e


def to_unicode_host(host: str) -> str:
    out = []
    for lbl in host.split("."):
        if lbl.startswith("xn--"):
            try:
                out.append(lbl[4:].encode("ascii").decode("punycode"))
                continue
            except Exception:  # noqa: BLE001
                pass
        out.append(lbl)
    return ".".join(out)


def parse_url(raw: str, *, default_scheme: str = "https") -> ParsedURL:
    s = raw.strip()
    if not s:
        raise URLParseError("empty URL")
    if "://" not in s and not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", s):
        s = f"{default_scheme}://{s}"
    scheme = s.split(":", 1)[0].lower()
    if scheme in DEFAULT_PORTS:
        head, sep, rest = s.partition("://")
        s = head + sep + rest.replace("\\", "/")
    try:
        parts = urlsplit(s)
    except ValueError as e:
        raise URLParseError(str(e)) from e
    netloc = parts.netloc
    userinfo = None
    if "@" in netloc:
        userinfo, _, netloc = netloc.rpartition("@")
    hostport = netloc
    explicit_port = False
    port: int | None = None
    if hostport.startswith("["):
        end = hostport.find("]")
        if end < 0:
            raise URLParseError("unterminated IPv6 literal")
        host = hostport[1:end]
        rest = hostport[end + 1 :]
        if rest.startswith(":") and rest[1:]:
            port, explicit_port = _port(rest[1:]), True
    else:
        host, sep, p = hostport.rpartition(":") if hostport.count(":") == 1 else (hostport, "", "")
        if not sep:
            host = hostport
        elif p:
            port, explicit_port = _port(p), True
    if not host:
        raise URLParseError("missing host")
    ip = parse_ip_literal(host)
    host_norm = str(ip.ip) if ip and not ip.non_canonical else to_ascii_host(host)
    if port is None:
        port = DEFAULT_PORTS.get(scheme, 0)
    return ParsedURL(
        raw=raw,
        scheme=scheme,
        host=host_norm,
        port=port,
        explicit_port=explicit_port,
        userinfo=userinfo,
        path=parts.path,
        query=parts.query,
        fragment=parts.fragment,
        ip=ip,
    )


def _port(p: str) -> int:
    if not p.isdigit() or not (0 < int(p) < 65536):
        raise URLParseError(f"bad port {p!r}")
    return int(p)


@cache
def _extractor() -> tldextract.TLDExtract:
    return tldextract.TLDExtract(
        include_psl_private_domains=True, suffix_list_urls=(), cache_dir=None, extra_suffixes=_EXTRA_SUFFIXES
    )


@cache
def _icann_extractor() -> tldextract.TLDExtract:
    return tldextract.TLDExtract(
        include_psl_private_domains=False, suffix_list_urls=(), cache_dir=None, extra_suffixes=_EXTRA_SUFFIXES
    )


def icann_registrable_domain(host: str) -> str:
    """eTLD+1 over ICANN suffixes only, i.e. the domain someone actually registered. For `x.appspot.com` or
    `me.github.io` this is `appspot.com` / `github.io`, which is what RDAP knows about."""
    if parse_ip_literal(host):
        return host
    r = _icann_extractor()(host)
    return f"{r.domain}.{r.suffix}" if r.domain and r.suffix else host


def split_domain(host: str) -> tuple[str, str, str]:
    """(subdomain, domain_label, suffix)."""
    r = _extractor()(host)
    return r.subdomain, r.domain, r.suffix


def registrable_domain(host: str) -> str:
    """eTLD+1 using the PSL including private domains. IPs and bare suffixes return the host itself."""
    if parse_ip_literal(host):
        return host
    r = _extractor()(host)
    if r.domain and r.suffix:
        return f"{r.domain}.{r.suffix}"
    return host
