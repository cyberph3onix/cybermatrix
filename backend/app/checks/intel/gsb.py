"""URL.INTEL.GSB: Google Safe Browsing v5. Missing key or HTTP 429 → group `unavailable`.

Default mode `hashes` (privacy-preserving): the URL is canonicalised and expanded into the host-suffix / path-prefix
expressions defined by the Safe Browsing spec, each expression is SHA-256 hashed, and only the 4-byte prefixes are
sent to `hashes.search`. Google returns full hashes for those prefixes and we match them locally, so Google never
sees the URL. `GSB_MODE=urls` switches to `urls.search`, which sends full URLs (simpler, but less private). There is
deliberately no automatic fallback from hashes to urls: it would leak exactly the URLs that hit an error.
Safe Browsing is licensed for non-commercial use.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import os
import re
from typing import Any
from urllib.parse import unquote, urlsplit

from app.checks.base import AssessmentContext, CheckResult, evidence, make_finding
from app.checks.intel.common import cached_json, run_intel
from app.fetch.api_client import ApiClient, ApiUnavailable
from app.schemas import Finding

GROUP = "intel.gsb"
SOURCE = "google_safe_browsing"
KEY_ENV = "GSB_API_KEY"
SEARCH = "https://safebrowsing.googleapis.com/v5/urls:search"
HASHES = "https://safebrowsing.googleapis.com/v5/hashes:search"
MAX_EVIDENCE = 5
THREAT_LABELS = {
    "MALWARE": "malware",
    "SOCIAL_ENGINEERING": "phishing / social engineering",
    "UNWANTED_SOFTWARE": "unwanted software",
    "POTENTIALLY_HARMFUL_APPLICATION": "potentially harmful application",
}


# v5 enum numbers (ThreatType). The live service answers in binary protobuf and rejects alt=json.
THREAT_ENUM = {1: "MALWARE", 2: "SOCIAL_ENGINEERING", 3: "UNWANTED_SOFTWARE", 4: "POTENTIALLY_HARMFUL_APPLICATION"}


def _varint(b: bytes, i: int) -> tuple[int, int]:
    n = shift = 0
    while True:
        if i >= len(b) or shift > 63:
            raise ValueError("bad varint")
        c = b[i]
        i += 1
        n |= (c & 0x7F) << shift
        if not c & 0x80:
            return n, i
        shift += 7


def _fields(b: bytes):
    """Yield (field_number, wire_type, value) for a protobuf message; value is int or bytes."""
    i = 0
    while i < len(b):
        tag, i = _varint(b, i)
        num, wt = tag >> 3, tag & 7
        if wt == 0:
            v, i = _varint(b, i)
        elif wt == 2:
            n, i = _varint(b, i)
            if i + n > len(b):
                raise ValueError("truncated")
            v, i = b[i:i + n], i + n
        else:
            raise ValueError("unsupported wire type")
        yield num, wt, v


def parse_search_response(body: bytes) -> list[dict[str, Any]]:
    """SearchUrlsResponse: threats = field 1 (ThreatUrl: url = 1, threat_types = 2, packed or not)."""
    if body[:1] == b"{":  # JSON form, in case Google starts honouring it
        import json
        data = json.loads(body)
        return [{"url": t.get("url", ""), "threat_types": sorted(t.get("threatTypes") or [])}
                for t in data.get("threats") or [] if isinstance(t, dict)]
    out = []
    for num, wt, v in _fields(body):
        if num != 1 or wt != 2:
            continue
        url, kinds = "", set()
        for n2, w2, v2 in _fields(v):
            if n2 == 1 and w2 == 2:
                url = v2.decode("utf-8", "replace")
            elif n2 == 2 and w2 == 0:
                kinds.add(THREAT_ENUM.get(v2, f"THREAT_{v2}"))
            elif n2 == 2 and w2 == 2:
                j = 0
                while j < len(v2):
                    k, j = _varint(v2, j)
                    kinds.add(THREAT_ENUM.get(k, f"THREAT_{k}"))
        out.append({"url": url, "threat_types": sorted(kinds)})
    return out


# ---------- hashes.search: canonicalisation and expressions (Safe Browsing URL hashing spec) ----------

def _unescape(s: str) -> str:
    for _ in range(10):  # repeatedly percent-unescape until stable
        u = unquote(s, errors="surrogateescape")
        if u == s:
            break
        s = u
    return s


def _escape(s: str) -> str:
    """Percent-escape bytes <= 0x20, >= 0x7F, '#' and '%' (uppercase hex)."""
    out = []
    for b in s.encode("utf-8", "surrogateescape"):
        out.append(f"%{b:02X}" if b <= 0x20 or b >= 0x7F or b in (0x23, 0x25) else chr(b))
    return "".join(out)


def _canon_host(host: str) -> str:
    host = _unescape(host).strip(".").lower()
    host = re.sub(r"\.{2,}", ".", host)
    try:
        if re.fullmatch(r"(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+)){0,3}", host):
            parts = [int(p, 16) if p.startswith("0x") else int(p, 8) if len(p) > 1 and p.startswith("0") else int(p)
                     for p in host.split(".")]
            n = 0
            for p in parts[:-1]:
                n = (n << 8) | (p & 0xFF)
            n = (n << (8 * (5 - len(parts)))) | parts[-1] if len(parts) < 4 else (n << 8) | (parts[-1] & 0xFF)
            host = str(ipaddress.IPv4Address(n & 0xFFFFFFFF))
    except (ValueError, ipaddress.AddressValueError):
        pass
    try:
        host = host.encode("idna").decode("ascii") if not host.isascii() else host
    except UnicodeError:
        pass
    return _escape(host)


def _canon_path(path: str) -> str:
    path = _unescape(path) or "/"
    segs: list[str] = []
    for seg in path.split("/"):
        if seg == "..":
            if segs:
                segs.pop()
        elif seg not in (".", ""):
            segs.append(seg)
    out = "/" + "/".join(segs)
    if path.endswith("/") and out != "/":
        out += "/"
    return _escape(out)


def canonicalize(url: str) -> tuple[str, str, str | None]:
    """(host, path, query-or-None) per the Safe Browsing canonicalisation rules."""
    url = re.sub(r"[\t\r\n]", "", url.strip())
    if "://" not in url:
        url = "http://" + url
    url = url.split("#", 1)[0]
    parts = urlsplit(url)
    host = parts.hostname or ""
    query = parts.query if "?" in url else None
    return _canon_host(host), _canon_path(parts.path), (_escape(_unescape(query)) if query is not None else None)


def expressions(url: str) -> list[str]:
    """Up to 5 host suffixes × up to 6 path prefixes, e.g. a.b.c/1/2.html?x=1 → a.b.c/1/2.html?x=1, …, b.c/."""
    host, path, query = canonicalize(url)
    hosts = [host]
    try:
        ipaddress.ip_address(host)
    except ValueError:
        labels = host.split(".")
        start = max(1, len(labels) - 5)
        hosts += [".".join(labels[i:]) for i in range(start, len(labels) - 1)]
    paths = [path + "?" + query] if query is not None else []
    paths.append(path)
    comps = [c for c in path.split("/") if c]
    prefixes = ["/"] + ["/" + "/".join(comps[:i]) + "/" for i in range(1, min(len(comps), 4))]
    paths += [p for p in prefixes if p not in paths]
    seen, out = set(), []
    for h in dict.fromkeys(hosts):
        for p in paths[:6]:
            e = h + p
            if e not in seen:
                seen.add(e)
                out.append(e)
    return out[:30]


def parse_full_hashes(body: bytes) -> list[tuple[bytes, list[str]]]:
    """SearchHashesResponse: full_hashes = field 1 (FullHash: full_hash = 1,
    full_hash_details = 2 (FullHashDetail: threat_type = 1))."""
    out = []
    for num, wt, v in _fields(body):
        if num != 1 or wt != 2:
            continue
        full, kinds = b"", set()
        for n2, w2, v2 in _fields(v):
            if n2 == 1 and w2 == 2:
                full = v2
            elif n2 == 2 and w2 == 2:
                for n3, w3, v3 in _fields(v2):
                    if n3 == 1 and w3 == 0:
                        kinds.add(THREAT_ENUM.get(v3, f"THREAT_{v3}"))
        out.append((full, sorted(kinds)))
    return out


async def _search_hashes(api: ApiClient, urls: list[str]) -> list[dict[str, Any]]:
    by_hash: dict[bytes, tuple[str, str]] = {}  # full hash -> (url, expression)
    for u in urls:
        for e in expressions(u):
            by_hash.setdefault(hashlib.sha256(e.encode()).digest(), (u, e))
    prefixes = sorted({h[:4] for h in by_hash})
    body = await api.get_bytes(HASHES, params=[("hashPrefixes", base64.b64encode(p).decode()) for p in prefixes],
                               headers_env={"x-goog-api-key": KEY_ENV})
    try:
        full = parse_full_hashes(body)
    except ValueError:
        raise ApiUnavailable("google_safe_browsing: unexpected response") from None
    hits: dict[str, set[str]] = {}
    for h, kinds in full:
        if h in by_hash and kinds:  # only an exact full-hash match counts; a prefix collision is not a hit
            url, expr = by_hash[h]
            hits.setdefault(url, set()).update(kinds)
    return [{"url": u, "threat_types": sorted(k), "method": "hash_prefix"} for u, k in hits.items()]


def mode() -> str:
    return "urls" if os.environ.get("GSB_MODE", "hashes").lower() == "urls" else "hashes"


async def _search(api: ApiClient, urls: list[str]) -> list[dict[str, Any]]:
    if mode() == "hashes":
        return await _search_hashes(api, urls)
    return await _search_urls(api, urls)


async def _search_urls(api: ApiClient, urls: list[str]) -> list[dict[str, Any]]:
    body = await api.get_bytes(SEARCH, params=[("urls", u) for u in urls], headers_env={"x-goog-api-key": KEY_ENV})
    try:
        return parse_search_response(body)
    except ValueError:  # includes JSONDecodeError
        raise ApiUnavailable("google_safe_browsing: unexpected response") from None


async def lookup(ctx: AssessmentContext, urls: list[str]) -> list[dict[str, Any]]:
    key = mode() + "\n" + "\n".join(sorted(urls))
    return await cached_json(ctx, SOURCE, key, lambda api: _search(api, urls))


def build(ctx: AssessmentContext, hits: list[dict[str, Any]]) -> list[Finding]:
    hits = [h for h in hits if h["threat_types"]]
    if not hits:
        return []
    kinds = sorted({THREAT_LABELS.get(t, t.lower()) for h in hits for t in h["threat_types"]})
    ev = [evidence("ti_match", f"Google Safe Browsing lists {h['url']} as: "
                   + ", ".join(THREAT_LABELS.get(t, t.lower()) for t in h["threat_types"]),
                   SOURCE, {"url": h["url"], "threat_types": h["threat_types"]}, observed_at=ctx.now)
          for h in hits[:MAX_EVIDENCE]]
    return [make_finding(
        "URL.INTEL.GSB", f"Google Safe Browsing flags this link ({', '.join(kinds)})", ev,
        "Google's Safe Browsing service has classified this address (or a page on its host) as dangerous.",
        "Do not open the link or enter any information on it.")]


async def run(ctx: AssessmentContext) -> CheckResult:
    return await run_intel(ctx, group=GROUP, source=SOURCE, key_env=KEY_ENV, max_extra=10,
                           lookup=lambda urls: lookup(ctx, urls), build=build)
