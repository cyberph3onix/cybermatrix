"""URL.INTEL.GSB: Google Safe Browsing v5 `urls.search`. Missing key or HTTP 429 → group `unavailable`.

Note: v5 urls.search sends the full URL to Google (non-commercial use only). See docs/DECISIONS.md for the
`hashes.search` roadmap item that would send only hash prefixes.
"""
from __future__ import annotations

from typing import Any

from app.checks.base import AssessmentContext, CheckResult, evidence, make_finding
from app.checks.intel.common import cached_json, run_intel
from app.fetch.api_client import ApiClient, ApiUnavailable
from app.schemas import Finding

GROUP = "intel.gsb"
SOURCE = "google_safe_browsing"
KEY_ENV = "GSB_API_KEY"
SEARCH = "https://safebrowsing.googleapis.com/v5/urls:search"
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


async def _search(api: ApiClient, urls: list[str]) -> list[dict[str, Any]]:
    body = await api.get_bytes(SEARCH, params=[("urls", u) for u in urls], headers_env={"x-goog-api-key": KEY_ENV})
    try:
        return parse_search_response(body)
    except ValueError:  # includes JSONDecodeError
        raise ApiUnavailable("google_safe_browsing: unexpected response") from None


async def lookup(ctx: AssessmentContext, urls: list[str]) -> list[dict[str, Any]]:
    key = "\n".join(sorted(urls))
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
