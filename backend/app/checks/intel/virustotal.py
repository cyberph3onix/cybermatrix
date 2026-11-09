"""URL.INTEL.VT_MAJORITY / VT_MINORITY: VirusTotal v3 URL report lookup. Needs VT_API_KEY.

Lookup only: a URL VirusTotal has never seen is NOT submitted for scanning (that would publish it to a public
corpus, and the free tier allows 4 requests/min). HTTP 429 → `unavailable`.
"""
from __future__ import annotations

import base64
from typing import Any

from app.checks.base import AssessmentContext, CheckResult, evidence, make_finding
from app.checks.intel.common import cached_json, run_intel
from app.fetch.api_client import ApiClient, ApiNotFound, ApiUnavailable
from app.schemas import Finding

GROUP = "intel.virustotal"
SOURCE = "virustotal"
KEY_ENV = "VT_API_KEY"
API = "https://www.virustotal.com/api/v3/urls/"
MAJORITY = 5


def url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


async def _report(api: ApiClient, url: str) -> dict[str, Any]:
    uid = url_id(url)
    try:
        d = await api.get_json(API + uid, headers_env={"x-apikey": KEY_ENV})
    except ApiNotFound:
        return {"found": False}
    try:
        attrs = d["data"]["attributes"]
        stats = attrs["last_analysis_stats"]
        return {"found": True, "malicious": int(stats.get("malicious", 0)), "suspicious": int(stats.get("suspicious", 0)),
                "total": sum(int(v) for v in stats.values()), "last_analysis_date": int(attrs.get("last_analysis_date") or 0),
                "id": uid}
    except (KeyError, TypeError, ValueError):
        raise ApiUnavailable("virustotal: unexpected response") from None


async def lookup(ctx: AssessmentContext, urls: list[str]) -> list[dict[str, Any]]:
    out = []
    for u in urls:
        r = await cached_json(ctx, SOURCE, f"url:{u}", lambda api, u=u: _report(api, u))
        if r["found"] and r["malicious"] >= 1:
            out.append({"url": u, **r})
    return out


def build(ctx: AssessmentContext, hits: list[dict[str, Any]]) -> list[Finding]:
    if not hits:
        return []
    worst = max(h["malicious"] for h in hits)
    check_id = "URL.INTEL.VT_MAJORITY" if worst >= MAJORITY else "URL.INTEL.VT_MINORITY"
    ev = [evidence("ti_match", f"{h['malicious']} of {h['total']} VirusTotal engines flag {h['url']} as malicious",
                   SOURCE, {"url": h["url"], "malicious": h["malicious"], "suspicious": h["suspicious"],
                            "engines_total": h["total"], "last_analysis_date": h["last_analysis_date"],
                            "report": f"https://www.virustotal.com/gui/url/{h['id']}"}, observed_at=ctx.now)
          for h in hits]
    if check_id == "URL.INTEL.VT_MAJORITY":
        return [make_finding(
            check_id, f"{worst} security engines on VirusTotal flag this link as malicious", ev,
            "Many independent security vendors classify this address as malicious.",
            "Do not open the link or enter any information on it.")]
    return [make_finding(
        check_id, f"{worst} security engine(s) on VirusTotal flag this link", ev,
        "A few vendors flag this address; single-engine detections are often false positives.",
        "Treat the link with caution and verify the sender through an official channel.",
        limitation="Fewer than 5 engines flagged it, which is common for false positives.")]


async def run(ctx: AssessmentContext) -> CheckResult:
    return await run_intel(ctx, group=GROUP, source=SOURCE, key_env=KEY_ENV, max_extra=1,
                           lookup=lambda urls: lookup(ctx, urls), build=build)
