"""POSTURE.KNOWN_VULNERABLE_COMPONENT: public version info → OSV advisories (Module 5, "known software vulnerabilities").

Passive: versions come only from what the page fetch already returned (script src file names and CDN paths, the
generator meta tag). Each (ecosystem, package, version) is looked up at api.osv.dev through api_client. A version
we cannot read exactly (major only, or no version) gives no finding. OSV has no ecosystem for web servers (nginx,
Apache httpd) or WordPress core; server banners stay with POSTURE.OUTDATED_SOFTWARE (end-of-life table).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from selectolax.lexbor import LexborHTMLParser

from app.checks.intel.common import cached_json
from app.fetch.api_client import ApiClient

API = "https://api.osv.dev/v1/query"
SOURCE = "osv.dev"
MAX_COMPONENTS = 6
MAX_IDS = 5
_V = r"(\d+\.\d+\.\d+)"
# npm package name -> file-name / CDN-path patterns. Only exact x.y.z versions are accepted.
_JS = {
    "jquery": [rf"/jquery[.-]{_V}(?:\.slim)?(?:\.min)?\.js", rf"/jquery/{_V}/", rf"/jquery@{_V}/"],
    "jquery-ui": [rf"/jquery-ui[.-]{_V}(?:\.min)?\.js", rf"/jqueryui/{_V}/", rf"/jquery-ui@{_V}/"],
    "bootstrap": [rf"/bootstrap[.-]{_V}(?:\.bundle)?(?:\.min)?\.js", rf"/bootstrap/{_V}/", rf"/bootstrap@{_V}/"],
    "angular": [rf"/angular[.-]{_V}(?:\.min)?\.js", rf"/angular\.js/{_V}/", rf"/angular@{_V}/"],
    "lodash": [rf"/lodash[.-]{_V}(?:\.min)?\.js", rf"/lodash\.js/{_V}/", rf"/lodash@{_V}/"],
    "moment": [rf"/moment[.-]{_V}(?:\.min)?\.js", rf"/moment\.js/{_V}/", rf"/moment@{_V}/"],
    "vue": [rf"/vue[.-]{_V}(?:\.min)?\.js", rf"/vue/{_V}/", rf"/vue@{_V}/"],
    "handlebars": [rf"/handlebars[.-]{_V}(?:\.min)?\.js", rf"/handlebars\.js/{_V}/", rf"/handlebars@{_V}/"],
}
_JS_RX = {pkg: [re.compile(p, re.I) for p in pats] for pkg, pats in _JS.items()}
# generator meta content -> (ecosystem, package)
_GENERATORS = [(re.compile(rf"\bDrupal {_V}", re.I), "Packagist", "drupal/core")]


@dataclass(frozen=True)
class Component:
    ecosystem: str
    package: str
    version: str
    where: str  # what we saw, e.g. the script src


def detect(body: bytes) -> list[Component]:
    if not body:
        return []
    try:
        tree = LexborHTMLParser(body.decode("utf-8", errors="replace"))
    except Exception:  # noqa: BLE001
        return []
    out: dict[tuple[str, str], Component] = {}
    for node in tree.css("script[src]"):
        src = (node.attributes.get("src") or "")[:300]
        for pkg, rxs in _JS_RX.items():
            for rx in rxs:
                m = rx.search(src)
                if m:
                    out.setdefault(("npm", pkg), Component("npm", pkg, m.group(1), f"script src {src}"))
                    break
    for node in tree.css('meta[name="generator" i]'):
        content = (node.attributes.get("content") or "")[:200]
        for rx, eco, pkg in _GENERATORS:
            m = rx.search(content)
            if m:
                out.setdefault((eco, pkg), Component(eco, pkg, m.group(1), f'generator meta "{content}"'))
    return list(out.values())[:MAX_COMPONENTS]


async def _query(api: ApiClient, c: Component) -> dict[str, Any]:
    return await api.post_json(API, {"package": {"name": c.package, "ecosystem": c.ecosystem}, "version": c.version})


def summarise(resp: dict[str, Any]) -> list[dict[str, Any]]:
    """[{id, cve, severity}] for each advisory, newest-looking first, capped."""
    out = []
    for v in resp.get("vulns") or []:
        cves = [a for a in v.get("aliases") or [] if a.startswith("CVE-")]
        out.append({"id": v.get("id", "?"), "cve": cves[0] if cves else None,
                    "severity": (v.get("database_specific") or {}).get("severity")})
    return out


async def lookup(ctx, components: list[Component]) -> list[tuple[Component, list[dict[str, Any]]]]:
    """Raises ApiUnavailable if OSV cannot be reached."""
    results = []
    for c in components:
        resp = await cached_json(ctx, SOURCE, f"{c.ecosystem}:{c.package}@{c.version}", lambda api, c=c: _query(api, c))
        advisories = summarise(resp or {})
        if advisories:
            results.append((c, advisories))
    return results
