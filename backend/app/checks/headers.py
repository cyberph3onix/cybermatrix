"""POSTURE.* checks: HTTP security-header and TLS-hygiene findings (group posture.headers).

These go to `security_posture` and never feed the phishing classification (CLAUDE.md rule 10): plenty of
legitimate sites lack a CSP, and plenty of phishing pages have a perfect one. Passive: only the headers and body
that safe_fetch already retrieved are inspected.

POSTURE.EXPOSED_FILE makes two extra GETs (/.git/HEAD, /.env) through safe_fetch and ONLY when the user ticked
"I own this site" (ctx.owns_site). Evidence never contains file contents beyond the git ref line.
"""
from __future__ import annotations

import asyncio
import re
import time

from selectolax.lexbor import LexborHTMLParser

from app.checks.base import AssessmentContext, CheckResult, evidence, make_finding, make_run
from app.checks.tls_chain import _target
from app.fetch.safe_fetch import safe_fetch
from app.schemas import CheckStatus, Finding
from app.urlutil import URLParseError, parse_url

GROUP = "posture.headers"
SOURCE = "local:header_inspector"
LIMITATION = "Security-posture finding: reported for information and not used in the risk classification."
_VERSIONED = re.compile(r"\d+\.\d+")
_OLD_TLS = ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1")
_SUBRESOURCES = (("script", "src"), ("link[rel~=stylesheet]", "href"), ("iframe", "src"), ("img", "src"),
                 ("audio", "src"), ("video", "src"), ("source", "src"), ("embed", "src"), ("object", "data"))
MAX_LISTED = 5

_HEADER_FINDINGS = (
    ("POSTURE.NO_HSTS", "strict-transport-security", "No HSTS header",
     "Browsers aren't told to insist on HTTPS for this site, so a first visit can be downgraded.",
     "Send Strict-Transport-Security with a long max-age."),
    ("POSTURE.NO_CSP", "content-security-policy", "No Content-Security-Policy header",
     "Without a CSP, an injected script runs with the full privileges of the page.",
     "Define a Content-Security-Policy that limits script and frame sources."),
    ("POSTURE.NO_XFO", "x-frame-options", "No clickjacking protection (X-Frame-Options / frame-ancestors)",
     "Another site can embed this page in a frame and trick visitors into clicking hidden controls.",
     "Send X-Frame-Options: DENY (or CSP frame-ancestors)."),
    ("POSTURE.NO_XCTO", "x-content-type-options", "No X-Content-Type-Options: nosniff",
     "Browsers may guess content types, which can turn uploaded files into executable scripts.",
     "Send X-Content-Type-Options: nosniff."),
)


def mixed_content(body: bytes, base_url: str) -> list[str]:
    """http:// subresources on an https page (active and passive)."""
    try:
        tree = LexborHTMLParser(body.decode("utf-8", errors="replace"))
    except Exception:  # noqa: BLE001
        return []
    found: list[str] = []
    for selector, attr in _SUBRESOURCES:
        for node in tree.css(selector):
            v = (node.attributes.get(attr) or "").strip()
            if v.lower().startswith("http://") and v not in found:
                found.append(v)
    return found


def analyze(headers: dict[str, str], final_url: str, body: bytes, content_type: str | None, tls_version: str | None,
            now) -> list[Finding]:
    h = {k.lower(): v for k, v in headers.items()}
    try:
        https = parse_url(final_url).scheme == "https"
    except URLParseError:
        return []
    out: list[Finding] = []

    def add(check_id: str, title: str, desc: str, data: dict, impact: str, rec: str) -> None:
        out.append(make_finding(check_id, title, [evidence("http_header", desc, SOURCE, data, observed_at=now)],
                                impact, rec, limitation=LIMITATION))

    csp = h.get("content-security-policy", "")
    for check_id, header, title, impact, rec in _HEADER_FINDINGS:
        if check_id == "POSTURE.NO_HSTS" and not https:
            continue
        if check_id == "POSTURE.NO_XCTO":
            missing = h.get(header, "").lower().strip() != "nosniff"
        elif check_id == "POSTURE.NO_XFO":
            missing = header not in h and "frame-ancestors" not in csp.lower()
        else:
            missing = header not in h
        if missing:
            add(check_id, title, f"Response from {final_url} has no {header} header (or an ineffective one)",
                {"header": header, "url": final_url}, impact, rec)

    if https and body and (content_type or "").startswith("text/html"):
        mixed = mixed_content(body, final_url)
        if mixed:
            add("POSTURE.MIXED_CONTENT", f"Page loads {len(mixed)} resource(s) over plain HTTP",
                f"{len(mixed)} http:// subresource(s) on an https page, e.g. {mixed[0]}",
                {"count": len(mixed), "examples": mixed[:MAX_LISTED]},
                "Attackers on the network can modify what those resources deliver.",
                "Serve every resource over HTTPS.")

    if tls_version in _OLD_TLS:
        add("POSTURE.OLD_TLS_VERSION", f"Best TLS version offered is {tls_version}",
            f"The highest TLS version the server negotiates is {tls_version}", {"tls_version": tls_version},
            "Protocols older than TLS 1.2 have known weaknesses and are rejected by modern browsers.",
            "Enable TLS 1.2 and 1.3 and disable older versions.")

    for banner in ("server", "x-powered-by", "x-aspnet-version"):
        v = h.get(banner)
        if v and _VERSIONED.search(v):
            add("POSTURE.SERVER_BANNER_VERSION", f"Server announces its software version ({banner}: {v[:60]})",
                f"{banner} header discloses a version number", {"header": banner, "value": v[:100]},
                "Version banners help attackers pick known exploits for outdated software.",
                "Remove version numbers from response headers.")
            break
    return out


_ENV_LINE = re.compile(r"^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=", re.M)


async def exposed_files(ctx: AssessmentContext, origin: str) -> list[Finding]:
    fetch = ctx.fetcher or safe_fetch
    out: list[Finding] = []
    for path, kind in (("/.git/HEAD", "git"), ("/.env", "env")):
        try:
            fr = await fetch(origin + path)
        except Exception:  # noqa: BLE001
            continue
        if fr.status != 200 or not fr.body:
            continue
        text = fr.body[:4096].decode("utf-8", errors="replace")
        if kind == "git" and text.startswith("ref: refs/"):
            desc, data = f"{path} is publicly readable: {text.splitlines()[0][:80]}", {"path": path}
        elif kind == "env" and len(_ENV_LINE.findall(text)) >= 2 and "<html" not in text[:200].lower():
            desc, data = f"{path} is publicly readable ({len(_ENV_LINE.findall(text))} KEY=value lines; contents not stored)", {"path": path}
        else:
            continue
        out.append(make_finding("POSTURE.EXPOSED_FILE", f"{path} is exposed on your site",
                                [evidence("http_header", desc, SOURCE, data, observed_at=ctx.now)],
                                "Anyone can download this file, which can leak source code history or secrets.",
                                "Block access to dotfiles in the web server and rotate any secrets it contained.",
                                limitation=LIMITATION))
    return out


async def run(ctx: AssessmentContext) -> CheckResult:
    t0 = time.monotonic()
    try:
        fr = await ctx.fetch()
        if fr.status is None or not fr.final_url:
            return make_run(GROUP, CheckStatus.FAILED, SOURCE, t0, f"fetch did not complete: {fr.error}"), []
        tls_version = None
        if parse_url(fr.final_url).scheme == "https":
            try:
                _, host, port = await _target(ctx)
                tls_version = (await asyncio.wait_for(ctx.tls_scan(host, port), 35)).tls_version
            except Exception:  # noqa: BLE001
                tls_version = None  # TLS posture just isn't assessed
        findings = analyze(fr.headers, fr.final_url, fr.body, fr.content_type, tls_version, ctx.now)
        if ctx.owns_site:
            fp = parse_url(fr.final_url)
            findings += await exposed_files(ctx, f"{fp.scheme}://{fp.host}" + (f":{fp.port}" if fp.explicit_port else ""))
        return make_run(GROUP, CheckStatus.COMPLETED, SOURCE, t0), findings
    except Exception as e:  # noqa: BLE001
        return make_run(GROUP, CheckStatus.FAILED, SOURCE, t0, f"error: {type(e).__name__}"), []
