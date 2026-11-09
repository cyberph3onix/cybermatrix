"""URL.* structural checks (and DOMAIN.SUSPICIOUS_TLD, which is purely structural). No network."""
from __future__ import annotations

import re
import time
from urllib.parse import parse_qsl, unquote

from confusable_homoglyphs import confusables

from app.brands import BrandIndex
from app.checks.base import AssessmentContext, CheckResult, evidence, make_finding, make_run
from app.schemas import CheckStatus, Finding
from app.urlutil import ParsedURL, URLParseError, parse_url, registrable_domain, split_domain, to_unicode_host

SOURCE = "local:url_structure"
GROUP = "url.structure"
KEYWORDS = ("login", "verify", "kyc", "refund", "update", "secure")
_EMBEDDED_URL = re.compile(r"(?i)(?:^|[^\w])((?:https?:)?//([^/?#\s&\\]+))")


def _ev(kind: str, desc: str, data: dict | None = None, *, url: str) -> list:
    return [evidence(kind, desc, SOURCE, {"url": url} | (data or {}))]


def analyze(u: ParsedURL, idx: BrandIndex) -> list[Finding]:
    out: list[Finding] = []
    url = u.url_without_userinfo()
    host, reg = u.host, registrable_domain(u.host)
    sub, label, suffix = split_domain(host)

    if u.userinfo is not None:
        shown = u.userinfo.split(":", 1)[0]
        out.append(make_finding(
            "URL.USERINFO_TRICK", f"Address hides the real destination behind '{shown}@'",
            _ev("url_component", f"Text before '@' ('{shown}') is ignored by browsers; the real host is {host}",
                {"userinfo": shown, "real_host": host}, url=url),
            "The link appears to point to one site but actually opens another.",
            "Look only at what comes after the '@' sign: that is the real website."))

    if u.ip is not None:
        out.append(make_finding(
            "URL.IP_HOST", "Link uses a raw IP address instead of a domain name",
            _ev("url_component", f"Host is the IP address {u.ip.ip}"
                + (" written in a disguised numeric form" if u.ip.non_canonical else ""),
                {"ip": str(u.ip.ip), "non_canonical": u.ip.non_canonical}, url=url),
            "Legitimate banks and services almost never send links to bare IP addresses.",
            "Do not enter details on sites reached through IP-address links."))

    out += _embedded_redirect(u, reg, url)

    if idx.is_shortener(host):
        out.append(make_finding(
            "URL.SHORTENER", f"Link uses the URL shortener {reg}",
            _ev("url_component", f"{host} is a known URL shortener; the destination is resolved separately",
                {"shortener": host}, url=url),
            "Shorteners hide the final destination until you click.",
            "Check where the link really leads (shown in the redirect chain) before opening it."))

    kw = _keywords(u)
    if kw:
        out.append(make_finding(
            "URL.KEYWORDS", "Address contains words common in phishing links",
            _ev("url_component", f"Found: {', '.join(kw)}", {"keywords": kw}, url=url),
            "Phishing links often use words like 'verify' or 'kyc' to create urgency.",
            "Words in a link prove nothing on their own; weigh this with the other findings."))

    f = _brand_in_subdomain(u, idx, sub, reg, url)
    if f:
        out.append(f)

    mixed = _mixed_script_labels(host)
    if mixed:
        out.append(make_finding(
            "URL.PUNYCODE_MIXED_SCRIPT", "Domain mixes characters from different alphabets",
            _ev("url_component", f"Label(s) {', '.join(mixed)} mix scripts (e.g. Latin and Cyrillic)",
                {"labels": mixed, "ascii_host": host}, url=url),
            "Mixed alphabets are used to make a fake domain look identical to a real one.",
            "Type the official address yourself instead of following this link."))

    tld = suffix.rsplit(".", 1)[-1] if suffix else ""
    if tld and tld in idx.suspicious_tlds:
        out.append(make_finding(
            "DOMAIN.SUSPICIOUS_TLD", f"Domain uses the .{tld} ending, which is heavily abused",
            _ev("url_component", f"Top-level domain .{tld} is on our curated abuse-heavy list", {"tld": tld},
                url=url),
            "Cheap, lightly-policed domain endings attract a lot of phishing.",
            "This is a weak signal; many legitimate sites use these endings too."))
    return out


def _embedded_redirect(u: ParsedURL, reg: str, url: str) -> list[Finding]:
    for key, value in parse_qsl(u.query, keep_blank_values=True):
        v = value
        for _ in range(2):
            v2 = unquote(v)
            if v2 == v:
                break
            v = v2
        m = _EMBEDDED_URL.search(v)
        if not m:
            continue
        target = m.group(1)
        if target.startswith("//"):
            target = "https:" + target
        try:
            t = parse_url(target)
        except URLParseError:
            continue
        treg = registrable_domain(t.host)
        if "." in t.host and treg != reg:
            return [make_finding(
                "URL.EMBEDDED_REDIRECT_PARAM", f"Link carries a hidden onward address to {treg}",
                _ev("url_component", f"Query parameter '{key}' contains a URL on {treg}",
                    {"param": key, "embedded_domain": treg}, url=url),
                "Open-redirect links borrow a trusted domain's name to send you somewhere else.",
                "Treat the embedded destination as the real one.")]
    return []


def _keywords(u: ParsedURL) -> list[str]:
    tokens = set(re.split(r"[^a-z0-9]+", (u.host + " " + unquote(u.path)).lower()))
    return [k for k in KEYWORDS if k in tokens]


def _brand_in_subdomain(u: ParsedURL, idx: BrandIndex, sub: str, reg: str, url: str) -> Finding | None:
    if idx.official.get(reg):
        return None
    sub_l = sub.lower()
    path_l = unquote(u.path).lower()
    # The brand's own top-10k site under its own label (outlook.office365.com) isn't using someone else's name.
    own_label = split_domain(u.host)[1].lower() if idx.allowlisted(u.host, u.path or "/") else None
    for b in idx.brands:
        if own_label in b.labels:
            continue
        for d in b.official_domains:
            if sub_l and re.search(r"(?:^|\.)" + re.escape(d) + r"(?:\.|$)", sub_l):
                return _bis(b.name, d, "subdomain", reg, url)
        tokens = [t for t in sub_l.split(".") if t and t != "www"]
        for t in tokens:
            parts = re.split(r"[-_]", t)
            for lbl in b.labels:
                if t == lbl or lbl in parts:
                    return _bis(b.name, lbl, "subdomain", reg, url)
    for b in idx.brands:
        for d in b.official_domains:
            if re.search(r"(?:^|[^a-z0-9-])" + re.escape(d) + r"(?:[^a-z0-9-]|$)", path_l):
                return _bis(b.name, d, "path", reg, url)
    return None


def _bis(brand: str, matched: str, where: str, reg: str, url: str) -> Finding:
    return make_finding(
        "URL.BRAND_IN_SUBDOMAIN",
        f"{brand} name used in the {where} of an unrelated site",
        _ev("url_component", f"'{matched}' appears in the {where}; the real registrable domain is '{reg}'",
            {"brand": brand, "matched": matched, "match_location": where, "registrable_domain": reg}, url=url),
        f"People reading the link may believe it belongs to {brand}.",
        f"Type {brand}'s address yourself instead of following links.")


def _mixed_script_labels(host: str) -> list[str]:
    out = []
    for lbl in to_unicode_host(host).split("."):
        if lbl.isascii():
            continue
        if confusables.is_mixed_script(lbl, allowed_aliases=["COMMON"]):
            out.append(lbl)
    return out


async def run(ctx: AssessmentContext, url: ParsedURL | None = None) -> CheckResult:
    t0 = time.monotonic()
    try:
        findings = analyze(url or ctx.url, ctx.brands)
    except Exception as e:  # noqa: BLE001 - checks never raise
        return make_run(GROUP, CheckStatus.FAILED, SOURCE, t0, f"error: {type(e).__name__}"), []
    return make_run(GROUP, CheckStatus.COMPLETED, SOURCE, t0), findings
