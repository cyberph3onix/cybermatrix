"""PAGE.* checks on the fetched HTML. Static parsing only (selectolax); scripts are never executed.

The claimed brand comes from identity signals only: og:site_name, logo alt text and the site-name segment of
<title> (after the last | – — separator, or the whole title). Headlines and body text don't count, so a news
article about SBI with a site login box is not "claiming to be SBI".
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin

from selectolax.lexbor import LexborHTMLParser

from app.brands import Brand, BrandIndex
from app.checks.base import AssessmentContext, CheckResult, evidence, make_finding, make_run
from app.schemas import CheckStatus, Finding
from app.urlutil import URLParseError, parse_url, registrable_domain

SOURCE = "local:page_inspector"
GROUP = "page.content"
_TITLE_SEP = re.compile(r"\s*[|–—]\s*")
_SENSITIVE = re.compile(
    r"\b(otp|mpin|cvv|cvc|password|passwd|passcode|pwd|one time (?:password|code)|card (?:no|num|number)|"
    r"cc (?:number|csc)|debit card|credit card|atm pin|upi pin|tpin|ipin)\b|\bpin\b(?! ?code)")


@dataclass
class PageFacts:
    title: str | None = None
    identity: dict[str, str] = field(default_factory=dict)  # signal name -> text
    sensitive_fields: list[str] = field(default_factory=list)
    form_actions: list[tuple[str, list[str]]] = field(default_factory=list)  # (resolved action, fields)


def _norm(v: str | None) -> str:
    return re.sub(r"([a-z])([A-Z])", r"\1 \2", v or "").replace("_", " ").replace("-", " ").replace(".", " ").lower()


def _field_kind(node) -> str | None:
    a = node.attributes
    t = (a.get("type") or "").lower()
    if t == "password":
        return "password"
    if (a.get("autocomplete") or "").lower() in ("one-time-code", "cc-number", "cc-csc", "current-password"):
        return (a.get("autocomplete") or "").lower()
    if t in ("hidden", "submit", "button", "checkbox", "radio", "image", "reset", "file"):
        return None
    for attr in ("name", "id", "placeholder", "aria-label"):
        m = _SENSITIVE.search(_norm(a.get(attr)))
        if m:
            return m.group(0)
    return None


def extract(html: str, page_url: str) -> PageFacts:
    tree = LexborHTMLParser(html)
    facts = PageFacts()
    base = page_url
    b = tree.css_first("base[href]")
    if b is not None:
        base = urljoin(page_url, b.attributes.get("href") or "")
    t = tree.css_first("title")
    if t is not None:
        facts.title = " ".join(t.text().split())[:300]
        parts = [p for p in _TITLE_SEP.split(facts.title) if p]
        if parts:
            facts.identity["title_site_name"] = parts[-1]
    for m in tree.css("meta"):
        prop = (m.attributes.get("property") or m.attributes.get("name") or "").lower()
        if prop == "og:site_name" and m.attributes.get("content"):
            facts.identity["og:site_name"] = m.attributes["content"].strip()[:200]
    alts = []
    for img in tree.css("img[alt]"):
        a = img.attributes
        hint = " ".join(filter(None, (a.get("src"), a.get("class"), a.get("id")))).lower()
        if "logo" in hint or "logo" in (a.get("alt") or "").lower():
            alts.append((a.get("alt") or "").strip())
    if alts:
        facts.identity["logo_alt"] = " / ".join(x for x in alts if x)[:300]

    in_form: set[int] = set()
    for form in tree.css("form"):
        fields = []
        for inp in form.css("input, textarea"):
            in_form.add(id(inp))
            k = _field_kind(inp)
            if k:
                fields.append(k)
        if fields:
            action = (form.attributes.get("action") or "").strip()
            if not action.lower().startswith(("javascript:", "mailto:", "#")):
                facts.form_actions.append((urljoin(base, action) if action else page_url, fields))
            facts.sensitive_fields += fields
    for inp in tree.css("input"):
        k = _field_kind(inp)
        if k and k not in facts.sensitive_fields:
            facts.sensitive_fields.append(k)
    return facts


def _claims(facts: PageFacts, idx: BrandIndex) -> list[tuple[Brand, str, str]]:
    out, seen = [], set()
    for signal, text in facts.identity.items():
        for brand, matched in idx.brands_claimed_in(text):
            if brand.id not in seen:
                seen.add(brand.id)
                out.append((brand, signal, matched))
    return out


def analyze(html: str, page_url: str, idx: BrandIndex) -> list[Finding]:
    u = parse_url(page_url)
    facts = extract(html, page_url)
    page_reg = registrable_domain(u.host)
    official = idx.official_brand(u.host, u.path)
    out: list[Finding] = []
    claims = [c for c in _claims(facts, idx) if official is None or official.id != c[0].id]
    fields = sorted(set(facts.sensitive_fields))

    if claims:
        brand, signal, matched = claims[0]
        ev = [evidence("html_element", f"Page {signal.replace('_', ' ')} claims '{matched}' ({brand.name}); "
                       f"the site is {page_reg}", SOURCE,
                       {"signal": signal, "text": facts.identity[signal][:200], "brand": brand.name,
                        "page_domain": page_reg, "official_domains": list(brand.official_domains)})]
        if fields:
            ev.append(evidence("html_element", f"Page asks for: {', '.join(fields)}", SOURCE, {"fields": fields}))
            out.append(make_finding(
                "PAGE.CREDENTIAL_FORM", f"Login form on a non-{brand.name} site claiming to be {brand.name}", ev,
                "Credentials, PINs or OTPs typed here go to whoever runs this site.",
                "Do not enter any details. Report it at cybercrime.gov.in or call 1930."))
        else:
            out.append(make_finding(
                "PAGE.BRAND_MISMATCH", f"Page presents itself as {brand.name} but is not on its domain", ev,
                f"The site borrows {brand.name}'s identity.",
                f"Use {brand.official_domains[0]} directly."))

    for action, f in facts.form_actions:
        try:
            areg = registrable_domain(parse_url(action).host)
        except URLParseError:
            continue
        if areg != page_reg:
            out.append(make_finding(
                "PAGE.FORM_ACTION_CROSS_DOMAIN", f"Sensitive form sends data to another site ({areg})",
                [evidence("html_element", f"Form with {', '.join(sorted(set(f)))} submits to {areg}", SOURCE,
                          {"action_domain": areg, "page_domain": page_reg, "fields": sorted(set(f))})],
                "What you type is sent to a different organisation than the page you see.",
                "Do not submit this form."))
            break
    return out


def _decode(body: bytes, headers: dict[str, str]) -> str:
    m = re.search(r"charset=([\w-]+)", headers.get("content-type", ""), re.I)
    if not m:
        m = re.search(rb"<meta[^>]+charset=[\"']?([\w-]+)", body[:4096], re.I)
    enc = m.group(1) if m else "utf-8"
    if isinstance(enc, bytes):
        enc = enc.decode("ascii", "ignore")
    try:
        return body.decode(enc, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


async def run(ctx: AssessmentContext) -> CheckResult:
    t0 = time.monotonic()
    try:
        fr = await ctx.fetch()
        if not fr.ok:
            return make_run(GROUP, CheckStatus.UNAVAILABLE, SOURCE, t0, f"page not retrieved: {fr.error}"), []
        if fr.content_type != "text/html":
            return make_run(GROUP, CheckStatus.SKIPPED, SOURCE, t0, f"not HTML ({fr.content_type})"), []
        findings = analyze(_decode(fr.body, fr.headers), fr.final_url or ctx.url.raw, ctx.brands)
        return make_run(GROUP, CheckStatus.COMPLETED, SOURCE, t0), findings
    except Exception as e:  # noqa: BLE001
        return make_run(GROUP, CheckStatus.FAILED, SOURCE, t0, f"error: {type(e).__name__}"), []
