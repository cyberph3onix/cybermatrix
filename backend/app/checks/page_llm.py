"""PAGE.LLM_CLAIMED_BRAND (group page.llm, coverage weight 0).

Fires only when ALL of these hold, all decided by code:
  1. the LLM extracted a claimed brand that is NOT in brands.json (brands we know are handled by the
     deterministic PAGE.* checks);
  2. the page asks for credentials or payment;
  3. the site is not allowlisted (official brand domain / Tranco top 10k);
  4. no meaningful word of the claimed brand appears in the site's registrable domain.
It is a heuristic hint: it can add a medium signal (-> suspicious at most), never a verdict.
"""
from __future__ import annotations

import re
import time

from selectolax.lexbor import LexborHTMLParser

from app.ai.brand_claim import BrandClaim, extract_claim
from app.ai.injection import has_injection
from app.ai.llm import LlmUnavailable
from app.ai.redact import redact
from app.brands import BrandIndex
from app.checks.base import AssessmentContext, CheckResult, evidence, make_finding, make_run
from app.checks.page import _decode, extract
from app.schemas import CheckStatus, Finding
from app.urlutil import parse_url, registrable_domain, split_domain

GROUP = "page.llm"
SOURCE = "llm"
MAX_TEXT = 3000
_WORD = re.compile(r"[a-z0-9]{4,}")


def visible_text(html: str) -> str:
    tree = LexborHTMLParser(html)
    for n in tree.css("script, style, noscript, template"):
        n.decompose()
    body = tree.body.text(separator=" ") if tree.body else ""
    return " ".join(body.split())[:MAX_TEXT]


def page_digest(html: str, page_url: str) -> str:
    facts = extract(html, page_url)
    parts = [f"Title: {facts.title or ''}"]
    parts += [f"{k}: {v}" for k, v in facts.identity.items()]
    if facts.sensitive_fields:
        parts.append("Form fields: " + ", ".join(sorted(set(facts.sensitive_fields))))
    parts.append("Text: " + visible_text(html))
    return "\n".join(parts)


def domain_belongs(brand: str, host: str) -> bool:
    """True when a meaningful word of the brand name appears in the site's own domain label."""
    label = re.sub(r"[^a-z0-9]", "", split_domain(host)[1].lower())
    squashed = re.sub(r"[^a-z0-9]", "", brand.lower())
    return bool(squashed) and (squashed in label or any(w in label for w in _WORD.findall(brand.lower())))


def decide(claim: BrandClaim, page_url: str, idx: BrandIndex, *, injected: bool = False, model: str = "") -> list[Finding]:
    brand = claim.claimed_brand
    if not brand or not (claim.seeks_credentials or claim.seeks_payment):
        return []
    if idx.brands_claimed_in(brand):  # known brand: deterministic PAGE.* checks decide
        return []
    u = parse_url(page_url)
    if idx.allowlisted(u.host, u.path or "/") or domain_belongs(brand, u.host):
        return []
    asks = [k for k, v in (("credentials", claim.seeks_credentials), ("payment", claim.seeks_payment)) if v]
    return [make_finding(
        "PAGE.LLM_CLAIMED_BRAND", f"Page presents itself as “{brand}” but is hosted on {registrable_domain(u.host)}",
        [evidence("text_span", f"Model-extracted from page text: claims to be “{brand}” and asks for {' and '.join(asks)}",
                  f"llm:{model}", {"claimed_brand": brand, "seeks": asks, "page_domain": registrable_domain(u.host),
                                  "page_text_contains_instructions_for_ai": injected})],
        "A page that asks for sensitive details under another organisation's name, on an unrelated domain, is a "
        "common phishing pattern.", "Use the organisation's official app or a typed-in address instead.",
        limitation="Brand extracted by an AI model from page text; the name is not in our brand list, so this is a "
                   "weak signal on its own.")]


_PAYMENT_WORDS = re.compile(r"\b(?:pay(?:ment)?|upi|donate|wallet|checkout|invoice)\b", re.I)


def _worth_asking(html: str, url: str) -> bool:
    """Spend an LLM call only on pages that could be credential or payment lures: a sensitive input field, or
    payment wording. The free LLM tiers are small, and a page with neither cannot trigger the finding anyway
    (the model must report that it seeks credentials or payment)."""
    return bool(extract(html, url).sensitive_fields) or bool(_PAYMENT_WORDS.search(visible_text(html)))


async def run(ctx: AssessmentContext) -> CheckResult:
    t0 = time.monotonic()
    llm = ctx.llm
    if llm is None:
        return make_run(GROUP, CheckStatus.SKIPPED, SOURCE, t0, "no LLM configured"), []
    try:
        fr = await ctx.fetch()
        if not fr.ok or fr.content_type != "text/html":
            return make_run(GROUP, CheckStatus.SKIPPED, f"llm:{llm.model}", t0, "no HTML page to read"), []
        url = fr.final_url or ctx.url.raw
        html = _decode(fr.body, fr.headers)
        if not _worth_asking(html, url):
            return make_run(GROUP, CheckStatus.SKIPPED, f"llm:{llm.model}", t0, "page has no sensitive form"), []
        digest = page_digest(html, url)
        claim = await extract_claim(llm, redact(digest).text)
        return (make_run(GROUP, CheckStatus.COMPLETED, f"llm:{llm.model}", t0),
                decide(claim, url, ctx.brands, injected=has_injection(digest), model=llm.model))
    except LlmUnavailable as e:
        return make_run(GROUP, CheckStatus.UNAVAILABLE, f"llm:{llm.model}", t0, str(e)), []
    except Exception as e:  # noqa: BLE001
        return make_run(GROUP, CheckStatus.FAILED, f"llm:{llm.model}", t0, f"error: {type(e).__name__}"), []
