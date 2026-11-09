"""Message similarity and brand-impersonation indicators (Module 4: "detect similarities between reported phishing
messages", "identify recurring impersonation patterns").

Deterministic, like the rest of correlation. A message's *template* replaces links, numbers, phone numbers,
amounts and redaction placeholders with tokens, so one campaign sent with different links or amounts maps to the
same template. Similarity is the Jaccard index of word 3-shingles of the templates.

- Each message gets a `message_family` indicator: the family of the most similar earlier suspicious-or-worse
  message (Jaccard ≥ SIMILAR), else its own template hash. Clusters join on it, so near-duplicates group together.
- Every report gets `brand_claimed` indicators for brands that findings say it impersonates. These feed the
  impersonation trends view, never clusters (one popular brand would glue unrelated campaigns together).
"""
from __future__ import annotations

import hashlib
import re

from app.brands import BrandIndex
from app.schemas import AssessmentReport, Indicator

SIMILAR = 60  # percent Jaccard
MIN_SHINGLES = 4  # very short messages ("Call me") are too generic to compare
RECENT_LIMIT = 300

_TOKENS = [
    (re.compile(r"\[[A-Z_]+\]"), " ‹x› "),  # redaction placeholders
    (re.compile(r"(?:https?://|www\.)\S+|\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/\S*)?", re.I), " ‹link› "),
    (re.compile(r"(?:rs\.?|inr|₹|\$|£)\s*[\d,]+(?:\.\d+)?", re.I), " ‹amount› "),
    (re.compile(r"\d[\d\s-]{5,}\d"), " ‹number› "),
    (re.compile(r"\d+"), " ‹n› "),
]
# brand-claim evidence keys in findings: some checks store the brand id, others the display name
BRAND_FINDINGS = ("MSG.AUTHORITY_IMPERSONATION", "MSG.SENDER_DOMAIN_MISMATCH", "URL.LOOKALIKE.HOMOGLYPH",
                  "URL.LOOKALIKE.TYPOSQUAT", "URL.BRAND_IN_SUBDOMAIN", "PAGE.CREDENTIAL_FORM", "PAGE.BRAND_MISMATCH",
                  "PAGE.SCREENSHOT_BRAND_MISMATCH")


def template(text: str) -> str:
    t = text.lower()
    for rx, token in _TOKENS:
        t = rx.sub(token, t)
    return " ".join(re.findall(r"‹\w+›|[a-zऀ-ॿ]+", t))


def template_hash(text: str) -> str:
    return hashlib.sha256(template(text).encode()).hexdigest()[:32]


def shingles(text: str, k: int = 3) -> frozenset[str]:
    words = template(text).split()
    return frozenset(" ".join(words[i:i + k]) for i in range(max(0, len(words) - k + 1)))


def jaccard_pct(a: frozenset[str], b: frozenset[str]) -> int:
    if not a or not b:
        return 0
    return 100 * len(a & b) // len(a | b)


def brand_indicators(report: AssessmentReport, idx: BrandIndex) -> list[Indicator]:
    by_key = {b.id: b for b in idx.brands} | {b.name: b for b in idx.brands}
    seen: dict[str, str] = {}
    for f in report.findings:
        if f.check_id not in BRAND_FINDINGS:
            continue
        for e in f.evidence:
            b = by_key.get(str((e.data or {}).get("brand", "")))
            if b is not None:
                seen.setdefault(b.id, b.name)
    return [Indicator(type="brand_claimed", value=name, normalized=bid) for bid, name in seen.items()]
