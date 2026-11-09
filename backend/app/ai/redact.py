"""Mask personal data in submitted text BEFORE any external API call (CLAUDE.md rule 8).

The original text stays local. Order matters: longer / more specific patterns first. Names can't be detected
reliably by regex, so only names after a salutation, a sign-off, "my name is" or "This is X Y from" are masked;
the report says so. Over-redaction is acceptable (the LLM only labels language signals); a leak is not.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

_NAME = r"[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2}"
_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("email", re.compile(r"[\w.+-]+@(?:[\w-]+\.)+[A-Za-z]{2,}")),
    ("upi", re.compile(r"(?<![\w.@])[\w.-]{2,}@[A-Za-z][A-Za-z0-9]{1,20}\b(?!\.[A-Za-z])")),
    ("pan", re.compile(r"\b[A-Za-z]{5}\d{4}[A-Za-z]\b")),
    ("gstin", re.compile(r"\b\d{2}[A-Z]{5}\d{4}[A-Z][A-Z\d]Z[A-Z\d]\b")),
    ("ifsc", re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")),
    ("vehicle", re.compile(r"\b[A-Z]{2}\d{1,2}[A-Z]{1,3}\d{4}\b")),
    ("passport", re.compile(r"\b[A-PR-WY]\d{7}\b")),
    ("cvv", re.compile(r"(?i)\b(?:cvv2?|cvc2?|cid)\b\s*[:=]?\s*\d{3,4}\b")),
    ("card", re.compile(r"\b(?:\d{4}[\s-]){3}\d{4}\b")),
    ("aadhaar", re.compile(r"\b\d{4}[\s-]\d{4}[\s-]\d{4}\b")),
    ("ip", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("date", re.compile(r"\b\d{1,2}[/-]\d{1,2}[/-](?:\d{4}|\d{2})\b")),
    ("phone", re.compile(r"(?<![\w.])(?:\+|00)?(?:91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}\b|(?<![\w.])\+\d{1,3}[\s-]?\d[\d\s-]{7,13}\d\b")),
    ("number", re.compile(r"(?<![\w.])(?:\d[ .-]){9,}\d(?![\w.])")),  # digits split up to dodge the patterns above
    ("account", re.compile(r"\b\d{9,18}\b")),
    ("otp", re.compile(r"(?<![\w.,₹$])(?<!Rs )(?<!Rs\. )(?<!INR )\b\d{4,8}\b(?![\w.,]*\d)")),
    ("name", re.compile(r"\b((?:Dear|Hi|Hello|Mr|Mrs|Ms|Shri|Smt|Sri|Name:|My name is|I am|I'm|Regards,|Thanks,|"
                        r"Thank you,|Sincerely,|Yours(?: sincerely| faithfully)?,|Sent by)\.?\s+)(" + _NAME + ")")),
    ("name", re.compile(r"\b(This is\s+)([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})(?=\s+from\b)")),
]
_QUERY = re.compile(r"(https?://[^\s?#]+)\?[^\s#]*")
# long path segments with a digit: reset links, session ids, document ids
_PATH_TOKEN = re.compile(r"(?<=/)(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]{20,}(?=[/?#\s]|$)")


@dataclass
class Redaction:
    text: str
    counts: dict[str, int] = field(default_factory=dict)


def redact(text: str) -> Redaction:
    counts: dict[str, int] = {}

    def bump(kind: str, n: int) -> None:
        if n:
            counts[kind] = counts.get(kind, 0) + n

    out = _QUERY.sub(lambda m: m.group(1) + "?[QUERY]", text)  # query strings often carry tokens / ids
    out, n = _PATH_TOKEN.subn("[TOKEN]", out)
    bump("token", n)
    for kind, rx in _RULES:
        if kind == "name":
            out, n = rx.subn(lambda m: m.group(1) + "[NAME]", out)
        else:
            out, n = rx.subn(f"[{kind.upper()}]", out)
        bump(kind, n)
    return Redaction(out, counts)
