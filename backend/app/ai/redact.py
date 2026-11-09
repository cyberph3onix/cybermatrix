"""Mask personal data in submitted text BEFORE any external API call (CLAUDE.md rule 8).

The original text stays local. Order matters: longer / more specific patterns first. Names can't be detected
reliably by regex, so only names after a salutation or title are masked; the report says so.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("email", re.compile(r"[\w.+-]+@(?:[\w-]+\.)+[A-Za-z]{2,}")),
    ("upi", re.compile(r"(?<![\w.@])[\w.-]{2,}@[A-Za-z][A-Za-z0-9]{1,20}\b(?!\.[A-Za-z])")),
    ("pan", re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")),
    ("aadhaar", re.compile(r"\b\d{4}[\s-]\d{4}[\s-]\d{4}\b")),
    ("card", re.compile(r"\b(?:\d{4}[\s-]){3}\d{4}\b")),
    ("phone", re.compile(r"(?<![\w.])(?:\+|00)?(?:91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}\b|(?<![\w.])\+\d{1,3}[\s-]?\d[\d\s-]{7,13}\d\b")),
    ("account", re.compile(r"\b\d{9,18}\b")),
    ("otp", re.compile(r"(?<![\w.,₹$])(?<!Rs )(?<!Rs\. )(?<!INR )\b\d{4,8}\b(?![\w.,]*\d)")),
    ("name", re.compile(r"\b((?:Dear|Hi|Hello|Mr|Mrs|Ms|Shri|Smt|Sri)\.?\s+)([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2})")),
]
_QUERY = re.compile(r"(https?://[^\s?#]+)\?[^\s#]*")


@dataclass
class Redaction:
    text: str
    counts: dict[str, int] = field(default_factory=dict)


def redact(text: str) -> Redaction:
    counts: dict[str, int] = {}
    out = _QUERY.sub(lambda m: m.group(1) + "?[QUERY]", text)  # query strings often carry tokens / ids
    for kind, rx in _RULES:
        if kind == "name":
            out, n = rx.subn(lambda m: m.group(1) + "[NAME]", out)
        else:
            out, n = rx.subn(f"[{kind.upper()}]", out)
        if n:
            counts[kind] = n
    return Redaction(out, counts)
