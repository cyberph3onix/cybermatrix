"""Message analysis (local, no network): indicator extraction, regex MSG.* signals, email-header checks.

Runs on the ORIGINAL text locally; evidence spans are cut from the REDACTED text so reports never carry PII
that the redactor knows how to mask.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import message_from_string
from email.utils import parseaddr
from html.parser import HTMLParser

from app.ai.redact import redact
from app.brands import BrandIndex
from app.checks.base import evidence, make_finding
from app.schemas import Finding, Indicator, utcnow
from app.urlutil import URLParseError, parse_url, registrable_domain

SOURCE = "local:message_inspector"
_URL = re.compile(r"(?:https?://|www\.)[^\s<>\"'\])}]+|\b(?:[a-z0-9-]+\.)+[a-z]{2,}/[^\s<>\"'\])}]+", re.IGNORECASE)
_AT = re.compile(r"(?<![\w.+-])[\w.+-]{2,}@[A-Za-z0-9.-]+")
_PHONE = re.compile(r"(?<![\w.])(?:\+|00)?(?:91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}\b|(?<![\w.])\+\d{1,3}[\s-]?\d[\d\s-]{7,13}\d\b")
_BTC = re.compile(r"\b(?:bc1[a-z0-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
_ETH = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
TRAIL = ".,;:!?"

SIGNALS: dict[str, tuple[re.Pattern[str], str, str]] = {
    "MSG.CREDENTIAL_REQUEST": (
        re.compile(r"\b(?:share|send|enter|provide|tell|confirm|verify|update|reply with)\b[^.\n]{0,50}\b(?:otp|one[- ]time|password|pin|cvv|card (?:number|details)|seed phrase|recovery phrase|aadhaar|pan)\b"
                   r"|\b(?:otp|password|pin|cvv)\b[^.\n]{0,30}\b(?:share|send|enter|required|needed)\b", re.I),
        "Message asks for a code, PIN or password", "Legitimate organisations never ask for these in a message."),
    "MSG.PAYMENT_REQUEST": (
        re.compile(r"\b(?:pay|transfer|deposit|send)\b[^.\n]{0,30}\b(?:rs\.?|inr|₹|\d+)\b|\bscan (?:the |this )?qr\b|\bcollect request\b|\breceive money\b|\bapprove (?:the )?(?:upi )?(?:request|payment)\b|\bupi (?:pin|id)\b", re.I),
        "Message asks you to pay or approve a payment", "Receiving money never needs you to scan, approve or enter a PIN."),
    "MSG.URGENCY": (
        re.compile(r"\b(?:urgent(?:ly)?|immediately|right now|within (?:\d+|one|two|24|48) ?(?:hours?|hrs?|minutes?|days?)|expires? (?:today|tonight|soon)|(?:will be|get) (?:blocked|suspended|deactivated|closed)|last (?:chance|warning)|final notice)\b", re.I),
        "Message pressures you with a deadline or threat", "Pressure is used to stop you checking."),
    "MSG.REWARD_LURE": (
        re.compile(r"\b(?:you(?:'ve| have)? (?:won|been selected)|lottery|prize|cash ?back|refund|reward points|free gift|work from home|registration fee|processing fee|claim (?:now|your))\b", re.I),
        "Message offers a prize, refund or job", "Unexpected rewards, especially with a fee, are a common lure."),
}


@dataclass
class Extracted:
    urls: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    phones: list[str] = field(default_factory=list)
    upi_ids: list[str] = field(default_factory=list)
    crypto: list[str] = field(default_factory=list)

    def indicators(self, idx: BrandIndex) -> list[Indicator]:
        out: list[Indicator] = []
        for u in self.urls:
            try:
                p = parse_url(u)
                out.append(Indicator(type="url", value=u, normalized=p.url_without_userinfo()))
                if not p.ip:
                    out.append(Indicator(type="domain", value=p.host, normalized=registrable_domain(p.host)))
            except URLParseError:
                continue
        out += [Indicator(type="email", value=e, normalized=e.lower()) for e in self.emails]
        out += [Indicator(type="phone", value=p, normalized=_norm_phone(p)) for p in self.phones]
        out += [Indicator(type="upi_id", value=u, normalized=u.lower()) for u in self.upi_ids]
        out += [Indicator(type="crypto_address", value=c, normalized=c.lower() if c.startswith("0x") else c) for c in self.crypto]
        seen, uniq = set(), []
        for i in out:
            if (i.type, i.normalized) not in seen:
                seen.add((i.type, i.normalized))
                uniq.append(i)
        return uniq


def _norm_phone(p: str) -> str:
    d = re.sub(r"\D", "", p)
    return "+91" + d[-10:] if len(d) in (10, 12) and d[-10] in "6789" else "+" + d


def _uniq(xs):
    return list(dict.fromkeys(xs))


def extract(text: str) -> Extracted:
    urls = _uniq(u.rstrip(TRAIL) for u in _URL.findall(text))
    email_spans = _AT.findall(text)
    emails, upi = [], []
    for m in email_spans:
        m = m.rstrip(TRAIL)
        (emails if "." in m.split("@", 1)[1] else upi).append(m)
    return Extracted(urls=urls, emails=_uniq(emails), upi_ids=_uniq(upi),
                     phones=_uniq(m.strip() for m in _PHONE.findall(text) if re.sub(r"\D", "", m)),
                     crypto=_uniq(_BTC.findall(text) + _ETH.findall(text)))


def regex_signals(text: str, idx: BrandIndex) -> list[Finding]:
    red = redact(text).text
    out: list[Finding] = []
    for cid, (rx, title, advice) in SIGNALS.items():
        m = rx.search(red)
        if m:
            out.append(make_finding(cid, title, [evidence("text_span", f"Matched phrase: “{m.group(0)[:80]}”", SOURCE,
                                                        {"span": m.group(0)[:80]}, observed_at=utcnow())],
                                    "Language like this is common in scams but also appears in genuine messages.", advice,
                                    limitation="Pattern match on wording; a weak signal on its own."))
    claimed = idx.brands_claimed_in(red)
    if claimed:
        b, alias = claimed[0]
        out.append(make_finding("MSG.AUTHORITY_IMPERSONATION", f"Message mentions {b.name}",
                                [evidence("text_span", f"Message names {b.name} (“{alias}”)", SOURCE,
                                          {"brand": b.id, "span": alias}, observed_at=utcnow())],
                                "Scam messages often borrow a trusted organisation's name.",
                                f"Contact {b.name} only through its official app or a typed-in website.",
                                limitation="Naming an organisation is normal in genuine messages too."))
    return out


class _Anchors(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href, self._text = dict(attrs).get("href"), []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


def link_text_mismatches(html: str) -> list[tuple[str, str]]:
    p = _Anchors()
    try:
        p.feed(html)
    except Exception:  # noqa: BLE001
        return []
    out = []
    for href, text in p.links:
        m = _URL.search(text)
        if not m or not href.lower().startswith(("http://", "https://")):
            continue
        try:
            a, b = registrable_domain(parse_url(m.group(0)).host), registrable_domain(parse_url(href).host)
        except URLParseError:
            continue
        if a != b:
            out.append((m.group(0)[:80], href[:200]))
    return out


def has_headers(text: str) -> bool:
    head = text.lstrip().split("\n\n", 1)[0]
    return bool(re.search(r"^From:\s*\S", head, re.M | re.I)) and bool(re.search(r"^(?:Subject|To|Date|Reply-To):", head, re.M | re.I))


def header_findings(text: str, idx: BrandIndex) -> list[Finding]:
    out: list[Finding] = []
    if has_headers(text):
        msg = message_from_string(text)
        body = msg.get_payload() if not msg.is_multipart() else " ".join(
            str(p.get_payload()) for p in msg.walk() if not p.is_multipart())
        claimed = idx.brands_claimed_in(f"{msg.get('Subject', '')} {body} {parseaddr(msg.get('From', ''))[0]}")
        for hdr in ("From", "Reply-To"):
            addr = parseaddr(msg.get(hdr, ""))[1]
            if "@" not in addr or not claimed:
                continue
            dom = registrable_domain(addr.rsplit("@", 1)[1].lower())
            b = claimed[0][0]
            if dom not in b.official_domains and not any(dom == registrable_domain(d) for d in b.official_domains):
                out.append(make_finding(
                    "MSG.SENDER_DOMAIN_MISMATCH", f"{hdr} address is not on {b.name}'s official domain",
                    [evidence("text_span", f"{hdr} domain {dom} but the message claims to be from {b.name} "
                              f"(official: {', '.join(b.official_domains[:3])})", SOURCE,
                              {"header": hdr, "sender_domain": dom, "brand": b.id}, observed_at=utcnow())],
                    "Genuine mail from this organisation comes from its own domain.",
                    "Do not reply or click anything; contact the organisation through its official channels.",
                    limitation="Headers can be forged; this checks the claimed address, not SPF/DKIM."))
                break
    if "<a " in text.lower():
        for shown, href in link_text_mismatches(text)[:3]:
            out.append(make_finding(
                "MSG.LINK_TEXT_MISMATCH", "A link shows one address but goes to another",
                [evidence("html_element", f"Link text “{shown}” points to {href}", SOURCE,
                          {"shown": shown, "href": href}, observed_at=utcnow())],
                "Showing a trusted address while linking elsewhere is a standard phishing trick.",
                "Do not click it; type the organisation's address yourself."))
    return out
