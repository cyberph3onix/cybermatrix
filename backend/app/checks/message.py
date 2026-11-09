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
from app.urlutil import URLParseError, parse_url, registrable_domain, split_domain

SOURCE = "local:message_inspector"
_URL = re.compile(r"(?:https?://|www\.)[^\s<>\"'\])}]+|\b(?:[a-z0-9-]+\.)+[a-z]{2,}/[^\s<>\"'\])}]+", re.IGNORECASE)
# Bare domains with no scheme or path ("Update KYC at hdfc-verify.in"). Lowercase only, so sentence joins such as
# "activity.SMS" or "paid.In" are not read as domains; the suffix must be a real public suffix.
_BARE = re.compile(r"(?<![\w.@/-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?![\w@-])")
_AT = re.compile(r"(?<![\w.+-])[\w.+-]{2,}@[A-Za-z0-9.-]+")
_PHONE = re.compile(r"(?<![\w.])(?:\+|00)?(?:91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}\b|(?<![\w.])\+\d{1,3}[\s-]?\d[\d\s-]{7,13}\d\b")
_BTC = re.compile(r"\b(?:bc1[a-z0-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
_ETH = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
TRAIL = ".,;:!?"

SIGNALS: dict[str, tuple[re.Pattern[str], str, str]] = {
    "MSG.CREDENTIAL_REQUEST": (
        re.compile(r"\b(?:share|send|sms|enter|provide|tell|confirm|verify|update|reply with)\b[^.\n]{0,50}\b(?:otp|one[- ]time|password|pin|cvv|card (?:number|details)|seed phrase|recovery phrase|aadhaar|pan|bank (?:details|account details)|a/c (?:&|and) ifsc|ifsc)\b"
                   r"|\b(?:otp|password|pin|cvv|aadhaar(?: number)?|bank details)\b[^.\n]{0,40}\b(?:share|send|enter|required|needed|bhejein|bhejo|batayein|batao|enter karein|share karein)\b"
                   r"|\b(?:re-?verify|update|complete) (?:your )?kyc\b|\bkyc (?:pending|update|expired?|will expire)\b", re.I),
        "Message asks for a code, PIN or password", "Legitimate organisations never ask for these in a message."),
    "MSG.PAYMENT_REQUEST": (
        re.compile(r"\b(?:pay|transfer|deposit)\b[^.\n]{0,40}(?:\b(?:rs\.?|inr)\s*[\d,]+|₹\s*[\d,]+|\bsettlement\b)"
                   r"|\bscan (?:the |this )?qr\b|\bcollect request\b|\breceive money\b|\bapprove\b[^.\n]{0,30}\b(?:request|payment|amt|amount)\b|\bupi (?:pin|id)\b"
                   r"|(?<!0% )\b(?:processing|verification|registration|reg|activation|handling|settlement) (?:fee|charges?)\b|\brefund kar\w*\b|\b(?:sent|transferred|bhej diya)\b[^.\n]{0,30}\b(?:by mistake|galti se)\b|\bgalti se\b|\bpay (?:now|immediately|today)\b|\bpay karein\b"
                   r"|\binvest(?:ment)?\b[^.\n]{0,20}\b(?:rs\.?|inr)\s*[\d,]+", re.I),
        "Message asks you to pay or approve a payment", "Receiving money never needs you to scan, approve or enter a PIN."),
    "MSG.URGENCY": (
        re.compile(r"\b(?:urgent(?:ly)?|immediately|immly|right now|within (?:\d+|one|two|24|48) ?(?:hours?|hrs?|minutes?|days?)|in \d+ ?(?:hours?|hrs?|mins?)\b|expires? (?:today|tonight|soon)|(?:will be|get|be) (?:blocked|suspended|deactivated|closed|frozen|disconnected|cut)|frozen|tonight|to avoid (?:arrest|block|blocking|disconnection|deactivation|suspension|policy lapse|penalty)|digital arrest|last (?:chance|warning)|final notice|turant|ghante mein|block ho jayega|abhi (?:karein|kare|renew|apply|update)|expire ho (?:gayi|raha|rahi)|(?:will )?stop [^.\n]{0,20}\btoday)\b", re.I),
        "Message pressures you with a deadline or threat", "Pressure is used to stop you checking."),
    "MSG.AUTHORITY_IMPERSONATION": (
        re.compile(r"\b(?:RBI|SEBI|TRAI|cyber ?crime(?: cell)?|cyber cell|police|court (?:notice|warrant)|warrant issued|FIR (?:has been )?(?:filed|registered)|customs|income tax department|customer care)\b", re.I),
        "Message claims to come from an authority", "Authorities do not demand payment or codes by SMS; contact them through official channels."),
    "MSG.REWARD_LURE": (
        re.compile(r"\b(?:you(?:'ve| have)? (?:won|been selected)|(?:ur|your) (?:no|number|sim(?: card)?) (?:is chosen|won)|selected for|lucky (?:draw|winner)|lottery|prize|cash ?back|refund|reward points|free gift|work from home|registration fee|processing fee|claim (?:now|your|at)|guarantee[ds]? (?:daily )?(?:profit|returns?)|\d+x return|pre-approved (?:personal )?loan|loan (?:application )?approved|claim (?:of rs\.? ?[\d,]+ )?(?:is )?approved|earn rs\.? ?[\d,]+\s*(?:/|per |a )?(?:day|daily)|earn rs\.? ?[\d,]+ daily|daily rs\.? ?[\d,]+ kama\w*|ghar baithe|guarantee[ds]?\b[^.\n]{0,25}\b(?:profit|returns?)|\d{2,}% (?:daily )?returns?|jeet (?:chuke|gaye))\b", re.I),
        "Message offers a prize, refund or job", "Unexpected rewards, especially with a fee, are a common lure."),
}


# "Do not share this OTP with anyone" is the warning genuine banks send, not a request. A credential or payment
# phrase directly after a negation is skipped (the next non-negated match, if any, still counts).
_NEGATION = re.compile(r"\b(?:do not|don't|dont|never|not to|no one will|nobody will|will never|won't)\W+(?:\w+\W+){0,2}$", re.I)
_NEGATABLE = {"MSG.CREDENTIAL_REQUEST", "MSG.PAYMENT_REQUEST"}


def _first_match(cid: str, rx: re.Pattern[str], text: str) -> re.Match[str] | None:
    pos = 0
    while (m := rx.search(text, pos)) is not None:
        if cid in _NEGATABLE and _NEGATION.search(text[max(0, m.start() - 40):m.start()]):
            pos = m.start() + 1  # a later phrase inside the skipped span can still be a real request
            continue
        return m
    return None


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


def parse_host(u: str) -> str | None:
    try:
        return parse_url(u).host
    except URLParseError:
        return None


def _is_domain(s: str) -> bool:
    """A real public suffix and a registrable name (not "e.g" or a file name like report.pdf)."""
    if s.rsplit(".", 1)[-1] in {"pdf", "jpg", "jpeg", "png", "doc", "docx", "txt", "exe", "apk", "zip", "html", "php"}:
        return False
    try:
        _sub, name, suffix = split_domain(s)
    except Exception:  # noqa: BLE001
        return False
    return bool(name and suffix and any(c.isalpha() for c in name))


def extract(text: str) -> Extracted:
    urls = _uniq(u.rstrip(TRAIL) for u in _URL.findall(text))
    covered = {parse_host(u) for u in urls}
    for m in _BARE.findall(text):
        if m not in covered and _is_domain(m):
            urls.append(m)
            covered.add(m)
    email_spans = _AT.findall(text)
    emails, upi = [], []
    for m in email_spans:
        m = m.rstrip(TRAIL)
        (emails if "." in m.split("@", 1)[1] else upi).append(m)
    return Extracted(urls=urls, emails=_uniq(emails), upi_ids=_uniq(upi),
                     phones=_uniq(m.strip() for m in _PHONE.findall(text) if re.sub(r"\D", "", m)),
                     crypto=_uniq(_BTC.findall(text) + _ETH.findall(text)))


# Redaction placeholders ("[OTP]" for any short number) must not match the keywords they replaced.
_PLACEHOLDER = re.compile(r"\[[A-Z_]+\]")
STRONG_LURE = re.compile(r"\b(?:won|lottery|lucky|prize|guarantee[ds]?|\d+x return|\d+% (?:daily )?returns?|pre-approved|approved|jeet|chosen|selected|earn|kama\w*|ghar baithe)\b", re.I)
# Replying or calling is the "act now" channel when there is no link ("Reply YES to avoid digital arrest").
_ACT = re.compile(r"\breply (?:yes|y|now)\b|\bcall (?:now|immediately)\b|\bclick\b", re.I)


def regex_signals(text: str, idx: BrandIndex) -> list[Finding]:
    red = _PLACEHOLDER.sub("[…]", redact(text).text)
    out: list[Finding] = []
    for cid, (rx, title, advice) in SIGNALS.items():
        m = _first_match(cid, rx, red)
        if m:
            out.append(make_finding(cid, title, [evidence("text_span", f"Matched phrase: “{m.group(0)[:80]}”", SOURCE,
                                                        {"span": m.group(0)[:80]}, observed_at=utcnow())],
                                    "Language like this is common in scams but also appears in genuine messages.", advice,
                                    limitation="Pattern match on wording; a weak signal on its own."))
    claimed = idx.brands_claimed_in(red)
    if claimed and not any(f.check_id == "MSG.AUTHORITY_IMPERSONATION" for f in out):
        b, alias = claimed[0]
        out.append(make_finding("MSG.AUTHORITY_IMPERSONATION", f"Message mentions {b.name}",
                                [evidence("text_span", f"Message names {b.name} (“{alias}”)", SOURCE,
                                          {"brand": b.id, "span": alias}, observed_at=utcnow())],
                                "Scam messages often borrow a trusted organisation's name.",
                                f"Contact {b.name} only through its official app or a typed-in website.",
                                limitation="Naming an organisation is normal in genuine messages too."))
    pattern = scam_pattern(out, extract(text), red)
    if pattern:
        out.append(pattern)
    return out


PRESSURE = ("MSG.URGENCY", "MSG.AUTHORITY_IMPERSONATION", "MSG.REWARD_LURE")


def scam_pattern(found: list[Finding], ex: Extracted, text: str = "") -> Finding | None:
    """MSG.SCAM_PATTERN: two different pressure tactics AND a way to act on them (a link, phone number, UPI ID or
    payment/credential request). Each tactic alone is common in genuine messages; the combination is the scam shape.
    Still heuristic, so wording alone can reach `suspicious` but never `high_risk`."""
    ids = {f.check_id for f in found}
    act = bool(_ACT.search(text))
    tactics = [c for c in PRESSURE if c in ids]
    # "You have won" / "guaranteed returns" is too good to be true on its own: it counts as a second tactic
    if "MSG.REWARD_LURE" in ids and STRONG_LURE.search(text):
        tactics.append("too-good-to-be-true offer")
    actions = ([f"{len(ex.urls)} link(s)"] if ex.urls else []) + ([f"{len(ex.phones)} phone number(s)"] if ex.phones else []) \
        + ([f"{len(ex.upi_ids)} UPI ID(s)"] if ex.upi_ids else []) + ([f"{len(ex.emails)} email address(es)"] if ex.emails else []) \
        + [c for c in ("MSG.CREDENTIAL_REQUEST", "MSG.PAYMENT_REQUEST") if c in ids] + (["a reply/call-now instruction"] if act else [])
    if len(tactics) < 2 or not actions:
        return None
    return make_finding("MSG.SCAM_PATTERN", "Message combines pressure tactics with a way to act on them",
                        [evidence("signal_combination", f"Tactics: {', '.join(tactics)}; asks you to act via {', '.join(actions)}",
                                  SOURCE, {"tactics": tactics, "actions": actions}, observed_at=utcnow())],
                        "Pressure plus an immediate channel to respond is how most SMS and WhatsApp scams are built.",
                        "Do not use the link or number in the message. Contact the organisation through its official app or website.",
                        limitation="Built from wording patterns only; genuine urgent notices can match.")


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
