"""Site-ownership proof before the exposed-file probe (POSTURE.EXPOSED_FILE).

The brief allows active checks only against authorised targets, so "I own this site" must be proven:
1. POST /ownership/challenge → a random challenge for the registrable domain.
2. The owner publishes it as a DNS TXT record `_cybermatrix-verify.<domain>` = `cybermatrix-verify=<challenge>`,
   or as the body of `https://<domain>/.well-known/cybermatrix-verify.txt`.
3. POST /ownership/verify → we look (TXT via DNS-over-HTTPS; the file via safe_fetch) and issue a grant token,
   valid 24 h for that registrable domain. /assess with owns_site=true must carry it.
Challenges expire after 1 h. Tokens are random, stored server-side, and only ever compared, never logged.
"""
from __future__ import annotations

import hmac
import secrets
from collections.abc import Awaitable, Callable
from datetime import timedelta

from app.fetch.api_client import ApiClient, ApiUnavailable
from app.fetch.safe_fetch import safe_fetch
from app.urlutil import URLParseError, parse_url, registrable_domain

CHALLENGE_TTL = timedelta(hours=1)
GRANT_TTL = timedelta(hours=24)
TXT_PREFIX = "_cybermatrix-verify."
TXT_VALUE = "cybermatrix-verify="
WELL_KNOWN = "/.well-known/cybermatrix-verify.txt"
DOH = "https://dns.google/resolve"

# (domain, challenge) -> method that proved it ("dns" | "file"), or None
Checker = Callable[[str, str], Awaitable[str | None]]


class OwnershipError(ValueError):
    pass


def domain_of(target: str) -> str:
    """Registrable domain (private PSL suffixes count, so `me.github.io` is its own domain)."""
    try:
        p = parse_url(target.strip())
    except URLParseError as e:
        raise OwnershipError(f"That isn't a valid domain or link ({e}).") from None
    if p.ip is not None:
        raise OwnershipError("Ownership can only be proven for a domain name, not an IP address.")
    return registrable_domain(p.host)


def new_token() -> str:
    return secrets.token_hex(16)


def same(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def instructions(domain: str, challenge: str) -> dict[str, str]:
    return {"txt_name": TXT_PREFIX + domain, "txt_value": TXT_VALUE + challenge,
            "file_url": f"https://{domain}{WELL_KNOWN}", "file_body": challenge}


def make_checker(api: ApiClient, fetch: Callable = safe_fetch) -> Checker:
    async def check(domain: str, challenge: str) -> str | None:
        try:
            d = await api.get_json(DOH, params={"name": TXT_PREFIX + domain, "type": "TXT"})
            for a in (d.get("Answer") or []) if isinstance(d, dict) else []:
                if isinstance(a, dict) and same(str(a.get("data", "")).strip('"'), TXT_VALUE + challenge):
                    return "dns"
        except ApiUnavailable:
            pass
        fr = await fetch(f"https://{domain}{WELL_KNOWN}")  # SSRF-guarded like every request to a user's site
        if fr.ok and fr.status == 200 and fr.final_url:
            try:
                final = registrable_domain(parse_url(fr.final_url).host)
            except URLParseError:
                return None
            if final == domain and same(fr.body[:200].decode("utf-8", "replace").strip(), challenge):
                return "file"
        return None
    return check
