"""DOMAIN.* DNS characteristics and POSTURE.* email-authentication records (group domain.dns).

Passive: records come from a public DNS-over-HTTPS resolver (dns.google, a fixed host via api_client), so nothing
is sent to the target. Answers are cached like threat-intel lookups.

- DOMAIN.FAST_FLUX: many short-lived A records spread over unrelated networks, the classic botnet-hosting shape.
  CDNs can look similar, so it is a heuristic and allowlisted domains are dampened by risk.dampen (DOMAIN.*).
- DOMAIN.FREE_DNS: nameservers (or the host itself) on a free / dynamic DNS service, cheap and anonymous for abusers.
- POSTURE.NO_SPF / POSTURE.NO_DMARC / POSTURE.DMARC_NOT_ENFORCED: the domain can be spoofed in email. Posture only
  (CLAUDE.md rule 10): it says nothing about whether the website is phishing.
"""
from __future__ import annotations

import asyncio
import ipaddress
import time
from typing import Any

from app.checks.base import AssessmentContext, CheckResult, evidence, make_finding, make_run
from app.checks.intel.common import cached_json
from app.fetch.api_client import ApiClient, ApiUnavailable
from app.schemas import CheckStatus, Finding
from app.urlutil import icann_registrable_domain

GROUP = "domain.dns"
SOURCE = "dns.google (DNS-over-HTTPS)"
DOH = "https://dns.google/resolve"
TYPES = {"A": 1, "NS": 2, "TXT": 16, "MX": 15}

FLUX_MIN_IPS = 5
FLUX_MIN_NETS = 3  # distinct /16s
FLUX_MAX_TTL = 300

# Free or dynamic DNS providers whose nameservers / subdomains cost nothing and need no identity.
FREE_DNS_NS = ("afraid.org", "duckdns.org", "no-ip.com", "dynu.com", "he.net", "1984.is", "freenom.com",
               "dnsexit.com", "changeip.com", "dynv6.com", "desec.io", "hostry.com")
DYNAMIC_HOST_SUFFIXES = ("duckdns.org", "no-ip.org", "no-ip.biz", "ddns.net", "hopto.org", "zapto.org",
                         "sytes.net", "dynu.net", "freedns.afraid.org", "mooo.com", "chickenkiller.com", "dynv6.net")


async def resolve(ctx: AssessmentContext, name: str, rtype: str) -> dict[str, Any]:
    """{"status": int, "answers": [(data, ttl)]}. Status 0 = NOERROR, 3 = NXDOMAIN."""
    async def fetch(api: ApiClient) -> dict[str, Any]:
        d = await api.get_json(DOH, params={"name": name, "type": rtype})
        if not isinstance(d, dict) or "Status" not in d:
            raise ApiUnavailable("dns: unexpected response")
        want = TYPES[rtype]
        answers = [(str(a.get("data", "")), int(a.get("TTL", 0))) for a in d.get("Answer") or []
                   if isinstance(a, dict) and a.get("type") == want]
        return {"status": int(d["Status"]), "answers": answers}
    return await cached_json(ctx, "dns", f"{rtype}:{name}", fetch)


def _txt(answers: list[tuple[str, int]]) -> list[str]:
    return [a.strip('"').replace('" "', "") for a, _ in answers]


def analyze(host: str, domain: str, a: dict, ns: dict, txt: dict, dmarc: dict, now) -> list[Finding]:
    out: list[Finding] = []
    ips = sorted({d for d, _ in a["answers"] if _is_ip(d)})
    ttls = [t for _, t in a["answers"]]
    nets = {str(ipaddress.ip_network(f"{ip}/16", strict=False)) for ip in ips if ipaddress.ip_address(ip).version == 4}
    if len(ips) >= FLUX_MIN_IPS and len(nets) >= FLUX_MIN_NETS and ttls and min(ttls) <= FLUX_MAX_TTL:
        out.append(make_finding(
            "DOMAIN.FAST_FLUX", f"{host} resolves to {len(ips)} addresses in {len(nets)} networks with a {min(ttls)} s TTL",
            [evidence("dns_a", f"A records: {', '.join(ips[:8])}{'…' if len(ips) > 8 else ''}; lowest TTL {min(ttls)} s",
                      SOURCE, {"host": host, "ips": ips[:20], "networks": sorted(nets), "min_ttl": min(ttls)},
                      observed_at=now)],
            "Rapidly rotating addresses across unrelated networks are used to keep phishing and malware sites online.",
            "Treat this site with caution, especially if it asks for logins or payment.",
            limitation="Large CDNs can look similar; this is a hint, not proof."))

    servers = sorted({d.lower().rstrip(".") for d, _ in ns["answers"]})
    free = [s for s in servers if s.endswith(FREE_DNS_NS)]
    dyn = host.endswith(DYNAMIC_HOST_SUFFIXES)
    if free or dyn:
        what = f"nameservers {', '.join(free)}" if free else f"dynamic-DNS host {host}"
        out.append(make_finding(
            "DOMAIN.FREE_DNS", f"{domain} uses a free or dynamic DNS service",
            [evidence("dns_ns", f"Found {what}", SOURCE, {"domain": domain, "nameservers": servers, "dynamic_host": dyn},
                      observed_at=now)],
            "Free and dynamic DNS needs no identity, so it is popular for short-lived scam sites.",
            "Check the site's identity through an official channel before trusting it.",
            limitation="Hobbyists and small projects use these services legitimately."))

    if txt["status"] == 0:  # posture only when the domain answered
        spf = [t for t in _txt(txt["answers"]) if t.lower().startswith("v=spf1")]
        if not spf:
            out.append(_posture("POSTURE.NO_SPF", f"{domain} publishes no SPF record", domain,
                                "No v=spf1 TXT record", "Anyone can send email claiming to be from this domain more easily.",
                                "Publish an SPF record listing the servers allowed to send this domain's mail.", now))
        rec = next((t for t in _txt(dmarc["answers"]) if t.lower().startswith("v=dmarc1")), None)
        if rec is None:
            out.append(_posture("POSTURE.NO_DMARC", f"{domain} publishes no DMARC policy", domain,
                                f"No v=DMARC1 TXT record at _dmarc.{domain}",
                                "Receivers have no instruction to reject email that fakes this domain.",
                                "Publish a DMARC record, then move from p=none to p=quarantine or p=reject.", now))
        elif "p=none" in rec.replace(" ", "").lower():
            out.append(_posture("POSTURE.DMARC_NOT_ENFORCED", f"{domain}'s DMARC policy is p=none", domain,
                                f"DMARC record: {rec[:120]}", "Spoofed email is reported but still delivered.",
                                "Move the DMARC policy to p=quarantine or p=reject once reports look clean.", now))
    return out


def _posture(cid: str, title: str, domain: str, summary: str, impact: str, fix: str, now) -> Finding:
    return make_finding(cid, title, [evidence("dns_txt", summary, SOURCE, {"domain": domain}, observed_at=now)], impact, fix,
                        limitation="Email authentication is about spoofed email, not about whether this website is safe.")


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


async def run(ctx: AssessmentContext) -> CheckResult:
    t0 = time.monotonic()
    try:
        if ctx.url.ip is not None:
            return make_run(GROUP, CheckStatus.SKIPPED, SOURCE, t0, "IP address host has no DNS records"), []
        host = ctx.url.host
        domain = icann_registrable_domain(host)
        a, ns, txt, dmarc = await asyncio.gather(resolve(ctx, host, "A"), resolve(ctx, domain, "NS"),
                                                 resolve(ctx, domain, "TXT"), resolve(ctx, f"_dmarc.{domain}", "TXT"))
        if a["status"] == 3 and ns["status"] == 3:
            return make_run(GROUP, CheckStatus.COMPLETED, SOURCE, t0, f"{domain} does not exist in DNS (NXDOMAIN)"), []
        servers = {d.lower().rstrip(".") for d, _ in ns["answers"]}
        ctx.nameservers = sorted(set(ctx.nameservers) | servers)  # correlation indicators, merged with RDAP's
        return make_run(GROUP, CheckStatus.COMPLETED, SOURCE, t0), analyze(host, domain, a, ns, txt, dmarc, ctx.now)
    except ApiUnavailable as e:
        return make_run(GROUP, CheckStatus.UNAVAILABLE, SOURCE, t0, str(e)), []
    except Exception as e:  # noqa: BLE001
        return make_run(GROUP, CheckStatus.FAILED, SOURCE, t0, f"error: {type(e).__name__}"), []
