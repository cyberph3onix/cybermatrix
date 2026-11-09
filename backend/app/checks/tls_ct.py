"""Certificate Transparency checks (group tls.ct): Cert Spotter issuances first, crt.sh fallback, 6 s each.

Both sources being down is fine: the group becomes `unavailable` and the assessment continues.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from cryptography import x509

from app.checks.base import AssessmentContext, CheckResult, evidence, make_finding, make_run
from app.checks.tls_chain import _org, _target, cert_sha256, spki_sha256
from app.fetch.api_client import ApiClient, ApiUnavailable
from app.schemas import CheckStatus, Finding

GROUP = "tls.ct"
CERTSPOTTER = "https://api.certspotter.com/v1/issuances"
CRTSH = "https://crt.sh/"
TIMEOUT_S = 6.0
NEW_DAYS = 7
# Chrome began requiring CT for all newly issued publicly-trusted certificates on 2018-04-30.
CT_REQUIRED_FROM = datetime(2018, 4, 30, tzinfo=UTC)


@dataclass
class CtEntry:
    cert_sha256: str | None
    pubkey_sha256: str | None
    serial: str | None
    issuer_org: str | None
    not_before: datetime | None


def _dn_org(dn: str | None) -> str | None:
    if not dn:
        return None
    m = re.search(r"(?:^|,\s*)O=(\"[^\"]+\"|[^,]+)", dn)
    return m.group(1).strip('"').strip() if m else None


def _dt(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=UTC)


def _norm_serial(s: str | None) -> str | None:
    return s.lower().lstrip("0") if s else None


async def certspotter(api: ApiClient, host: str) -> list[CtEntry]:
    params = [("domain", host), ("include_subdomains", "false"), ("expand", "dns_names"), ("expand", "issuer")]
    rows = await api.get_json(CERTSPOTTER, params=params, bearer_env="CERTSPOTTER_API_KEY")
    if not isinstance(rows, list):
        raise ApiUnavailable("certspotter: unexpected response")
    out = []
    for r in rows:
        iss = r.get("issuer") or {}
        out.append(CtEntry(cert_sha256=(r.get("cert_sha256") or "").upper() or None,
                           pubkey_sha256=(r.get("pubkey_sha256") or "").upper() or None, serial=None,
                           issuer_org=_dn_org(iss.get("name")) or iss.get("friendly_name"),
                           not_before=_dt(r.get("not_before"))))
    return out


async def crtsh(api: ApiClient, host: str) -> list[CtEntry]:
    rows = await api.get_json(CRTSH, params={"q": host, "output": "json"})
    if not isinstance(rows, list):
        raise ApiUnavailable("crt.sh: unexpected response")
    return [CtEntry(cert_sha256=None, pubkey_sha256=None, serial=_norm_serial(r.get("serial_number")),
                    issuer_org=_dn_org(r.get("issuer_name")), not_before=_dt(r.get("not_before")))
            for r in rows]


def _found(leaf: x509.Certificate, entries: list[CtEntry]) -> bool:
    ch, sh = cert_sha256(leaf), spki_sha256(leaf)
    serial = format(leaf.serial_number, "x").lstrip("0")
    nb = leaf.not_valid_before_utc.replace(microsecond=0)
    for e in entries:
        if e.cert_sha256 and e.cert_sha256 == ch:
            return True
        if e.pubkey_sha256 and e.pubkey_sha256 == sh and e.not_before and abs(e.not_before - nb) < timedelta(
                minutes=5):
            return True
        if e.serial and e.serial == serial:
            return True
    return False


def analyze(leaf: x509.Certificate, sct_count: int | None, entries: list[CtEntry], source: str,
            now: datetime) -> tuple[list[Finding], bool]:
    out: list[Finding] = []
    found = _found(leaf, entries)
    logged = bool(sct_count) or found
    if not logged and leaf.not_valid_before_utc >= CT_REQUIRED_FROM:
        out.append(make_finding(
            "TLS.CT_NOT_LOGGED", "Certificate does not appear in public Certificate Transparency logs",
            [evidence("ct_entry", f"No embedded SCTs and not found in {source} ({len(entries)} entries checked)",
                      source, {"sct_count": sct_count or 0, "entries_checked": len(entries)}, observed_at=now)],
            "Publicly trusted certificates must be logged; an unlogged certificate may be private or mis-issued.",
            "Treat the connection's identity as unverified.",
            limitation="CT search indexes can lag new issuance by minutes to hours."))
    nb = leaf.not_valid_before_utc
    issuer = _org(leaf.issuer)
    if issuer and timedelta(0) <= now - nb < timedelta(days=NEW_DAYS):
        older = {e.issuer_org for e in entries if e.not_before and now - e.not_before >= timedelta(days=NEW_DAYS)
                 and e.issuer_org}
        if older and issuer not in older:
            out.append(make_finding(
                "TLS.CT_UNEXPECTED_ISSUER", f"New certificate from a CA this domain has never used ({issuer})",
                [evidence("ct_entry", f"Leaf issued by {issuer}; earlier certificates came from "
                          f"{', '.join(sorted(older)[:5])}", source,
                          {"issuer": issuer, "previous_issuers": sorted(older)[:10]}, observed_at=now)],
                "A sudden change of CA can indicate a hijacked domain or a mis-issued certificate.",
                "Be cautious; this is a weak signal on its own."))
    return out, logged


async def run(ctx: AssessmentContext) -> CheckResult:
    t0 = time.monotonic()
    try:
        scheme, host, port = await _target(ctx)
        if scheme != "https":
            return make_run(GROUP, CheckStatus.SKIPPED, "certspotter", t0, "no HTTPS endpoint"), []
        scan = await ctx.tls_scan(host, port)
        if scan.leaf is None:
            return make_run(GROUP, CheckStatus.UNAVAILABLE, "certspotter", t0, "no certificate to look up"), []
        api = ctx.api or ApiClient(timeout=TIMEOUT_S)
        errors = []
        try:
            for source, fn in (("certspotter", certspotter), ("crt.sh", crtsh)):
                try:
                    entries = await fn(api, scan.hostname)
                except ApiUnavailable as e:
                    errors.append(str(e))
                    continue
                findings, logged = analyze(scan.leaf, scan.sct_count, entries, source, ctx.now)
                ctx.ct_logged = logged
                detail = f"fallback after: {errors[0]}" if errors else None
                return make_run(GROUP, CheckStatus.COMPLETED, source, t0, detail), findings
        finally:
            if ctx.api is None:
                await api.aclose()
        return make_run(GROUP, CheckStatus.UNAVAILABLE, "certspotter", t0,
                        "CT sources unavailable: " + "; ".join(errors)), []
    except Exception as e:  # noqa: BLE001
        return make_run(GROUP, CheckStatus.FAILED, "certspotter", t0, f"error: {type(e).__name__}"), []
