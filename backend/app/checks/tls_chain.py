"""TLS.* certificate checks (groups tls.chain and tls.revocation).

`scan_tls` is a thin sslyze adapter (certificate_info only) that connects to an IP validated by safe_fetch's
policy; everything else is pure analysis of a `TlsScan`, so tests build scans from fixture certificates.

What we claim: we flag CAs on a curated distrust list (matched by cert AND SPKI SHA-256, which also catches
cross-signed copies of a compromised key), removed roots, revocation, and chain/config problems. We cannot
detect a CA's internal key-generation weakness from a URL.
"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import cache

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID, NameOID

from app.brands import DATA_DIR
from app.checks.base import AssessmentContext, CheckResult, evidence, make_finding, make_run
from app.fetch.safe_fetch import BINARY_TYPES, FetchBlocked, check_url_policy, resolve_and_validate, safe_fetch
from app.schemas import CertificateSummary, CheckStatus, Finding
from app.urlutil import URLParseError, parse_url

SOURCE = "local:tls_inspector"
GROUP = "tls.chain"
REV_GROUP = "tls.revocation"
SCAN_TIMEOUT_S = 10.0
MOZILLA = "mozilla"
CA_LIMITATION = ("We flag certificate authorities on curated distrust lists; we cannot detect a CA's internal "
                 "key-generation weakness from a URL.")


# ---------------- scan model ----------------

@dataclass
class TlsScan:
    hostname: str
    port: int
    ip: str | None = None
    received_chain: list[x509.Certificate] = field(default_factory=list)
    store_results: dict[str, bool] = field(default_factory=dict)  # trust store name (lowercase) -> validated
    store_errors: dict[str, str] = field(default_factory=dict)
    verified_chain: list[x509.Certificate] = field(default_factory=list)
    sct_count: int | None = None
    stapled_ocsp: ocsp.OCSPResponse | None = None
    tls_version: str | None = None
    error: str | None = None
    blocked: bool = False

    @property
    def leaf(self) -> x509.Certificate | None:
        return self.received_chain[0] if self.received_chain else None


async def scan_tls(hostname: str, port: int) -> TlsScan:
    """Policy-check, resolve+validate, then run sslyze certificate_info against the validated IP. Never raises."""
    scan = TlsScan(hostname=hostname, port=port)
    try:
        # Same scheme/port/hostname policy as safe_fetch (80/443/8080/8443 only), before any socket.
        check_url_policy(parse_url(f"https://{hostname}:{port}/"))
        ips = await resolve_and_validate(hostname, port)
    except (FetchBlocked, URLParseError) as e:
        scan.error, scan.blocked = f"blocked: {e}", True
        return scan
    scan.ip = str(ips[0])
    try:
        await asyncio.wait_for(asyncio.to_thread(_sslyze_scan, scan), SCAN_TIMEOUT_S)
    except TimeoutError:
        scan.error = "TLS scan timed out"
    except Exception as e:  # noqa: BLE001
        scan.error = f"TLS scan error: {type(e).__name__}"
    return scan


def _sslyze_scan(scan: TlsScan) -> None:
    from sslyze import (
        ScanCommand,
        ScanCommandAttemptStatusEnum,
        Scanner,
        ServerNetworkLocation,
        ServerScanRequest,
        ServerScanStatusEnum,
    )
    loc = ServerNetworkLocation(scan.hostname, scan.port, ip_address=scan.ip)  # no DNS inside sslyze
    scanner = Scanner()
    scanner.queue_scans([ServerScanRequest(server_location=loc, scan_commands={ScanCommand.CERTIFICATE_INFO})])
    for result in scanner.get_results():
        if result.scan_status != ServerScanStatusEnum.COMPLETED:
            scan.error = f"TLS connection failed: {result.connectivity_error_trace.__class__.__name__}" \
                if result.connectivity_error_trace else "TLS connection failed"
            return
        if result.connectivity_result is not None:
            scan.tls_version = result.connectivity_result.highest_tls_version_supported.name.replace("_", ".") \
                .replace("TLS.", "TLSv").replace("SSL.", "SSLv")
        attempt = result.scan_result.certificate_info
        if attempt.status != ScanCommandAttemptStatusEnum.COMPLETED or attempt.result is None:
            scan.error = "certificate_info scan failed"
            return
        dep = attempt.result.certificate_deployments[0]
        scan.received_chain = list(dep.received_certificate_chain)
        scan.sct_count = dep.leaf_certificate_signed_certificate_timestamps_count
        scan.stapled_ocsp = dep.ocsp_response
        for pv in dep.path_validation_results:
            name = pv.trust_store.name.lower().split()[0]
            ok = pv.was_validation_successful
            scan.store_results[name] = ok
            if not ok and pv.validation_error:
                scan.store_errors[name] = str(pv.validation_error)[:200]
            if ok and (name == MOZILLA or not scan.verified_chain):
                scan.verified_chain = list(pv.verified_certificate_chain or [])


# ---------------- distrust list ----------------

@dataclass(frozen=True)
class DistrustList:
    cert_hashes: dict[str, str]  # sha256 hex upper -> entry name
    spki_hashes: dict[str, str]
    removed_roots: list[dict]


@cache
def distrust_list() -> DistrustList:
    doc = json.loads((DATA_DIR / "distrusted_cas.json").read_text())
    certs, spkis = {}, {}
    for e in doc["entries"]:
        if e.get("cert_sha256"):
            certs[e["cert_sha256"].upper()] = e["name"]
        if e.get("spki_sha256"):
            spkis[e["spki_sha256"].upper()] = e.get("cross_sign_of") or e["name"]
    return DistrustList(certs, spkis, doc.get("removed_roots", []))


def cert_sha256(c: x509.Certificate) -> str:
    return hashlib.sha256(c.public_bytes(Encoding.DER)).hexdigest().upper()


def spki_sha256(c: x509.Certificate) -> str:
    return hashlib.sha256(c.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)) \
        .hexdigest().upper()


def _cn(name: x509.Name) -> str | None:
    a = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(a[0].value) if a else None


def _org(name: x509.Name) -> str | None:
    a = name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    return str(a[0].value) if a else None


def _as_list(v) -> list[str]:
    if not v:
        return []
    return [x.upper() for x in (v if isinstance(v, list) else [v])]


# ---------------- helpers ----------------

def _sans(c: x509.Certificate) -> tuple[list[str], list[str]]:
    try:
        ext = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return [], []
    return [d.lower() for d in ext.get_values_for_type(x509.DNSName)], \
        [str(i) for i in ext.get_values_for_type(x509.IPAddress)]


def hostname_matches(c: x509.Certificate, host: str) -> bool:
    host = host.lower().rstrip(".")
    dns, ips = _sans(c)
    try:
        ip = ipaddress.ip_address(host)
        return str(ip) in ips
    except ValueError:
        pass
    for pat in dns:
        if pat == host:
            return True
        if pat.startswith("*.") and "." in host:
            if host.split(".", 1)[1] == pat[2:] and host.split(".", 1)[0]:
                return True
    return False


def is_self_signed(c: x509.Certificate) -> bool:
    if c.issuer != c.subject:
        return False
    try:
        c.verify_directly_issued_by(c)
        return True
    except (UnsupportedAlgorithm, ValueError) as e:
        return _unsupported(e) and _key_ids_match(c, c)
    except (TypeError, InvalidSignature):
        return False


def key_info(c: x509.Certificate) -> tuple[str, int]:
    k = c.public_key()
    if isinstance(k, rsa.RSAPublicKey):
        return "RSA", k.key_size
    if isinstance(k, ec.EllipticCurvePublicKey):
        return "EC", k.curve.key_size
    if isinstance(k, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(k, ed448.Ed448PublicKey):
        return "other", 456
    if isinstance(k, dsa.DSAPublicKey):
        return "other", k.key_size
    return "other", 0


def sig_name(c: x509.Certificate) -> str:
    return getattr(c.signature_algorithm_oid, "_name", None) or c.signature_algorithm_oid.dotted_string


def _weak_sig(c: x509.Certificate) -> bool:
    h = c.signature_hash_algorithm
    return h is not None and h.name in ("sha1", "md5", "md2")


def _utc(dt: datetime) -> datetime:
    return dt.astimezone(UTC).replace(microsecond=0)


def _unsupported(e: Exception) -> bool:
    return isinstance(e, UnsupportedAlgorithm) or "unsupported" in str(e).lower()


def _key_ids_match(child: x509.Certificate, parent: x509.Certificate) -> bool:
    try:
        aki = child.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier
        ski = parent.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
    except x509.ExtensionNotFound:
        return True  # nothing to contradict the name match
    return aki is None or aki == ski


def find_issuer(leaf: x509.Certificate, pool: list[x509.Certificate]) -> x509.Certificate | None:
    for c in pool:
        if c is leaf or c.subject != leaf.issuer:
            continue
        try:
            leaf.verify_directly_issued_by(c)
            return c
        except (UnsupportedAlgorithm, ValueError) as e:
            # e.g. SHA-1 signatures, which this crypto backend refuses to verify: fall back to name + key-id match.
            if _unsupported(e) and _key_ids_match(leaf, c):
                return c
        except (TypeError, InvalidSignature):
            continue
    return None


# ---------------- analysis ----------------

def _ev(desc: str, data: dict, now: datetime) -> list:
    return [evidence("certificate_field", desc, SOURCE, data, observed_at=now)]


def analyze(scan: TlsScan, now: datetime) -> tuple[list[Finding], CertificateSummary | None]:
    leaf = scan.leaf
    if leaf is None:
        return [], None
    out: list[Finding] = []
    dl = distrust_list()
    chain_all = list(scan.received_chain) + [c for c in scan.verified_chain
                                             if cert_sha256(c) not in {cert_sha256(x) for x in scan.received_chain}]

    # Distrusted CA (cert or SPKI hash)
    hits = []
    for c in chain_all:
        ch, sh = cert_sha256(c), spki_sha256(c)
        if ch in dl.cert_hashes:
            hits.append({"name": dl.cert_hashes[ch], "match": "cert_sha256", "cert_sha256": ch,
                         "subject": c.subject.rfc4514_string()})
        elif sh in dl.spki_hashes:
            hits.append({"name": dl.spki_hashes[sh], "match": "spki_sha256", "spki_sha256": sh,
                         "subject": c.subject.rfc4514_string()})
    if hits:
        out.append(make_finding(
            "TLS.DISTRUSTED_CA", f"Certificate chain includes a distrusted CA ({hits[0]['name']})",
            [evidence("certificate_field", f"{h['subject']} matches distrust entry '{h['name']}' by {h['match']}",
                      SOURCE, h, observed_at=now) for h in hits],
            "This CA's signing key is known to be compromised; anyone holding it could issue certificates for any "
            "site. Browsers block it, but apps with bundled trust stores may not.",
            "Do not trust this connection. If you run this site, replace the certificate immediately.",
            limitation=CA_LIMITATION))
    else:
        rr = _removed_root(chain_all, dl)
        if rr:
            out.append(make_finding(
                "TLS.REMOVED_ROOT", f"Chain leads to a root removed from browser trust stores ({rr['root']})",
                _ev(f"{rr['subject']} {rr['how']} '{rr['root']}'", rr, now),
                "Browsers no longer trust this root; older clients and bundled trust stores may still do so.",
                "Site owners should move to a certificate from a different CA.", limitation=CA_LIMITATION))

    nb, na = _utc(leaf.not_valid_before_utc), _utc(leaf.not_valid_after_utc)
    expired, not_yet = na < now, nb > now
    if expired:
        out.append(make_finding("TLS.EXPIRED", f"Certificate expired on {na.date()}",
                                _ev(f"notAfter {na.isoformat()}", {"not_after": na.isoformat()}, now),
                                "Expired certificates are not checked for revocation and break trust.",
                                "Do not enter information on this site."))
    if not_yet:
        out.append(make_finding("TLS.NOT_YET_VALID", f"Certificate not valid until {nb.date()}",
                                _ev(f"notBefore {nb.isoformat()}", {"not_before": nb.isoformat()}, now),
                                "The certificate is not yet valid, which indicates misconfiguration or tampering.",
                                "Do not enter information on this site."))

    self_signed = is_self_signed(leaf)
    if self_signed:
        out.append(make_finding("TLS.SELF_SIGNED", "Certificate is self-signed",
                                _ev(f"Issuer equals subject ({leaf.subject.rfc4514_string()})",
                                    {"subject": leaf.subject.rfc4514_string()}, now),
                                "Anyone can create a self-signed certificate; it proves nothing about identity.",
                                "Do not enter information on this site."))

    moz = scan.store_results.get(MOZILLA)
    chain_valid = bool(moz) if moz is not None else any(scan.store_results.values())
    if scan.store_results and not chain_valid and not self_signed:
        err = scan.store_errors.get(MOZILLA, "")
        explained = expired or not_yet or any(w in err.lower() for w in ("expired", "not yet valid"))
        if not explained:
            out.append(make_finding(
                "TLS.UNTRUSTED_ROOT", "Certificate chain is not trusted by the Mozilla root store",
                _ev(f"Path validation failed: {err or 'no trusted path'}",
                    {"stores": dict(sorted(scan.store_results.items())), "error": err}, now),
                "The certificate was not issued by a publicly trusted authority.",
                "Do not enter information on this site."))

    if not hostname_matches(leaf, scan.hostname):
        dns, _ = _sans(leaf)
        out.append(make_finding("TLS.HOSTNAME_MISMATCH", f"Certificate is not valid for {scan.hostname}",
                                _ev(f"SANs: {', '.join(dns[:10]) or 'none'}",
                                    {"hostname": scan.hostname, "san": dns[:20]}, now),
                                "The certificate belongs to a different site.",
                                "Do not enter information on this site."))

    weak_keys, weak_sigs = [], []
    for c in scan.received_chain:
        kt, kb = key_info(c)
        if (kt == "RSA" and kb < 2048) or (kt == "EC" and kb < 256):
            weak_keys.append(f"{_cn(c.subject)}: {kt}-{kb}")
        if not is_self_signed(c) and _weak_sig(c):
            weak_sigs.append(f"{_cn(c.subject)}: {sig_name(c)}")
    if weak_keys:
        out.append(make_finding("TLS.WEAK_KEY", "Certificate uses a weak key",
                                _ev("; ".join(weak_keys), {"weak_keys": weak_keys}, now),
                                "Short keys can be broken, letting an attacker impersonate the site.",
                                "Site owners should reissue with RSA-2048+ or ECDSA P-256+."))
    if weak_sigs:
        out.append(make_finding("TLS.WEAK_SIGNATURE", "Certificate chain uses a broken signature algorithm",
                                _ev("; ".join(weak_sigs), {"weak_signatures": weak_sigs}, now),
                                "SHA-1/MD5 signatures can be forged.",
                                "Site owners should reissue with a SHA-256 signature."))

    if not self_signed and find_issuer(leaf, scan.received_chain) is None:
        out.append(make_finding("TLS.INCOMPLETE_CHAIN", "Server does not send its intermediate certificate",
                                _ev(f"Issuer '{_cn(leaf.issuer)}' not in the presented chain",
                                    {"issuer": leaf.issuer.rfc4514_string(), "presented": len(scan.received_chain)},
                                    now),
                                "Some clients will fail to connect. This is a configuration issue, not a compromise.",
                                "Site owners should serve the full chain."))

    age = now - nb
    if timedelta(0) <= age < timedelta(days=7):
        out.append(make_finding("TLS.CERT_VERY_NEW", f"Certificate issued {age.days} day(s) ago",
                                _ev(f"notBefore {nb.isoformat()}", {"not_before": nb.isoformat()}, now),
                                "A valid certificate only proves the connection is encrypted, not that the site is "
                                "legitimate. Phishing sites usually have brand-new certificates.",
                                "Do not treat the padlock as proof of legitimacy."))

    kt, kb = key_info(leaf)
    dns, ip_sans = _sans(leaf)
    issuer_cn, issuer_o = _cn(leaf.issuer), _org(leaf.issuer)
    summary = CertificateSummary(
        subject_cn=_cn(leaf.subject), san=(dns + ip_sans)[:50],
        issuer=f"{issuer_cn} ({issuer_o})" if issuer_cn and issuer_o else (issuer_cn or leaf.issuer.rfc4514_string()),
        chain_issuers=[_cn(c.issuer) or c.issuer.rfc4514_string() for c in (scan.verified_chain or scan.received_chain)
                       if not is_self_signed(c)][:6] or [issuer_cn or ""],
        not_before=nb, not_after=na, days_remaining=(na - now).days, key_type=kt, key_bits=kb,
        signature_algorithm=sig_name(leaf), sha256_fingerprint=cert_sha256(leaf).lower(),
        ct_sct_count=scan.sct_count or 0, chain_valid=chain_valid, tls_version=scan.tls_version)
    return out, summary


def _removed_root(chain: list[x509.Certificate], dl: DistrustList) -> dict | None:
    for root in dl.removed_roots:
        name = root["name"]
        spkis, certs = set(_as_list(root.get("spki_sha256"))), set(_as_list(root.get("cert_sha256")))
        for c in chain:
            if cert_sha256(c) in certs or spki_sha256(c) in spkis or (_cn(c.subject) == name and is_self_signed(c)):
                return {"root": name, "subject": c.subject.rfc4514_string(), "how": "is"}
        top = chain[-1] if chain else None
        if top is not None and _cn(top.issuer) == name and not is_self_signed(top):
            return {"root": name, "subject": top.subject.rfc4514_string(), "how": "is issued by"}
    return None


# ---------------- revocation ----------------

def _verify_sig(pub, signature: bytes, data: bytes, h: hashes.HashAlgorithm | None) -> bool:
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(signature, data, padding.PKCS1v15(), h)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(signature, data, ec.ECDSA(h))
        elif isinstance(pub, ed25519.Ed25519PublicKey | ed448.Ed448PublicKey):
            pub.verify(signature, data)
        else:
            return False
        return True
    except (InvalidSignature, TypeError, ValueError):
        return False


def ocsp_status(resp: ocsp.OCSPResponse, leaf: x509.Certificate, issuer: x509.Certificate | None) -> str:
    """'good' | 'revoked' | 'unknown'. The response must be signed by the issuer or a delegated responder."""
    if resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        return "unknown"
    try:
        if resp.serial_number != leaf.serial_number:
            return "unknown"
        if issuer is not None:
            signer = issuer
            for rc in resp.certificates:
                try:
                    rc.verify_directly_issued_by(issuer)
                    signer = rc
                    break
                except (ValueError, TypeError, InvalidSignature):
                    continue
            if not _verify_sig(signer.public_key(), resp.signature, resp.tbs_response_bytes,
                               resp.signature_hash_algorithm):
                return "unknown"
        st = resp.certificate_status
    except ValueError:
        return "unknown"
    return {ocsp.OCSPCertStatus.GOOD: "good", ocsp.OCSPCertStatus.REVOKED: "revoked"}.get(st, "unknown")


def _aia(leaf: x509.Certificate, oid) -> list[str]:
    try:
        ext = leaf.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
    except x509.ExtensionNotFound:
        return []
    return [d.access_location.value for d in ext if d.access_method == oid
            and isinstance(d.access_location, x509.UniformResourceIdentifier)]


def _crl_urls(leaf: x509.Certificate) -> list[str]:
    try:
        ext = leaf.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).value
    except x509.ExtensionNotFound:
        return []
    return [n.value for dp in ext for n in (dp.full_name or []) if isinstance(n, x509.UniformResourceIdentifier)]


async def check_revocation(scan: TlsScan, now: datetime | None = None) -> tuple[str, str, str]:
    """Returns (status, method, detail). All network goes through safe_fetch: OCSP/CRL URLs come from the cert."""
    leaf = scan.leaf
    if leaf is None:
        return "unknown", "none", "no certificate"
    if leaf.not_valid_after_utc < (now or datetime.now(UTC)):
        return "unknown", "none", "certificate expired; CAs do not maintain revocation status for expired certificates"
    issuer = find_issuer(leaf, scan.received_chain + scan.verified_chain)
    if scan.stapled_ocsp is not None:
        st = ocsp_status(scan.stapled_ocsp, leaf, issuer)
        if st != "unknown":
            return st, "ocsp_stapled", "stapled OCSP response"
    if issuer is None:
        return "unknown", "none", "issuer certificate not available"
    for url in _aia(leaf, AuthorityInformationAccessOID.OCSP)[:1]:
        req = ocsp.OCSPRequestBuilder().add_certificate(leaf, issuer, hashes.SHA1()).build()
        fr = await safe_fetch(url, method="POST", body=req.public_bytes(Encoding.DER), max_hops=2,
                              headers={"Content-Type": "application/ocsp-request"}, allowed_types=BINARY_TYPES)
        if fr.ok:
            try:
                st = ocsp_status(ocsp.load_der_ocsp_response(fr.body), leaf, issuer)
            except ValueError:
                st = "unknown"
            if st != "unknown":
                return st, "ocsp", url
    for url in _crl_urls(leaf)[:1]:
        fr = await safe_fetch(url, max_hops=2, allowed_types=BINARY_TYPES)
        if not fr.ok:
            continue
        try:
            crl = x509.load_der_x509_crl(fr.body)
        except ValueError:
            try:
                crl = x509.load_pem_x509_crl(fr.body)
            except ValueError:
                continue
        if not crl.is_signature_valid(issuer.public_key()):
            continue
        return ("revoked" if crl.get_revoked_certificate_by_serial_number(leaf.serial_number) else "good"), "crl", url
    return "unknown", "none", "no reachable OCSP responder or CRL"


# ---------------- runs ----------------

async def _target(ctx: AssessmentContext) -> tuple[str, str, int]:
    """(scheme, host, port) of the URL whose TLS we inspect: the final URL if https, else the submitted one."""
    fr = await ctx.fetch()
    final = parse_url(fr.final_url) if fr.final_url else None
    if final and final.scheme == "https":
        return "https", final.host, final.port
    if ctx.url.scheme == "https":
        return "https", ctx.url.host, ctx.url.port
    return "http", (final or ctx.url).host, (final or ctx.url).port


async def run(ctx: AssessmentContext) -> CheckResult:
    t0 = time.monotonic()
    try:
        scheme, host, port = await _target(ctx)
        if scheme != "https":
            f = make_finding("TLS.NO_HTTPS", "Site does not use HTTPS",
                             [evidence("http_redirect", f"{host} was served over plain HTTP", SOURCE,
                                       {"host": host}, observed_at=ctx.now)],
                             "Anything you type can be read or changed by others on the network.",
                             "Never enter passwords, OTPs or card details on a non-HTTPS page.")
            return make_run(GROUP, CheckStatus.SKIPPED, SOURCE, t0, "no HTTPS endpoint"), [f]
        scan = await ctx.tls_scan(host, port)
        if scan.leaf is None:
            status = CheckStatus.FAILED if not scan.blocked else CheckStatus.SKIPPED
            return make_run(GROUP, status, SOURCE, t0, scan.error or "no certificate received"), []
        findings, summary = analyze(scan, ctx.now)
        ctx.certificate = summary
        return make_run(GROUP, CheckStatus.COMPLETED, SOURCE, t0), findings
    except Exception as e:  # noqa: BLE001
        return make_run(GROUP, CheckStatus.FAILED, SOURCE, t0, f"error: {type(e).__name__}"), []


async def run_revocation(ctx: AssessmentContext) -> CheckResult:
    t0 = time.monotonic()
    try:
        scheme, host, port = await _target(ctx)
        if scheme != "https":
            return make_run(REV_GROUP, CheckStatus.SKIPPED, SOURCE, t0, "no HTTPS endpoint"), []
        scan = await ctx.tls_scan(host, port)
        if scan.leaf is None:
            return make_run(REV_GROUP, CheckStatus.FAILED, SOURCE, t0, scan.error or "no certificate"), []
        status, method, detail = await check_revocation(scan, ctx.now)
        ctx.revocation_status = status
        if status == "unknown":
            return make_run(REV_GROUP, CheckStatus.UNAVAILABLE, SOURCE, t0,
                            f"revocation status unknown: {detail}"), []
        findings = []
        if status == "revoked":
            findings.append(make_finding(
                "TLS.REVOKED", "Certificate has been revoked by its issuer",
                [evidence("certificate_field", f"{method.upper()} reports the certificate as revoked", SOURCE,
                          {"method": method, "responder": detail,
                           "serial": format(scan.leaf.serial_number, "x")}, observed_at=ctx.now)],
                "The issuing CA has withdrawn this certificate, typically because the key was compromised or "
                "the certificate was mis-issued.",
                "Do not use this site."))
        return make_run(REV_GROUP, CheckStatus.COMPLETED, f"local:{method}", t0), findings
    except Exception as e:  # noqa: BLE001
        return make_run(REV_GROUP, CheckStatus.FAILED, SOURCE, t0, f"error: {type(e).__name__}"), []
