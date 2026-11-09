import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import ocsp

from app.checks import tls_chain as tc
from app.checks.base import AssessmentContext
from app.fetch.safe_fetch import FetchResult
from app.urlutil import parse_url
from tests.certgen import NOW, make_ca, make_leaf, rsa_key
from tests.conftest import fake_fetcher, fetch_result

CERTS = Path(__file__).parent / "fixtures" / "certs"
EMUDHRA_EV_G3B = CERTS / "emudhra" / "em_ev_tls_ca_g3b.pem"


def load(p: Path) -> list[x509.Certificate]:
    return x509.load_pem_x509_certificates(p.read_bytes())


def scan_of(chain, host="shop.example.com", trusted=True, **kw):
    return tc.TlsScan(hostname=host, port=443, ip="93.184.216.34", received_chain=list(chain),
                      store_results={"mozilla": trusted, "apple": trusted}, sct_count=2, **kw)


def ids(scan):
    return {f.check_id for f in tc.analyze(scan, NOW)[0]}


@pytest.fixture(scope="module")
def pki():
    return make_ca()


def test_clean_chain(pki):
    ca, key = pki
    leaf, _ = make_leaf(ca, key)
    findings, summary = tc.analyze(scan_of([leaf, ca]), NOW)
    assert findings == []
    assert summary.chain_valid and summary.key_type == "EC" and summary.key_bits == 256
    assert summary.days_remaining == 60 and summary.sha256_fingerprint == tc.cert_sha256(leaf).lower()


def test_expired_does_not_double_count_untrusted(pki):
    ca, key = pki
    leaf, _ = make_leaf(ca, key, nb=NOW - timedelta(days=400), na=NOW - timedelta(days=5))
    s = scan_of([leaf, ca], trusted=False, store_errors={"mozilla": "certificate has expired"})
    assert ids(s) == {"TLS.EXPIRED"}


def test_not_yet_valid(pki):
    ca, key = pki
    leaf, _ = make_leaf(ca, key, nb=NOW + timedelta(days=3), na=NOW + timedelta(days=90))
    assert "TLS.NOT_YET_VALID" in ids(scan_of([leaf, ca]))


def test_self_signed(pki):
    ca, key = pki
    leaf, _ = make_leaf(ca, key, self_signed=True)
    assert ids(scan_of([leaf], trusted=False)) == {"TLS.SELF_SIGNED"}


def test_untrusted_root(pki):
    ca, key = pki
    leaf, _ = make_leaf(ca, key)
    assert ids(scan_of([leaf, ca], trusted=False, store_errors={"mozilla": "unable to get local issuer"})) == \
        {"TLS.UNTRUSTED_ROOT"}


def test_hostname_mismatch_and_wildcards(pki):
    ca, key = pki
    leaf, _ = make_leaf(ca, key, san=["*.example.org", "example.org"])
    assert ids(scan_of([leaf, ca], host="shop.example.com")) == {"TLS.HOSTNAME_MISMATCH"}
    assert ids(scan_of([leaf, ca], host="a.example.org")) == set()
    assert ids(scan_of([leaf, ca], host="a.b.example.org")) == {"TLS.HOSTNAME_MISMATCH"}


def test_weak_key(pki):
    ca, key = pki
    leaf, _ = make_leaf(ca, key, key=rsa_key(1024))
    assert ids(scan_of([leaf, ca])) == {"TLS.WEAK_KEY"}


def test_weak_signature_fixture():
    chain = load(CERTS / "sha1_leaf_chain.pem")
    at = chain[0].not_valid_before_utc + timedelta(days=30)
    assert {f.check_id for f in tc.analyze(scan_of(chain, host="sha1.example.test"), at)[0]} == \
        {"TLS.WEAK_SIGNATURE"}


def test_incomplete_chain(pki):
    ca, key = pki
    leaf, _ = make_leaf(ca, key)
    assert ids(scan_of([leaf])) == {"TLS.INCOMPLETE_CHAIN"}


def test_cert_very_new(pki):
    ca, key = pki
    leaf, _ = make_leaf(ca, key, nb=NOW - timedelta(days=2))
    assert ids(scan_of([leaf, ca])) == {"TLS.CERT_VERY_NEW"}


# ---- distrust list: real public eMudhra intermediate; nothing is ever signed with its key ----

def test_distrust_list_loaded():
    dl = tc.distrust_list()
    assert "E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838" in dl.cert_hashes
    assert dl.spki_hashes, "spki_sha256 must be filled by scripts/fill_distrusted_spki.py"


def test_distrusted_intermediate_by_cert_hash(pki):
    ca, key = pki
    emudhra = load(EMUDHRA_EV_G3B)[0]
    leaf, _ = make_leaf(ca, key)  # throwaway leaf; it does not need to verify against the intermediate
    findings, _ = tc.analyze(scan_of([leaf, emudhra], trusted=False), NOW)
    f = next(f for f in findings if f.check_id == "TLS.DISTRUSTED_CA")
    assert f.severity == "critical" and f.strength == "authoritative"
    assert f.evidence[0].data["match"] == "cert_sha256"
    assert "TLS.REMOVED_ROOT" not in {x.check_id for x in findings}
    assert "key-generation" in f.limitation


def test_distrusted_by_spki_only(pki):
    """Cross-sign stand-in: a NEW cert (different subject, signed by OUR test CA) carrying the eMudhra public key."""
    ca, key = pki
    emudhra = load(EMUDHRA_EV_G3B)[0]
    xsign, _ = make_leaf(ca, key, cn="Some Cross-Signed CA", public_key=emudhra.public_key())
    assert tc.cert_sha256(xsign) not in tc.distrust_list().cert_hashes
    leaf, _ = make_leaf(ca, key)
    f = next(f for f in tc.analyze(scan_of([leaf, xsign]), NOW)[0] if f.check_id == "TLS.DISTRUSTED_CA")
    assert f.evidence[0].data["match"] == "spki_sha256"


def test_real_sectigo_cross_sign_matches():
    xs = sorted((CERTS / "emudhra").glob("em_ev_tls_ca_g3b__xsign_*.pem"))
    assert xs, "cross-sign fixture missing"
    cert = load(xs[0])[0]
    assert tc.spki_sha256(cert) == tc.spki_sha256(load(EMUDHRA_EV_G3B)[0])
    assert "TLS.DISTRUSTED_CA" in {f.check_id for f in tc.analyze(scan_of([cert]), NOW)[0]}


DISTRUST_DOC = json.loads((Path(tc.DATA_DIR) / "distrusted_cas.json").read_text())
EMUDHRA_DIR = CERTS / "emudhra"


def test_distrust_list_invariant_eight_keys():
    """8 original intermediates, 8 distinct keys; every other entry re-uses one of those 8 keys."""
    entries = DISTRUST_DOC["entries"]
    originals = {e["name"]: e for e in entries if e["relation"] == "original"}
    assert len(originals) == 8
    orig_spkis = {e["spki_sha256"] for e in originals.values()}
    assert len(orig_spkis) == 8
    assert len({e["spki_sha256"] for e in entries}) == 8
    for e in entries:
        assert e["spki_sha256"] in orig_spkis, e["name"]
        assert e["spki_sha256"] == originals[e["derived_from"]]["spki_sha256"], e["name"]
    assert len({e["cert_sha256"] for e in entries}) == len(entries)


def test_distrust_list_provenance():
    for e in DISTRUST_DOC["entries"]:
        assert isinstance(e["crt_sh_id"], int) and e["crt_sh_id"] > 0, e["name"]
        assert e["derived_from"] and e["relation"] in ("original", "cross_sign", "reissue"), e["name"]
        assert datetime.fromisoformat(e["fetched_at"].replace("Z", "+00:00")).tzinfo is not None, e["name"]
        assert (e["relation"] == "original") == (e["derived_from"] == e["name"]), e["name"]


def test_every_entry_has_a_matching_fixture():
    by_hash = {tc.cert_sha256(c): (p, c) for p in EMUDHRA_DIR.glob("*.pem") for c in load(p)}
    for e in DISTRUST_DOC["entries"]:
        assert e["cert_sha256"] in by_hash, f"no fixture for {e['name']}"
        assert tc.spki_sha256(by_hash[e["cert_sha256"]][1]) == e["spki_sha256"]
    roots = {h for r in DISTRUST_DOC["removed_roots"] for h in r["cert_sha256"]}
    assert set(by_hash) == {e["cert_sha256"] for e in DISTRUST_DOC["entries"]} | roots, "unexplained fixture"


def test_real_reissue_matches_by_spki_alone(pki, monkeypatch):
    """The emSign Root TLS CA - G3 re-issue of DV G3B still fires when its cert hash is NOT on the list."""
    reissue = next(e for e in DISTRUST_DOC["entries"] if e["relation"] == "reissue")
    path = next(EMUDHRA_DIR.glob(f"*__reissue_{reissue['crt_sh_id']}.pem"))
    cert = load(path)[0]
    assert tc.cert_sha256(cert) == reissue["cert_sha256"]
    dl = tc.distrust_list()
    stripped = tc.DistrustList({h: n for h, n in dl.cert_hashes.items() if h != reissue["cert_sha256"]},
                               dict(dl.spki_hashes), dl.removed_roots)
    monkeypatch.setattr(tc, "distrust_list", lambda: stripped)
    ca, key = pki
    leaf, _ = make_leaf(ca, key)
    f = next(f for f in tc.analyze(scan_of([leaf, cert]), NOW)[0] if f.check_id == "TLS.DISTRUSTED_CA")
    assert f.evidence[0].data["match"] == "spki_sha256"
    assert f.severity == "critical"
    assert f.evidence[0].data["name"] == reissue["derived_from"]


def test_removed_root_only_is_high_not_critical(pki):
    ca, key = pki
    root = load(next((CERTS / "emudhra").glob("root_emsign_ecc_root_ca_g3_*.pem")))[0]
    leaf, _ = make_leaf(ca, key)
    findings, _ = tc.analyze(scan_of([leaf, ca], verified_chain=[leaf, ca, root]), NOW)
    rr = [f for f in findings if f.check_id == "TLS.REMOVED_ROOT"]
    assert rr and rr[0].severity == "high" and rr[0].strength == "authoritative"
    assert "TLS.DISTRUSTED_CA" not in {f.check_id for f in findings}


# ---- revocation ----

def _ocsp(leaf, ca, key, status, responder=None):
    b = ocsp.OCSPResponseBuilder().add_response(
        cert=leaf, issuer=ca, algorithm=hashes.SHA1(), cert_status=status, this_update=NOW,
        next_update=NOW + timedelta(days=1),
        revocation_time=NOW - timedelta(days=1) if status == ocsp.OCSPCertStatus.REVOKED else None,
        revocation_reason=None).responder_id(ocsp.OCSPResponderEncoding.HASH, responder or ca)
    return ocsp.load_der_ocsp_response(b.sign(key, hashes.SHA256()).public_bytes(Encoding.DER))


async def test_stapled_ocsp_revoked(pki):
    ca, key = pki
    leaf, _ = make_leaf(ca, key)
    s = scan_of([leaf, ca], stapled_ocsp=_ocsp(leaf, ca, key, ocsp.OCSPCertStatus.REVOKED))
    assert (await tc.check_revocation(s))[0] == "revoked"


async def test_ocsp_signed_by_wrong_key_is_unknown(pki):
    ca, key = pki
    other_ca, other_key = make_ca("Other")
    leaf, _ = make_leaf(ca, key)
    forged = _ocsp(leaf, ca, other_key, ocsp.OCSPCertStatus.GOOD, responder=other_ca)
    s = scan_of([leaf, ca], stapled_ocsp=forged)
    assert tc.ocsp_status(forged, leaf, ca) == "unknown"
    assert (await tc.check_revocation(s))[0] == "unknown"


async def test_ocsp_over_network_goes_through_safe_fetch(pki, monkeypatch):
    ca, key = pki
    leaf, _ = make_leaf(ca, key, ocsp_url="http://ocsp.example-ca.com/")
    calls = []

    async def fake_safe_fetch(url, **kw):
        calls.append((url, kw["method"], kw["allowed_types"]))
        resp = _ocsp(leaf, ca, key, ocsp.OCSPCertStatus.GOOD)
        return FetchResult(requested_url=url, final_url=url, status=200, body=resp.public_bytes(Encoding.DER),
                           content_type="application/ocsp-response")
    monkeypatch.setattr(tc, "safe_fetch", fake_safe_fetch)
    assert (await tc.check_revocation(scan_of([leaf, ca])))[0:2] == ("good", "ocsp")
    assert calls[0][1] == "POST" and "application/ocsp-response" in calls[0][2]


async def test_no_revocation_endpoint_unavailable(pki):
    ca, key = pki
    leaf, _ = make_leaf(ca, key)
    ctx = AssessmentContext(url=parse_url("https://shop.example.com/"), brands=None, now=NOW,
                            fetcher=fake_fetcher(fetch_result(["https://shop.example.com/"])))

    async def scanner(host, port):
        return scan_of([leaf, ca])
    ctx.tls_scanner = scanner
    run, fs = await tc.run_revocation(ctx)
    assert run.status == "unavailable" and fs == []


# ---- runs / policy ----

async def test_http_only_gives_no_https():
    ctx = AssessmentContext(url=parse_url("http://plain.example.com/"), brands=None, now=NOW,
                            fetcher=fake_fetcher(fetch_result(["http://plain.example.com/"])))
    run, fs = await tc.run(ctx)
    assert run.status == "skipped" and [f.check_id for f in fs] == ["TLS.NO_HTTPS"]


async def test_inspects_final_https_host(pki):
    ca, key = pki
    leaf, _ = make_leaf(ca, key, host="final.example.net")
    seen = []

    async def scanner(host, port):
        seen.append((host, port))
        return scan_of([leaf, ca], host=host)
    ctx = AssessmentContext(url=parse_url("http://start.example.com/"), brands=None, now=NOW,
                            fetcher=fake_fetcher(fetch_result(["http://start.example.com/",
                                                               "https://final.example.net/"])),
                            tls_scanner=scanner)
    run, fs = await tc.run(ctx)
    assert run.status == "completed" and seen == [("final.example.net", 443)] and ctx.certificate is not None


@pytest.mark.parametrize("host,port", [("example.com", 22), ("example.com", 8000), ("10.0.0.1", 443),
                                       ("127.0.0.1", 443), ("localhost", 443), ("metadata.google.internal", 443),
                                       ("2130706433", 443)])
async def test_scan_tls_enforces_policy_before_connecting(host, port, monkeypatch):
    def boom(scan):
        raise AssertionError("sslyze must not run")
    monkeypatch.setattr(tc, "_sslyze_scan", boom)

    async def dns(h, p):
        return ["93.184.216.34"]
    monkeypatch.setattr("app.fetch.safe_fetch._getaddrinfo", dns)
    s = await tc.scan_tls(host, port)
    assert s.blocked and s.leaf is None


async def test_scan_tls_rejects_private_resolution(monkeypatch):
    async def dns(h, p):
        return ["10.9.9.9"]
    monkeypatch.setattr("app.fetch.safe_fetch._getaddrinfo", dns)
    monkeypatch.setattr(tc, "_sslyze_scan", lambda s: (_ for _ in ()).throw(AssertionError))
    s = await tc.scan_tls("evil.example.com", 443)
    assert s.blocked


async def test_expired_cert_revocation_unknown(pki):
    ca, key = pki
    leaf, _ = make_leaf(ca, key, nb=NOW - timedelta(days=400), na=NOW - timedelta(days=5))
    s = scan_of([leaf, ca], stapled_ocsp=_ocsp(leaf, ca, key, ocsp.OCSPCertStatus.GOOD))
    st, _, detail = await tc.check_revocation(s, NOW)
    assert st == "unknown" and "expired" in detail
