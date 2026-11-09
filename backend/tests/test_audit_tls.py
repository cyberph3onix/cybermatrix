"""Compliance audit, Module 2: the certificate's own verdict (M2-2) and the eMudhra scenario end to end (M2-4)."""
from types import SimpleNamespace

import pytest

from app.checks import tls_chain as tc
from app.checks.base import evidence, make_finding
from app.engine import risk
from app.engine.cert_verdict import certificate_verdict
from tests.certgen import NOW, make_leaf
from tests.test_tls_chain import CERTS, EMUDHRA_EV_G3B, load, pki, scan_of  # noqa: F401  (pki is a fixture)


def F(check_id):
    return make_finding(check_id, check_id, [evidence("test", "t", "test")], "i", "r")


def rep(ids, cert=True):
    return SimpleNamespace(report_id="r", findings=[F(i) for i in ids], certificate=object() if cert else None)


@pytest.mark.parametrize("ids,verdict,reasons", [
    ([], "valid", []),
    (["TLS.CERT_VERY_NEW", "TLS.INCOMPLETE_CHAIN"], "valid", []),          # low only
    (["URL.INTEL.GSB", "PAGE.CREDENTIAL_FORM"], "valid", []),             # non-TLS findings do not count
    (["TLS.EXPIRED"], "suspicious", ["TLS.EXPIRED"]),                      # tls_config, high
    (["TLS.HOSTNAME_MISMATCH"], "suspicious", ["TLS.HOSTNAME_MISMATCH"]),  # tls_trust, technical
    (["TLS.CT_NOT_LOGGED"], "suspicious", ["TLS.CT_NOT_LOGGED"]),          # medium
    (["TLS.DISTRUSTED_CA", "TLS.EXPIRED"], "potentially_compromised", ["TLS.DISTRUSTED_CA"]),
    (["TLS.REMOVED_ROOT"], "potentially_compromised", ["TLS.REMOVED_ROOT"]),
    (["TLS.REVOKED"], "potentially_compromised", ["TLS.REVOKED"]),
])
def test_certificate_verdict_table(ids, verdict, reasons):
    v = certificate_verdict(rep(ids))
    assert v.verdict == verdict and v.reasons == reasons


def test_trust_and_config_findings_are_listed_separately():
    v = certificate_verdict(rep(["TLS.EXPIRED", "TLS.WEAK_KEY", "TLS.HOSTNAME_MISMATCH", "TLS.INCOMPLETE_CHAIN"]))
    assert v.config_findings == ["TLS.EXPIRED", "TLS.WEAK_KEY", "TLS.INCOMPLETE_CHAIN"]
    assert v.trust_findings == ["TLS.HOSTNAME_MISMATCH"]
    assert "does not mean the site is legitimate" in v.note and "key-generation" in v.note


def test_emudhra_chain_is_confirmed_malicious_and_potentially_compromised(pki):
    """Real public eMudhra EM EV TLS CA - G3B intermediate (nothing is signed with its key) → R1 + compromised."""
    ca, key = pki
    leaf, _ = make_leaf(ca, key)
    findings, cert = tc.analyze(scan_of([leaf, load(EMUDHRA_EV_G3B)[0]], trusted=False), NOW)
    assert risk.classify(findings, 90).classification == "confirmed_malicious"
    assert risk.classify(findings, 90).reason.startswith("R1: TLS.DISTRUSTED_CA")
    v = certificate_verdict(SimpleNamespace(report_id="r", findings=findings, certificate=cert))
    assert v.verdict == "potentially_compromised" and "TLS.DISTRUSTED_CA" in v.reasons


def test_real_sectigo_cross_sign_is_potentially_compromised_via_spki(pki):
    ca, key = pki
    xsign = load(sorted((CERTS / "emudhra").glob("em_ev_tls_ca_g3b__xsign_*.pem"))[0])[0]
    leaf, _ = make_leaf(ca, key)
    findings, cert = tc.analyze(scan_of([leaf, xsign], trusted=False), NOW)
    f = next(f for f in findings if f.check_id == "TLS.DISTRUSTED_CA")
    assert f.evidence[0].data["match"] in ("spki_sha256", "cert_sha256")
    assert certificate_verdict(SimpleNamespace(report_id="r", findings=findings, certificate=cert)).verdict \
        == "potentially_compromised"


def test_clean_chain_is_valid(pki):
    ca, key = pki
    leaf, _ = make_leaf(ca, key)
    findings, cert = tc.analyze(scan_of([leaf, ca]), NOW)
    assert certificate_verdict(SimpleNamespace(report_id="r", findings=findings, certificate=cert)).verdict == "valid"
