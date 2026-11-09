from datetime import UTC, timedelta

import httpx
import pytest
import respx

from app.checks import tls_ct
from app.checks.base import AssessmentContext
from app.checks.tls_chain import TlsScan, cert_sha256, spki_sha256
from app.fetch.api_client import ApiClient
from app.urlutil import parse_url
from tests.certgen import NOW, make_ca, make_leaf
from tests.conftest import fake_fetcher, fetch_result

HOST = "shop.example.com"


@pytest.fixture(scope="module")
def pki():
    return make_ca("Test CA")


def cs_row(cert, issuer="C=US, O=Let's Encrypt, CN=R11", nb=None):
    return {"id": "1", "cert_sha256": cert_sha256(cert).lower(), "pubkey_sha256": spki_sha256(cert).lower(),
            "dns_names": [HOST], "issuer": {"name": issuer, "friendly_name": "LE"},
            "not_before": (nb or cert.not_valid_before_utc).isoformat().replace("+00:00", "Z")}


def ctx_for(leaf, ca, sct=0):
    async def scanner(h, p):
        return TlsScan(hostname=h, port=p, received_chain=[leaf, ca], sct_count=sct)
    return AssessmentContext(url=parse_url(f"https://{HOST}/"), brands=None, now=NOW,
                             fetcher=fake_fetcher(fetch_result([f"https://{HOST}/"])), tls_scanner=scanner,
                             api=ApiClient(timeout=6))


@respx.mock
async def test_certspotter_hit(pki):
    ca, key = pki
    leaf, _ = make_leaf(ca, key)
    respx.get(tls_ct.CERTSPOTTER).mock(return_value=httpx.Response(200, json=[cs_row(leaf)]))
    run, fs = await tls_ct.run(ctx_for(leaf, ca))
    assert run.status == "completed" and run.source == "certspotter" and fs == []


@respx.mock
async def test_not_logged(pki):
    ca, key = pki
    leaf, _ = make_leaf(ca, key)
    respx.get(tls_ct.CERTSPOTTER).mock(return_value=httpx.Response(200, json=[]))
    run, fs = await tls_ct.run(ctx_for(leaf, ca, sct=0))
    assert [f.check_id for f in fs] == ["TLS.CT_NOT_LOGGED"]


@respx.mock
async def test_embedded_scts_count_as_logged(pki):
    ca, key = pki
    leaf, _ = make_leaf(ca, key)
    respx.get(tls_ct.CERTSPOTTER).mock(return_value=httpx.Response(200, json=[]))
    run, fs = await tls_ct.run(ctx_for(leaf, ca, sct=2))
    assert fs == []


@respx.mock
async def test_fallback_to_crtsh(pki):
    ca, key = pki
    leaf, _ = make_leaf(ca, key)
    respx.get(tls_ct.CERTSPOTTER).mock(return_value=httpx.Response(500))
    respx.get(tls_ct.CRTSH).mock(return_value=httpx.Response(200, json=[
        {"id": 5, "issuer_name": "C=US, O=Test, CN=Test CA", "not_before": "2026-10-09T00:00:00",
         "serial_number": format(leaf.serial_number, "x")}]))
    run, fs = await tls_ct.run(ctx_for(leaf, ca))
    assert run.status == "completed" and run.source == "crt.sh" and "fallback" in run.detail and fs == []


@respx.mock
async def test_both_down_is_unavailable(pki):
    ca, key = pki
    leaf, _ = make_leaf(ca, key)
    respx.get(tls_ct.CERTSPOTTER).mock(side_effect=httpx.ConnectTimeout("t"))
    respx.get(tls_ct.CRTSH).mock(return_value=httpx.Response(502))
    run, fs = await tls_ct.run(ctx_for(leaf, ca))
    assert run.status == "unavailable" and fs == []


@respx.mock
async def test_unexpected_issuer(pki):
    ca, key = pki
    leaf, _ = make_leaf(ca, key, nb=NOW - timedelta(days=1))  # issuer org "Test"
    old = cs_row(leaf, issuer="C=US, O=DigiCert Inc, CN=DigiCert G2", nb=NOW - timedelta(days=200))
    old["cert_sha256"] = "00" * 32
    respx.get(tls_ct.CERTSPOTTER).mock(return_value=httpx.Response(200, json=[old, cs_row(leaf)]))
    run, fs = await tls_ct.run(ctx_for(leaf, ca, sct=2))
    assert [f.check_id for f in fs] == ["TLS.CT_UNEXPECTED_ISSUER"]


def test_dn_org():
    assert tls_ct._dn_org("C=US, O=Let's Encrypt, CN=R11") == "Let's Encrypt"
    assert tls_ct._dn_org('C=GB, O="Sectigo, Ltd", CN=x') == "Sectigo, Ltd"


@respx.mock
async def test_pre_ct_era_cert_not_flagged(pki):
    from datetime import datetime
    ca, key = pki
    leaf, _ = make_leaf(ca, key, nb=datetime(2015, 4, 9, tzinfo=UTC),
                        na=datetime(2015, 4, 12, tzinfo=UTC))
    respx.get(tls_ct.CERTSPOTTER).mock(return_value=httpx.Response(200, json=[]))
    run, fs = await tls_ct.run(ctx_for(leaf, ca, sct=0))
    assert run.status == "completed" and fs == []
