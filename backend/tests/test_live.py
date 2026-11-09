"""Live smoke tests against badssl.com. Run with: uv run pytest -m live -q

These hit the real network and are excluded from the default run. If badssl is unreachable they skip.
"""
import socket

import pytest

from app.checks import tls_chain
from app.fetch.safe_fetch import safe_fetch
from app.pipeline import assess_url
from app.schemas import utcnow

pytestmark = pytest.mark.live


@pytest.fixture(scope="module", autouse=True)
def badssl_reachable():
    try:
        socket.create_connection(("badssl.com", 443), timeout=5).close()
    except OSError:
        pytest.skip("badssl.com unreachable")


async def _ids(host):
    scan = await tls_chain.scan_tls(host, 443)
    if scan.leaf is None:
        pytest.skip(f"{host}: {scan.error}")
    return {f.check_id for f in tls_chain.analyze(scan, utcnow())[0]}, scan


@pytest.mark.parametrize("host,expected", [
    ("expired.badssl.com", "TLS.EXPIRED"),
    ("wrong.host.badssl.com", "TLS.HOSTNAME_MISMATCH"),
    ("self-signed.badssl.com", "TLS.SELF_SIGNED"),
    ("untrusted-root.badssl.com", "TLS.UNTRUSTED_ROOT"),
    ("incomplete-chain.badssl.com", "TLS.INCOMPLETE_CHAIN"),
])
async def test_badssl_tls(host, expected):
    ids, _ = await _ids(host)
    assert expected in ids, ids


async def test_sslyze_adapter_end_to_end():
    _, scan = await _ids("badssl.com")
    assert scan.received_chain and scan.store_results and scan.ip
    assert scan.tls_version and scan.tls_version.startswith("TLSv")


async def test_safe_fetch_live_reads_page_despite_bad_cert():
    fr = await safe_fetch("https://expired.badssl.com/")
    assert fr.ok and fr.tls_verified is False and b"expired" in fr.body.lower()


async def test_safe_fetch_live_blocks_localhost_names():
    fr = await safe_fetch("http://localtest.me/")  # public DNS name resolving to 127.0.0.1
    assert fr.blocked


async def test_revoked_badssl():
    scan = await tls_chain.scan_tls("revoked.badssl.com", 443)
    if scan.leaf is None:
        pytest.skip(scan.error)
    status, method, _ = await tls_chain.check_revocation(scan)
    if status == "unknown":
        pytest.skip("revocation endpoint unreachable or cert expired")
    assert status == "revoked", (status, method)


async def test_full_pipeline_live():
    rep = await assess_url("https://expired.badssl.com/")
    assert rep.limitations and rep.certificate is not None
    assert "TLS.EXPIRED" in {f.check_id for f in rep.findings}
    assert rep.classification in ("suspicious", "high_risk")
