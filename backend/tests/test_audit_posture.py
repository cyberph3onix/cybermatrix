"""Compliance audit, Module 5: cookie / CORS / HTTPS-redirect hygiene (M5-1), OSV advisories for exposed versions
(M5-3, recorded osv.dev response), complete posture findings (M5-4) and posture never classifying (M5-6)."""
import json
from pathlib import Path

import httpx
import pytest

from app.brands import get_index
from app.checks import headers, osv
from app.checks.base import AssessmentContext, evidence
from app.checks.catalogue import POSTURE_IDS, POSTURE_META
from app.engine import risk
from app.fetch.api_client import ApiClient
from app.schemas import Finding
from app.urlutil import parse_url
from tests.certgen import NOW
from tests.test_rdap_headers import GOOD

OSV_JQUERY = json.loads((Path(__file__).parent / "fixtures" / "osv" / "jquery-1.12.4.json").read_text())
PAGE = (b'<html><head><meta name="generator" content="Drupal 9 (https://www.drupal.org)">'
        b'<script src="/static/js/jquery-1.12.4.min.js"></script>'
        b'<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>'
        b'<script src="/js/app.js?v=2"></script></head></html>')


def ids(fs):
    return [f.check_id for f in fs]


# ---------- M5-1 ----------

def test_insecure_cookie_lists_missing_flags_without_values():
    h = {**GOOD, "set-cookie": "sid=SECRETVALUE; Path=/\nprefs=dark; Secure; HttpOnly; SameSite=Lax\n"
                               "csrftoken=abc; Secure; SameSite=Strict"}
    out = headers.analyze(h, "https://example.org/", b"", "text/html", "TLSv1.3", NOW)
    f = next(f for f in out if f.check_id == "POSTURE.INSECURE_COOKIE")
    cookies = f.evidence[0].data["cookies"]
    assert cookies == [{"name": "sid", "missing": ["Secure", "HttpOnly", "SameSite"]},
                       {"name": "csrftoken", "missing": ["HttpOnly"]}]
    assert "SECRETVALUE" not in f.model_dump_json()


def test_secure_flag_not_demanded_on_plain_http():
    assert headers.cookie_problems("a=1; HttpOnly; SameSite=Lax", https=False) == []


def test_cors_wildcard_with_credentials():
    h = {**GOOD, "access-control-allow-origin": "*", "access-control-allow-credentials": "true"}
    assert "POSTURE.CORS_WILDCARD_CREDENTIALS" in ids(headers.analyze(h, "https://example.org/", b"", "text/html", "TLSv1.3", NOW))
    h["access-control-allow-credentials"] = "false"
    assert "POSTURE.CORS_WILDCARD_CREDENTIALS" not in ids(headers.analyze(h, "https://example.org/", b"", "text/html", "TLSv1.3", NOW))


def test_http_link_not_redirected_to_https():
    out = headers.analyze({}, "http://example.org/", b"<html></html>", "text/html", None, NOW,
                          submitted_url="http://example.org/")
    assert "POSTURE.NO_HTTPS_REDIRECT" in ids(out)
    redirected = headers.analyze(GOOD, "https://example.org/", b"<html></html>", "text/html", "TLSv1.3", NOW,
                                 submitted_url="http://example.org/")
    assert "POSTURE.NO_HTTPS_REDIRECT" not in ids(redirected)


# ---------- M5-3 ----------

def test_detect_exact_versions_only():
    found = {(c.ecosystem, c.package, c.version) for c in osv.detect(PAGE)}
    assert found == {("npm", "jquery", "1.12.4"), ("npm", "bootstrap", "5.3.3")}  # "Drupal 9" has no exact version
    assert osv.detect(b'<meta name="generator" content="Drupal 10.1.2">') [0].package == "drupal/core"
    assert osv.detect(b'<script src="/jquery.min.js"></script>') == []


def _ctx(handler):
    api = ApiClient(transport=httpx.MockTransport(handler))
    return AssessmentContext(url=parse_url("https://example.org/"), brands=get_index(), now=NOW, api=api)


async def test_osv_lookup_maps_versions_to_advisory_ids():
    sent = []

    def handler(req: httpx.Request):
        body = json.loads(req.content)
        sent.append(body)
        assert req.url.host == "api.osv.dev" and req.url.path == "/v1/query"
        return httpx.Response(200, json=OSV_JQUERY if body["package"]["name"] == "jquery" else {})

    hits = await osv.lookup(_ctx(handler), osv.detect(PAGE))
    out = headers.vulnerable_components(hits, NOW)
    assert ids(out) == ["POSTURE.KNOWN_VULNERABLE_COMPONENT"]  # bootstrap 5.3.3: no advisories → no finding
    d = out[0].evidence[0].data
    assert d["package"] == "jquery" and d["version"] == "1.12.4" and d["count"] == 4
    assert "GHSA-rmxg-73gg-4p98" in d["advisories"] and "CVE-2020-11022" in d["cves"]
    assert out[0].evidence[0].source == "osv.dev"
    # only package name and version leave the server, never the page URL
    assert all(set(b) == {"package", "version"} for b in sent) and "example.org" not in json.dumps(sent)


async def test_run_reports_osv_outage_in_detail_not_as_failure():
    from tests.conftest import fake_fetcher, fetch_result
    ctx = _ctx(lambda req: httpx.Response(503))
    ctx.fetcher = fake_fetcher(fetch_result(["https://example.org/"], PAGE))

    async def scanner(host, port):
        from app.checks.tls_chain import TlsScan
        return TlsScan(hostname=host, port=port, error="none")
    ctx.tls_scanner = scanner
    run, findings = await headers.run(ctx)
    assert run.status == "completed" and "osv.dev unavailable" in (run.detail or "")
    assert "POSTURE.KNOWN_VULNERABLE_COMPONENT" not in ids(findings)


# ---------- M5-4: every posture finding is complete ----------

def test_every_posture_id_is_reported_with_all_fields():
    h = {"set-cookie": "sid=1", "access-control-allow-origin": "*", "access-control-allow-credentials": "true",
         "server": "nginx/1.14.0", "x-powered-by": "PHP/5.6.40"}
    body = b'<html><script src="http://cdn.example/a.js"></script></html>'
    found = headers.analyze(h, "https://example.org/", body, "text/html", "TLSv1.0", NOW)
    found += headers.analyze({}, "http://example.org/", b"<p>", "text/html", None, NOW, submitted_url="http://example.org/")
    found += headers.vulnerable_components([(osv.detect(PAGE)[0], osv.summarise(OSV_JQUERY))], NOW)
    for f in found:
        assert f.category == "security_posture"
        assert f.title and f.impact and f.recommendation and f.limitation and f.severity, f.check_id
        assert f.evidence and all(e.source and e.description for e in f.evidence), f.check_id
        assert POSTURE_META[f.check_id].category == "security_posture"
    covered = set(ids(found))
    # remaining IDs come from dns.py / exposed_files, which have their own tests; all must be in the catalogue
    assert covered <= POSTURE_IDS and {"POSTURE.INSECURE_COOKIE", "POSTURE.CORS_WILDCARD_CREDENTIALS",
                                       "POSTURE.NO_HTTPS_REDIRECT", "POSTURE.KNOWN_VULNERABLE_COMPONENT"} <= covered


# ---------- M5-6 ----------

@pytest.mark.parametrize("cid", sorted(POSTURE_IDS))
def test_posture_findings_score_zero_and_never_trigger_r3(cid):
    meta = POSTURE_META[cid]
    f = Finding(check_id=cid, title="t", category="security_posture", severity="critical", strength="authoritative",
                evidence=[evidence("http_header", "x", "local:headers")], impact="i", recommendation="r")
    v = risk.classify([f] * 3, 100)
    assert v.score == 0 and v.classification == "low_risk", (cid, meta)
