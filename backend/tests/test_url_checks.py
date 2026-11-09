import string

import pytest

from app.brands import get_index
from app.checks import lookalike, url_structure
from app.urlutil import parse_url

IDX = get_index()


def ids(url: str) -> set[str]:
    u = parse_url(url)
    return {f.check_id for f in url_structure.analyze(u, IDX) + lookalike.analyze(u, IDX)}


def finding(url: str, check_id: str):
    u = parse_url(url)
    return next(f for f in url_structure.analyze(u, IDX) + lookalike.analyze(u, IDX) if f.check_id == check_id)


@pytest.mark.parametrize("url,expected", [
    ("https://sbi.co.in.verify-now.xyz/", {"URL.BRAND_IN_SUBDOMAIN", "URL.KEYWORDS", "DOMAIN.SUSPICIOUS_TLD"}),
    ("https://sbi.co.in@evil.tld/", {"URL.USERINFO_TRICK"}),
    ("https://hdfcbank-verify.com/", {"URL.LOOKALIKE.TYPOSQUAT", "URL.KEYWORDS"}),
    ("https://sbi-kyc.in/", {"URL.LOOKALIKE.TYPOSQUAT", "URL.KEYWORDS"}),
    ("https://icicibamk.com/", {"URL.LOOKALIKE.TYPOSQUAT"}),
    ("https://flipkaart.com/", {"URL.LOOKALIKE.TYPOSQUAT"}),
    ("https://g00gle.com/", {"URL.LOOKALIKE.HOMOGLYPH"}),
    ("https://paytrn.com/", {"URL.LOOKALIKE.HOMOGLYPH"}),
    ("https://раytm.com/", {"URL.LOOKALIKE.HOMOGLYPH", "URL.PUNYCODE_MIXED_SCRIPT"}),
    ("http://2130706433/", {"URL.IP_HOST"}),
    ("http://203.0.113.9/login", {"URL.IP_HOST", "URL.KEYWORDS"}),
    ("https://bit.ly/3xYz", {"URL.SHORTENER"}),
    ("https://example.com/r?next=https%3A%2F%2Fevil.example.org%2F", {"URL.EMBEDDED_REDIRECT_PARAM"}),
    ("https://example.com/r?u=https%253A%252F%252Fevil.example.org", {"URL.EMBEDDED_REDIRECT_PARAM"}),
    ("https://example.com/r?u=https%3A%2F%2Fwww.example.com%2F", set()),
    ("https://login.sbi-secure.evil.org/", {"URL.BRAND_IN_SUBDOMAIN", "URL.KEYWORDS"}),
])
def test_url_checks(url, expected):
    assert ids(url) == expected


@pytest.mark.parametrize("url", [
    "https://www.onlinesbi.sbi/", "https://sbi.co.in/", "https://retail.sbi.bank.in/login",
    "https://netbanking.hdfcbank.com/netbanking/", "https://www.icicibank.com/",
    "https://eportal.incometax.gov.in/iec/foservices/", "https://myaadhaar.uidai.gov.in/",
    "https://www.amazon.in/", "https://www.linkedin.com/in/x", "https://www.irctc.co.in/nget/",
    "https://pay.google.com/", "https://www.iem.edu.in/",
])
def test_official_domains_produce_no_impersonation(url):
    # URL.KEYWORDS may still fire at check level ("login"); engine dampening removes it on official domains.
    assert ids(url) - {"URL.KEYWORDS"} == set()


def test_brand_in_subdomain_records_location():
    f = finding("https://sbi.co.in.kyc-verify-now.top/login", "URL.BRAND_IN_SUBDOMAIN")
    assert f.evidence[0].data["match_location"] == "subdomain"
    f = finding("https://web.archive.org/web/2024/https://sbi.co.in/", "URL.BRAND_IN_SUBDOMAIN")
    assert f.evidence[0].data["match_location"] == "path"


def test_evil_github_io_is_not_github():
    assert IDX.official_brand("evil.github.io") is None
    assert IDX.is_abusable("evil.github.io")
    assert not IDX.allowlisted("evil.github.io")


def test_sites_google_com_not_official():
    assert IDX.official_brand("pay.google.com") is not None
    assert IDX.official_brand("sites.google.com") is None
    assert not IDX.allowlisted("sites.google.com", "/view/sbi-kyc")
    assert IDX.is_abusable("docs.google.com", "/forms/d/x")
    assert not IDX.is_abusable("docs.google.com", "/document/d/x")


@pytest.mark.parametrize("brand_label,suffix", [("sbi", "co.in"), ("pnb", "bank.in"), ("iem", "edu.in")])
def test_short_brand_neighbours_produce_nothing(brand_label, suffix):
    """3-letter edit-distance neighbours of short brands never fire. Only dnstwist homoglyph-fuzzer hits survive."""
    perms = lookalike.permutation_index()
    hits = []
    for i in range(len(brand_label)):
        for c in string.ascii_lowercase + string.digits:
            cand = brand_label[:i] + c + brand_label[i + 1:]
            if cand == brand_label:
                continue
            got = ids(f"https://{cand}.{suffix}/")
            hit = perms.get(f"{cand}.{suffix}")
            if hit is not None:
                assert hit.fuzzer in lookalike.HOMOGLYPH_FUZZERS, (cand, hit)
            else:
                assert got == set(), (cand, got)
                continue
            hits.append(cand)
    # sanity: the homoglyph allowance is narrow
    assert len(hits) <= 6, hits


def test_skeleton():
    assert lookalike.skeleton("paypa1").casefold() == "paypal"
    assert lookalike._skel("g00gle") == "google"
    assert lookalike._skel("\u0440\u0430ytm") == lookalike._skel("paytm") == lookalike._skel("paytrn")


def test_osa():
    assert lookalike.osa_distance("hdfcbank", "hdfcbnak") == 1
    assert lookalike.osa_distance("abc", "abc") == 0
    assert lookalike.osa_distance("kitten", "sitting") == 3


async def test_run_contract():
    from app.checks.base import AssessmentContext
    ctx = AssessmentContext(url=parse_url("https://sbi-kyc.in/"), brands=IDX)
    for mod in (url_structure, lookalike):
        run, findings = await mod.run(ctx)
        assert run.status == "completed" and run.weight == 5
        assert all(f.evidence and f.evidence[0].source for f in findings)
