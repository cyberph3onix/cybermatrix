import pytest

from app.urlutil import URLParseError, parse_ip_literal, parse_url, registrable_domain


@pytest.mark.parametrize("host,reg", [
    ("sbi.bank.in", "sbi.bank.in"),
    ("www.hdfc.bank.in", "hdfc.bank.in"),
    ("eportal.incometax.gov.in", "incometax.gov.in"),
    ("myaadhaar.uidai.gov.in", "uidai.gov.in"),
    ("wbjeeb.nic.in", "wbjeeb.nic.in"),
    ("evil.github.io", "evil.github.io"),
    ("github.io", "github.io"),
    ("sites.google.com", "google.com"),
    ("x.y.web.app", "y.web.app"),
    ("sbi.co.in.kyc-verify-now.top", "kyc-verify-now.top"),
])
def test_registrable(host, reg):
    assert registrable_domain(host) == reg


@pytest.mark.parametrize("host,ip,nc", [
    ("2130706433", "127.0.0.1", True),
    ("0177.0.0.1", "127.0.0.1", True),
    ("0x7f.1", "127.0.0.1", True),
    ("127.1", "127.0.0.1", True),
    ("127.0.0.1", "127.0.0.1", False),
    ("[::1]", "::1", False),
])
def test_ip_literals(host, ip, nc):
    lit = parse_ip_literal(host)
    assert lit and str(lit.ip) == ip and lit.non_canonical is nc


def test_not_ip():
    assert parse_ip_literal("example.com") is None
    assert parse_ip_literal("123.example") is None


def test_parse_backslash_and_userinfo():
    u = parse_url("https://sbi.co.in\\@evil.tld/x")
    assert u.host in ("sbi.co.in",)  # backslash becomes '/', so '@evil.tld' is path
    u = parse_url("https://sbi.co.in@evil.tld/login")
    assert u.host == "evil.tld" and u.userinfo == "sbi.co.in"
    u = parse_url("example.com")
    assert u.scheme == "https" and u.port == 443
    u = parse_url("http://Exaмple.com:8080/")
    assert u.host.startswith("xn--") and u.port == 8080 and u.explicit_port


def test_icann_registrable_domain_ignores_private_suffixes():
    from app.urlutil import icann_registrable_domain, registrable_domain
    assert registrable_domain("testsafebrowsing.appspot.com") == "testsafebrowsing.appspot.com"
    assert icann_registrable_domain("testsafebrowsing.appspot.com") == "appspot.com"
    assert icann_registrable_domain("login.example.co.uk") == "example.co.uk"
    assert icann_registrable_domain("203.0.113.9") == "203.0.113.9"


@pytest.mark.parametrize("url,host,norm", [
    ("HTTPS://WWW.SBI.CO.IN./Login", "www.sbi.co.in", "https://www.sbi.co.in/Login"),   # case, trailing dot
    ("https://%73bi.co.in/%6Cogin", "sbi.co.in", "https://sbi.co.in/%6Cogin"),          # percent-encoded host
    ("https://sbi%2eco%2ein/", "sbi.co.in", "https://sbi.co.in/"),
    ("https://ѕbi.co.in/", "xn--bi-doc.co.in", "https://xn--bi-doc.co.in/"),            # Cyrillic ѕ → punycode
    ("https://user:pw@sbi.co.in.evil.top/", "sbi.co.in.evil.top", "https://sbi.co.in.evil.top/"),  # userinfo dropped
])
def test_normalisation(url, host, norm):
    p = parse_url(url)
    assert p.host == host and p.url_without_userinfo() == norm


@pytest.mark.parametrize("url", ["https://%2F%2Fevil.top/", "https://%E0%A4/", "https://a%40b.com/"])
def test_bad_percent_encoded_hosts_rejected(url):
    with pytest.raises(URLParseError):
        parse_url(url)
