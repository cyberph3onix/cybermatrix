import pytest

from app.checks import page, redirects
from app.checks.base import AssessmentContext
from app.urlutil import parse_url
from tests.conftest import fake_fetcher, fetch_result
from tests.conftest import page as load


def rids(urls, idx):
    return {f.check_id for f in redirects.analyze(parse_url(urls[0]).host, fetch_result(urls), idx)}


def test_same_brand_official_redirect_no_finding(idx):
    assert rids(["https://sbi.co.in/", "https://sbi.bank.in/"], idx) == set()
    assert rids(["https://onlinesbi.sbi/", "https://sbi.co.in/", "https://sbi.bank.in/", "https://onlinesbi.sbi/x"],
                idx) == set()


def test_shortener_to_evil_fires(idx):
    assert rids(["https://bit.ly/x", "https://evil.xyz/login"], idx) == {"REDIRECT.CROSS_DOMAIN"}


def test_shortener_to_amazon_fires_at_check_level_with_final_host(idx):
    fs = redirects.analyze("bit.ly", fetch_result(["https://bit.ly/x", "https://www.amazon.in/dp/1"]), idx)
    assert [f.check_id for f in fs] == ["REDIRECT.CROSS_DOMAIN"]
    assert fs[0].evidence[0].data["final_host"] == "www.amazon.in"  # engine dampening keys on this


def test_long_chain(idx):
    urls = ["https://bit.ly/a", "https://t.co/b", "https://a.example.org/", "https://b.example.net/",
            "https://evil.xyz/"]
    assert rids(urls, idx) == {"REDIRECT.CROSS_DOMAIN", "REDIRECT.LONG_CHAIN"}


def test_long_chain_ignores_same_brand_hops(idx):
    urls = ["https://bit.ly/a", "https://sbi.co.in/", "https://sbi.bank.in/", "https://onlinesbi.sbi/"]
    assert "REDIRECT.LONG_CHAIN" not in rids(urls, idx)


def test_no_redirect(idx):
    assert rids(["https://example.com/"], idx) == set()


def pids(name, url, idx):
    return {f.check_id for f in page.analyze(load(name).decode(), url, idx)}


def test_fake_sbi_login(idx):
    fs = page.analyze(load("fake_sbi_login.html").decode(), "https://sbi.co.in.kyc-verify-now.top/login", idx)
    assert {f.check_id for f in fs} == {"PAGE.CREDENTIAL_FORM"}
    assert {"password", "otp"} <= set(fs[0].evidence[1].data["fields"])


def test_fake_sbi_page_on_official_domain_is_fine(idx):
    assert pids("fake_sbi_login.html", "https://retail.onlinesbi.sbi/login", idx) == set()


def test_fake_sbi_page_on_abusable_host(idx):
    assert pids("fake_sbi_login.html", "https://sites.google.com/view/sbi", idx) == {"PAGE.CREDENTIAL_FORM"}


def test_legit_login(idx):
    assert pids("legit_login.html", "https://shop.example.com/login", idx) == set()


def test_cross_domain_action(idx):
    assert pids("cross_domain_action.html", "https://verify.example.com/", idx) == {"PAGE.FORM_ACTION_CROSS_DOMAIN"}


def test_brand_without_form(idx):
    assert pids("brand_no_form.html", "https://paytm-cashback.example.com/", idx) == {"PAGE.BRAND_MISMATCH"}


def test_news_article_about_brand_with_login_box(idx):
    assert pids("news_article.html", "https://news.example.com/sbi-fd", idx) == set()


def test_pincode_is_not_pin(idx):
    assert pids("pincode_form.html", "https://shop.example.com/", idx) == {"PAGE.BRAND_MISMATCH"}


def test_title_site_segment():
    f = page.extract("<title>Offers — Kotak Bank</title>", "https://x.example/")
    assert f.identity["title_site_name"] == "Kotak Bank"
    f = page.extract("<title>HDFC Bank NetBanking</title>", "https://x.example/")
    assert f.identity["title_site_name"] == "HDFC Bank NetBanking"


def test_base_href_used_for_action():
    f = page.extract('<base href="https://drop.example.net/"><form action="p.php"><input type="password"></form>',
                     "https://victim.example.com/")
    assert f.form_actions[0][0] == "https://drop.example.net/p.php"


async def test_page_run_skips_non_html(idx):
    ctx = AssessmentContext(url=parse_url("https://example.com/"), brands=idx,
                            fetcher=fake_fetcher(fetch_result(["https://example.com/"], b"hi", "text/plain")))
    run, fs = await page.run(ctx)
    assert run.status == "skipped" and fs == []


@pytest.mark.parametrize("blocked", [True, False])
async def test_runs_on_fetch_failure(idx, blocked):
    from app.fetch.safe_fetch import FetchResult
    fr = FetchResult(requested_url="https://x.example.com/", error="timeout", blocked=blocked)
    ctx = AssessmentContext(url=parse_url("https://x.example.com/"), brands=idx, fetcher=fake_fetcher(fr))
    r1, _ = await redirects.run(ctx)
    r2, _ = await page.run(ctx)
    assert r1.status == "failed" and r2.status == "unavailable" and "timeout" in r2.detail


async def test_fetch_shared_once(idx):
    calls = []

    async def f(url):
        calls.append(url)
        return fetch_result(["https://example.com/"], load("legit_login.html"))
    ctx = AssessmentContext(url=parse_url("https://example.com/"), brands=idx, fetcher=f)
    await redirects.run(ctx)
    await page.run(ctx)
    assert len(calls) == 1
