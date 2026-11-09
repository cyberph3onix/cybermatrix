from pathlib import Path

import pytest

from app.brands import get_index
from app.fetch.safe_fetch import FetchResult
from app.schemas import RedirectHop

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch, tmp_path):
    """No real API keys and no real OpenPhish feed leak into tests, whatever the dev machine has."""
    from app.checks.intel import openphish
    for k in ("GSB_API_KEY", "VT_API_KEY", "URLHAUS_AUTH_KEY", "CERTSPOTTER_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(openphish, "FEED", openphish.OpenPhishFeed(tmp_path / "openphish_feed.txt"))


@pytest.fixture
def idx():
    return get_index()


def page(name: str) -> bytes:
    return (FIXTURES / "pages" / name).read_bytes()


def fetch_result(urls: list[str], body: bytes = b"", ctype: str = "text/html", status: int = 200,
                 error: str | None = None) -> FetchResult:
    from app.urlutil import parse_url, registrable_domain
    hops, prev = [], None
    for i, u in enumerate(urls):
        reg = registrable_domain(parse_url(u).host)
        hops.append(RedirectHop(url=u, status_code=302 if i < len(urls) - 1 else status,
                                resolved_ip="93.184.216.34", cross_domain=prev is not None and prev != reg))
        prev = reg
    return FetchResult(requested_url=urls[0], final_url=urls[-1], status=status,
                       headers={"content-type": ctype}, content_type=ctype, body=body, hops=hops, error=error)


def fake_fetcher(result: FetchResult):
    async def f(url: str) -> FetchResult:
        return result
    return f
