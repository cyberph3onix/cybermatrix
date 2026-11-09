"""CT watchlist: baseline, new-certificate alerts, new-issuer flag, API."""
import httpx
import pytest
import respx

from app import watch
from app.db import Database
from app.fetch.api_client import ApiClient


def cert(n, issuer="Let's Encrypt", names=("shop.example.com",)):
    return {"id": str(n), "cert_sha256": f"{n:064x}", "dns_names": list(names), "issuer": {"name": f"C=US, O={issuer}, CN=R11"},
            "not_before": "2026-11-01T00:00:00Z"}


@pytest.fixture
async def db(tmp_path):
    d = Database(f"sqlite+aiosqlite:///{tmp_path / 'w.db'}")
    await d.create_all()
    yield d
    await d.aclose()


@respx.mock
async def test_baseline_then_alerts_for_new_certificates(db):
    from app.db import WatchRow
    from app.schemas import utcnow
    async with db.session() as s:
        s.add(WatchRow(watch_id="a" * 24, domain="example.com", created_at=utcnow(), known_certs=[], known_issuers=[]))
        await s.commit()
    route = respx.get(watch.CERTSPOTTER).mock(return_value=httpx.Response(200, json=[cert(1), cert(2)]))
    api = ApiClient()
    assert await watch.poll_one(db, api, "a" * 24) == 0  # baseline: existing certificates are not alerts
    assert route.calls[0].request.url.params["include_subdomains"] == "true"

    route.mock(return_value=httpx.Response(200, json=[cert(1), cert(2), cert(3), cert(4, "Shady CA", ["login.example.com"])]))
    assert await watch.poll_one(db, api, "a" * 24) == 2
    assert await watch.poll_one(db, api, "a" * 24) == 0  # already seen
    from sqlalchemy import select

    from app.db import WatchAlertRow
    async with db.session() as s:
        alerts = {a.cert_sha256[-1]: a for a in (await s.execute(select(WatchAlertRow))).scalars()}
    assert alerts["3"].new_issuer is False and alerts["4"].new_issuer is True
    assert alerts["4"].dns_names == ["login.example.com"] and alerts["4"].issuer == "Shady CA"


def test_watch_api(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from app.main import create_app
    from tests.test_api import FakeChain, make_deps
    answers = {"n": 0}

    async def fake_issuances(api, domain):
        answers["n"] += 1
        base = [{"id": "1", "cert_sha256": "A" * 64, "dns_names": [domain], "issuer": "Let's Encrypt", "not_before": None}]
        return base if answers["n"] == 1 else base + [{"id": "2", "cert_sha256": "B" * 64, "dns_names": ["x." + domain],
                                                       "issuer": "Other CA", "not_before": None}]
    monkeypatch.setattr(watch, "issuances", fake_issuances)
    app = create_app(database=Database(f"sqlite+aiosqlite:///{tmp_path / 'a.db'}"), deps=make_deps(), chain=FakeChain(),
                     background_feeds=False, use_env_llm=False)
    with TestClient(app) as c:
        w = c.post("/watch", json={"domain": "https://www.mybank-example.com/login"}).json()
        assert w["domain"] == "mybank-example.com" and w["known_certificates"] == 1 and w["alerts"] == []
        import asyncio
        st = c.app.state.cm
        assert asyncio.run(watch.poll_all(st.db, st.api)) == 1
        got = c.get(f"/watch/{w['watch_id']}").json()
        assert [a["issuer"] for a in got["alerts"]] == ["Other CA"] and got["alerts"][0]["new_issuer"] is True
        assert c.get("/watch/nothex").status_code == 404
        assert c.post("/watch", json={"domain": "10.0.0.1"}).status_code == 422
