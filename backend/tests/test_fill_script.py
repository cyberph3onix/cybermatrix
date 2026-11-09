"""scripts/fill_distrusted_spki.py must never report success when crt.sh failed."""
import importlib.util
import json
import shutil
from pathlib import Path

import pytest

from app.fetch.api_client import ApiUnavailable

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("fill_spki", ROOT / "scripts" / "fill_distrusted_spki.py")
fill = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fill)


class DownApi:
    def __init__(self, *a, **kw):
        self.calls = 0

    async def get_json(self, *a, **kw):
        self.calls += 1
        raise ApiUnavailable("crt.sh: HTTP 502")

    get_text = get_json

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    data = tmp_path / "distrusted_cas.json"
    shutil.copy(ROOT / "data" / "distrusted_cas.json", data)
    monkeypatch.setattr(fill, "DATA", data)
    monkeypatch.setattr(fill, "PEM_DIR", tmp_path / "pems")
    monkeypatch.setattr(fill, "ApiClient", DownApi)

    async def no_sleep(_):
        return None
    monkeypatch.setattr(fill.asyncio, "sleep", no_sleep)
    return data


@pytest.mark.parametrize("argv", [["--only", "EM EV TLS CA - G3B"], ["--provenance"], []])
async def test_upstream_502_exits_nonzero(sandbox, argv, capsys):
    before = json.loads(sandbox.read_text())
    assert await fill.main(argv + ["--max-attempts", "2"]) == 1
    out = capsys.readouterr().out
    assert "FAILED" in out and "502" in out
    assert json.loads(sandbox.read_text())["entries"] == before["entries"]  # nothing invented or dropped


async def test_unknown_only_name_is_an_error(sandbox):
    assert await fill.main(["--only", "No Such CA"]) == 2
