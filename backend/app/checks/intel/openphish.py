"""URL.INTEL.OPENPHISH: the public OpenPhish feed, downloaded to data/openphish_feed.txt and matched in memory.

No submitted URL ever leaves the server for this check. The feed is refreshed on startup and every 6 hours; if a
download fails we keep using the last file and say how old it is. Exact-URL matches always count; host-only
matches are skipped for allowlisted and abusable hosts (see common.host_match_allowed).
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import time
from pathlib import Path

from app.checks.base import AssessmentContext, CheckResult, evidence, make_finding, make_run
from app.checks.intel.common import host_match_allowed, host_of, staged_lookup
from app.fetch.api_client import ApiClient, ApiUnavailable
from app.schemas import CheckStatus, Finding
from app.urlutil import URLParseError, parse_url

log = logging.getLogger(__name__)

GROUP = "intel.openphish"
SOURCE = "openphish"
# openphish.com/feed.txt 302-redirects here; our API client never follows redirects, so use the target directly.
FEED_URL = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
DATA_FILE = Path(__file__).resolve().parents[3] / "data" / "openphish_feed.txt"
REFRESH_S = 6 * 3600
STALE_S = 48 * 3600  # older than this, the feed is too stale to be worth matching against


def normalize(url: str) -> str | None:
    """scheme-, port-, fragment- and trailing-slash-insensitive key: host/path?query."""
    try:
        p = parse_url(url)
    except URLParseError:
        return None
    path = p.path.rstrip("/")
    return f"{p.host}{path}" + (f"?{p.query}" if p.query else "")


class OpenPhishFeed:
    def __init__(self, path: Path = DATA_FILE) -> None:
        self.path = path
        self.urls: set[str] = set()
        self.hosts: set[str] = set()
        self.loaded_at: float | None = None  # file mtime

    @property
    def loaded(self) -> bool:
        return self.loaded_at is not None

    def age_s(self, now: float | None = None) -> int | None:
        return None if self.loaded_at is None else int((now or time.time()) - self.loaded_at)

    def _parse(self, text: str) -> tuple[set[str], set[str]]:
        urls, hosts = set(), set()
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith(("http://", "https://")):
                continue
            key = normalize(line)
            if key:
                urls.add(key)
                hosts.add(key.split("/", 1)[0].split("?", 1)[0])
        return urls, hosts

    def load_file(self) -> bool:
        try:
            text = self.path.read_text(errors="replace")
            mtime = self.path.stat().st_mtime
        except OSError:
            return False
        urls, hosts = self._parse(text)
        if not urls:
            return False
        self.urls, self.hosts, self.loaded_at = urls, hosts, mtime
        return True

    async def refresh(self, api: ApiClient) -> bool:
        """Download the feed, validate it, replace the file atomically. Returns False (and keeps the old data) on failure."""
        try:
            text = await api.get_text(FEED_URL)
        except ApiUnavailable as e:
            log.warning("openphish feed download failed: %s", e)
            return False
        urls, _ = self._parse(text)
        if not urls:
            log.warning("openphish feed download was empty or malformed; keeping previous file")
            return False
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(text)
        os.replace(tmp, self.path)
        return self.load_file()

    async def startup(self, api: ApiClient) -> None:
        self.load_file()  # fall back to the last file if the download fails
        await self.refresh(api)

    async def refresh_forever(self, api: ApiClient) -> None:
        while True:
            await asyncio.sleep(REFRESH_S)
            with contextlib.suppress(Exception):
                await self.refresh(api)


FEED = OpenPhishFeed()


async def lookup(ctx: AssessmentContext, urls: list[str]) -> list[dict]:
    hits = []
    for u in urls:
        key = normalize(u)
        if key is None:
            continue
        if key in FEED.urls:
            hits.append({"scope": "url", "url": u})
            continue
        host = host_of(u)
        if host and host in FEED.hosts and host_match_allowed(ctx, host):
            hits.append({"scope": "host", "url": u, "host": host})
    return hits


def build(ctx: AssessmentContext, hits: list[dict]) -> list[Finding]:
    if not hits:
        return []
    age = FEED.age_s()
    ev = [evidence("ti_match", (f"{h['url']} is listed in the OpenPhish feed" if h["scope"] == "url"
                                else f"Host {h['host']} (of {h['url']}) has phishing URLs in the OpenPhish feed"),
                   SOURCE, {"url": h["url"], "scope": h["scope"], "feed_entries": len(FEED.urls),
                            "feed_age_seconds": age}, observed_at=ctx.now) for h in hits[:5]]
    return [make_finding(
        "URL.INTEL.OPENPHISH", "OpenPhish lists this link or its host as phishing", ev,
        "OpenPhish tracks live phishing pages; this address (or its host) is in its current feed.",
        "Do not enter any information on this site.")]


async def run(ctx: AssessmentContext) -> CheckResult:
    t0 = time.monotonic()
    try:
        if not FEED.loaded:
            return make_run(GROUP, CheckStatus.UNAVAILABLE, SOURCE, t0, "OpenPhish feed not downloaded yet"), []
        age = FEED.age_s() or 0
        if age > STALE_S:
            return make_run(GROUP, CheckStatus.UNAVAILABLE, SOURCE, t0,
                            f"OpenPhish feed is {age // 3600} h old (refresh failing)"), []
        hits, detail = await staged_lookup(ctx, lambda urls: lookup(ctx, urls), max_extra=10)
        return make_run(GROUP, CheckStatus.COMPLETED, SOURCE, t0, detail), build(ctx, hits)
    except Exception as e:  # noqa: BLE001
        return make_run(GROUP, CheckStatus.FAILED, SOURCE, t0, f"error: {type(e).__name__}"), []
