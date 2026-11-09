"""Shared check plumbing: the context every check receives and helpers that enforce the finding contract."""
from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

from app.checks.catalogue import CATALOGUE, POSTURE_META
from app.engine.coverage import weight
from app.schemas import CheckRun, CheckStatus, Evidence, Finding, utcnow
from app.urlutil import ParsedURL

if TYPE_CHECKING:
    from app.brands import BrandIndex
    from app.cache import IntelCache
    from app.checks.tls_chain import TlsScan
    from app.fetch.api_client import ApiClient
    from app.fetch.safe_fetch import FetchResult

CheckResult = tuple[CheckRun, list[Finding]]


@dataclass
class AssessmentContext:
    url: ParsedURL
    brands: BrandIndex
    now: datetime = field(default_factory=utcnow)
    fetcher: Callable[[str], Awaitable[FetchResult]] | None = None
    tls_scanner: Callable[[str, int], Awaitable[TlsScan]] | None = None
    api: ApiClient | None = None
    cache: IntelCache | None = None
    owns_site: bool = False  # user ticked "I own this site": enables POSTURE.EXPOSED_FILE
    _fetch_task: asyncio.Task | None = field(default=None, repr=False)
    _tls_task: asyncio.Task | None = field(default=None, repr=False)
    tls_target: tuple[str, int] | None = None
    certificate: Any = None  # CertificateSummary set by tls.chain
    revocation_status: str = "unchecked"  # set by tls.revocation: good | revoked | unknown
    ct_logged: bool | None = None  # set by tls.ct
    nameservers: list[str] = field(default_factory=list)  # set by domain.rdap, becomes `nameserver` indicators

    async def fetch(self) -> FetchResult:
        """Fetch the submitted URL once; every caller shares the result."""
        if self._fetch_task is None:
            if self.fetcher is None:
                from app.fetch.safe_fetch import safe_fetch
                self.fetcher = safe_fetch
            self._fetch_task = asyncio.ensure_future(self.fetcher(self.url.raw))
        return await asyncio.shield(self._fetch_task)

    async def tls_scan(self, host: str, port: int) -> TlsScan:
        if self._tls_task is None:
            if self.tls_scanner is None:
                from app.checks.tls_chain import scan_tls
                self.tls_scanner = scan_tls
            self.tls_target = (host, port)
            self._tls_task = asyncio.ensure_future(self.tls_scanner(host, port))
        return await asyncio.shield(self._tls_task)


def evidence(kind: str, description: str, source: str, data: dict[str, Any] | None = None,
             observed_at: datetime | None = None) -> Evidence:
    return Evidence(kind=kind, description=description, data=data or {}, source=source,
                    observed_at=observed_at or utcnow())


def make_finding(check_id: str, title: str, evidence: list[Evidence], impact: str, recommendation: str,
                 *, severity: str | None = None, limitation: str | None = None,
                 indicator_ref: str | None = None) -> Finding:
    if not evidence:
        raise ValueError(f"{check_id}: a finding needs at least one Evidence")
    meta = CATALOGUE.get(check_id) or POSTURE_META[check_id]
    return Finding(check_id=check_id, title=title, category=meta.category, severity=severity or meta.severity,
                   strength=meta.strength, evidence=evidence, impact=impact, recommendation=recommendation,
                   limitation=limitation, indicator_ref=indicator_ref)


def make_run(group: str, status: CheckStatus | str, source: str, started: float,
             detail: str | None = None) -> CheckRun:
    return CheckRun(check_group=group, status=status, source=source,
                    duration_ms=int((time.monotonic() - started) * 1000), weight=weight(group), detail=detail)
