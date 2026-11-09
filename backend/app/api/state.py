"""Per-application state shared by the routes (built in main.lifespan, injectable for tests)."""
from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field

from app.ai.llm import LlmClient
from app.cache import SqlIntelCache
from app.db import Database
from app.fetch.api_client import ApiClient
from app.ownership import Checker
from app.pipeline import Deps
from app.ratelimit import RateLimiter
from app.registry.chain import ChainClient

MAX_CONCURRENT_ASSESSMENTS = int(os.environ.get("MAX_CONCURRENT_ASSESSMENTS", "8"))
REGISTER_MAX_PER_HOUR = int(os.environ.get("REGISTER_MAX_PER_HOUR", "30"))  # each registration costs relayer gas


@dataclass
class AppState:
    db: Database
    api: ApiClient
    cache: SqlIntelCache
    deps: Deps
    llm: LlmClient | None = None
    chain: ChainClient | None = None  # None → built lazily from env on first use
    assess_limiter: RateLimiter = field(default_factory=lambda: RateLimiter(10, 60))  # 10 / min / IP
    register_limiter: RateLimiter = field(default_factory=lambda: RateLimiter(5, 60))  # each one costs gas
    # Server-wide caps: per-IP limits don't stop someone rotating addresses.
    register_global: RateLimiter = field(default_factory=lambda: RateLimiter(REGISTER_MAX_PER_HOUR, 3600))
    owns_limiter: RateLimiter = field(default_factory=lambda: RateLimiter(3, 60))  # exposed-file probes (owner-verified)
    verify_limiter: RateLimiter = field(default_factory=lambda: RateLimiter(30, 60))  # each one is an RPC call
    quick_limiter: RateLimiter = field(default_factory=lambda: RateLimiter(120, 60))  # one per page the extension opens
    feed_limiter: RateLimiter = field(default_factory=lambda: RateLimiter(30, 60))
    assess_slots: asyncio.Semaphore = field(default_factory=lambda: asyncio.Semaphore(MAX_CONCURRENT_ASSESSMENTS))
    register_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    cluster_summaries: dict[str, str] = field(default_factory=dict)  # cache_key -> text
    ownership_checker: Checker | None = None  # None → DNS-over-HTTPS + safe_fetch (app.ownership.make_checker)

    def get_chain(self) -> ChainClient:
        if self.chain is None:
            self.chain = ChainClient.from_env()  # raises ChainError("NotConfigured") when env is missing
        return self.chain
