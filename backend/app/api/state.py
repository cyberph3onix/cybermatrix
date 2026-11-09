"""Per-application state shared by the routes (built in main.lifespan, injectable for tests)."""
from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field

from app.ai.llm import LlmClient
from app.cache import SqlIntelCache
from app.db import Database
from app.fetch.api_client import ApiClient
from app.pipeline import Deps
from app.ratelimit import RateLimiter
from app.registry.chain import ChainClient

MAX_CONCURRENT_ASSESSMENTS = int(os.environ.get("MAX_CONCURRENT_ASSESSMENTS", "8"))


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
    verify_limiter: RateLimiter = field(default_factory=lambda: RateLimiter(30, 60))  # each one is an RPC call
    assess_slots: asyncio.Semaphore = field(default_factory=lambda: asyncio.Semaphore(MAX_CONCURRENT_ASSESSMENTS))
    register_lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def get_chain(self) -> ChainClient:
        if self.chain is None:
            self.chain = ChainClient.from_env()  # raises ChainError("NotConfigured") when env is missing
        return self.chain
