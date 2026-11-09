"""Per-IP sliding-window rate limiting (in-process; one backend instance)."""
from __future__ import annotations

import math
import os
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request


class RateLimiter:
    def __init__(self, limit: int, window_s: float = 60.0, clock=time.monotonic) -> None:
        self.limit, self.window_s, self._clock = limit, window_s, clock
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._last_prune = clock()

    def check(self, key: str) -> int | None:
        """Record a hit. Returns None if allowed, else the seconds until the next hit would be."""
        now = self._clock()
        q = self._hits[key]
        while q and now - q[0] >= self.window_s:
            q.popleft()
        if len(q) >= self.limit:
            return max(1, math.ceil(self.window_s - (now - q[0])))
        q.append(now)
        if now - self._last_prune > self.window_s:  # drop idle keys so memory stays bounded
            self._last_prune = now
            for k in [k for k, v in self._hits.items() if not v or now - v[-1] >= self.window_s]:
                del self._hits[k]
        return None


def client_ip(request: Request) -> str:
    """The peer address. Behind a trusted reverse proxy (TRUST_FORWARDED_FOR=1) use the last X-Forwarded-For
    entry, which is the one our own proxy appended; earlier entries are client-controlled."""
    if os.environ.get("TRUST_FORWARDED_FOR") == "1":
        xff = request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[-1].strip()
    return request.client.host if request.client else "unknown"


def limit_dependency(limiter: RateLimiter):
    async def dep(request: Request) -> None:
        wait = limiter.check(client_ip(request))
        if wait is not None:
            raise HTTPException(429, f"Too many requests. Try again in {wait} s.", headers={"Retry-After": str(wait)})
    return dep
