"""Threat-intel response cache (6 h TTL). A cache failure never breaks a check: errors degrade to a miss."""
from __future__ import annotations

import hashlib
import logging
import time
from typing import Any, Protocol

from sqlalchemy import delete
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.db import IntelCacheRow

log = logging.getLogger(__name__)
TTL_S = 6 * 3600
_MISS = object()
MISS = _MISS  # returned by `get` on a miss, so a cached empty answer is distinguishable


class IntelCache(Protocol):
    async def get(self, source: str, key: str) -> Any: ...
    async def set(self, source: str, key: str, value: Any, ttl_s: int = TTL_S) -> None: ...


def key_hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


class MemoryIntelCache:
    """Process-local cache for tests. `get` returns `MISS` when absent so that `None` can be a cached answer."""

    MISS = _MISS

    def __init__(self, clock=time.time) -> None:
        self._data: dict[tuple[str, str], tuple[int, Any]] = {}
        self._clock = clock

    async def get(self, source: str, key: str) -> Any:
        hit = self._data.get((source, key_hash(key)))
        if hit is None or hit[0] <= self._clock():
            return _MISS
        return hit[1]

    async def set(self, source: str, key: str, value: Any, ttl_s: int = TTL_S) -> None:
        self._data[(source, key_hash(key))] = (int(self._clock()) + ttl_s, value)


class SqlIntelCache:
    MISS = _MISS

    def __init__(self, sessions: async_sessionmaker, clock=time.time) -> None:
        self._sessions = sessions
        self._clock = clock

    async def get(self, source: str, key: str) -> Any:
        try:
            async with self._sessions() as s:
                row = await s.get(IntelCacheRow, (source, key_hash(key)))
                if row is None or row.expires_at <= self._clock():
                    return _MISS
                return row.payload
        except Exception as e:  # noqa: BLE001
            log.warning("intel cache read failed: %s", type(e).__name__)
            return _MISS

    async def set(self, source: str, key: str, value: Any, ttl_s: int = TTL_S) -> None:
        try:
            async with self._sessions() as s:
                await s.merge(IntelCacheRow(source=source, key_hash=key_hash(key), payload=value,
                                            expires_at=int(self._clock()) + ttl_s))
                await s.commit()
        except Exception as e:  # noqa: BLE001
            log.warning("intel cache write failed: %s", type(e).__name__)

    async def purge_expired(self) -> None:
        try:
            async with self._sessions() as s:
                await s.execute(delete(IntelCacheRow).where(IntelCacheRow.expires_at <= int(self._clock())))
                await s.commit()
        except Exception as e:  # noqa: BLE001
            log.warning("intel cache purge failed: %s", type(e).__name__)
