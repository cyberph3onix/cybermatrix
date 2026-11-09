"""FastAPI application. `uvicorn app.main:app`."""
from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.ai.llm import LlmClient, default_llm
from app.api.routes import router
from app.api.state import AppState
from app.cache import SqlIntelCache
from app.checks.intel import openphish
from app.db import Database
from app.fetch.api_client import ApiClient
from app.pipeline import Deps
from app.registry.chain import ChainClient

log = logging.getLogger("cybermatrix")
MAINTENANCE_S = 6 * 3600


async def _maintenance(api: ApiClient, cache: SqlIntelCache) -> None:
    """Refresh the OpenPhish feed and purge expired cache rows every 6 hours."""
    while True:
        await asyncio.sleep(MAINTENANCE_S)
        with contextlib.suppress(Exception):
            await openphish.FEED.refresh(api)
            await cache.purge_expired()


def create_app(*, database: Database | None = None, llm: LlmClient | None = None, use_env_llm: bool = True, deps: Deps | None = None, chain: ChainClient | None = None,
               background_feeds: bool = True) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        db = database or Database()
        await db.create_all()
        api = ApiClient()
        cache = SqlIntelCache(db.sessionmaker)
        base = deps or Deps()
        app.state.cm = AppState(db=db, api=api, cache=cache, chain=chain, llm=llm or (default_llm() if use_env_llm else None),
                                deps=dataclasses.replace(base, api=base.api or api, cache=base.cache or cache))
        task = None
        if background_feeds:
            try:  # download the OpenPhish feed on startup; fall back to the last file on failure
                await asyncio.wait_for(openphish.FEED.startup(api), 25)
            except Exception as e:  # noqa: BLE001
                log.warning("openphish startup failed: %s", type(e).__name__)
            task = asyncio.create_task(_maintenance(api, cache))
        try:
            yield
        finally:
            if task:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
            if app.state.cm.chain is not None:
                await app.state.cm.chain.aclose()
            await api.aclose()
            await db.aclose()

    app = FastAPI(
        title="CyberMatrix API", version="0.1.0", lifespan=lifespan,
        description="Evidence-based web threat assessment with on-chain report registry.",
        generate_unique_id_function=lambda route: route.name,
        separate_input_output_schemas=True)
    origins = [o.strip() for o in os.environ.get("CORS_ORIGINS", "http://localhost:3000").split(",") if o.strip()]
    app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["GET", "POST"], allow_headers=["*"])
    app.include_router(router)
    return app


app = create_app()
