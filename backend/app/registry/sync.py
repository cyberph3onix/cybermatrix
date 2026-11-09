"""Keep stored registry statuses in step with the contract (limitation 3: statuses used to refresh only when a
report's registration was viewed). CORR.VALIDATED_MATCH reads these rows, so a validation or dispute on-chain
reaches correlation within one sync interval.

Only rows registered on the contract the client points at are refreshed: rows from an earlier deployment keep
their last known status (their on-chain ids mean something else on the new contract).
"""
from __future__ import annotations

import asyncio
import logging
import os

from sqlalchemy import select

from app.db import Database, RegistryRow
from app.registry.chain import ChainClient, ChainError, ChainUnavailable
from app.schemas import RegistryStatus, utcnow

log = logging.getLogger(__name__)
SYNC_S = int(os.environ.get("REGISTRY_SYNC_S", "600"))
TERMINAL = (RegistryStatus.REJECTED.value, RegistryStatus.SUPERSEDED.value)


def on_contract(row_address: str | None, chain: ChainClient) -> bool:
    return bool(row_address) and row_address.lower() == str(chain.address).lower()


async def refresh_statuses(db: Database, chain: ChainClient, limit: int = 500) -> int:
    """Re-read non-terminal registrations from the chain. Returns how many changed."""
    changed = 0
    async with db.session() as s:
        rows = (await s.execute(select(RegistryRow).where(RegistryRow.onchain_id.is_not(None),
                                                          RegistryRow.status.not_in(TERMINAL))
                                .order_by(RegistryRow.updated_at.asc()).limit(limit))).scalars().all()
        for row in rows:
            if not on_contract(row.contract_address, chain):
                continue
            try:
                status = (await chain.get_report(row.onchain_id)).status
            except ChainUnavailable:
                break  # RPC down: try again next round
            except ChainError:
                continue
            if status.value != row.status:
                row.status, row.updated_at = status.value, utcnow()
                changed += 1
        await s.commit()
    return changed


async def sync_loop(db: Database, get_chain) -> None:
    while True:
        await asyncio.sleep(SYNC_S)
        try:
            n = await refresh_statuses(db, get_chain())
            if n:
                log.info("registry sync: %d status change(s)", n)
        except ChainError:
            return  # chain not configured on this server
        except Exception as e:  # noqa: BLE001
            log.warning("registry sync failed: %s", type(e).__name__)
