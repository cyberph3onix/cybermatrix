"""SQLAlchemy models and engine. Postgres in production; tests use aiosqlite.

`reports.canonical` holds the exact RFC 8785 bytes that were hashed. Never re-serialise it: the on-chain hash
commits to these bytes. Raw URLs, messages and PII live only here (CLAUDE.md rule 7).
"""
from __future__ import annotations

import os
from datetime import datetime

from sqlalchemy import JSON, BigInteger, Boolean, DateTime, ForeignKey, Index, Integer, LargeBinary, String
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class ReportRow(Base):
    __tablename__ = "reports"

    report_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    subject_type: Mapped[str] = mapped_column(String(16))
    normalized_subject: Mapped[str] = mapped_column(String(2048))
    classification: Mapped[str] = mapped_column(String(24), index=True)
    score: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    report_hash: Mapped[str] = mapped_column(String(66), unique=True)
    canonical: Mapped[bytes] = mapped_column(LargeBinary)


class IndicatorRow(Base):
    __tablename__ = "indicators"
    __table_args__ = (Index("ix_indicators_lookup", "type", "normalized"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    report_id: Mapped[str] = mapped_column(ForeignKey("reports.report_id", ondelete="CASCADE"), index=True)
    type: Mapped[str] = mapped_column(String(24))
    value: Mapped[str] = mapped_column(String(2048))
    normalized: Mapped[str] = mapped_column(String(2048))


class RegistryRow(Base):
    __tablename__ = "registry_records"

    report_id: Mapped[str] = mapped_column(ForeignKey("reports.report_id", ondelete="CASCADE"), primary_key=True)
    report_hash: Mapped[str] = mapped_column(String(66), index=True)
    parent_hash: Mapped[str] = mapped_column(String(66))
    chain_id: Mapped[int] = mapped_column(BigInteger)
    contract_address: Mapped[str] = mapped_column(String(42))
    onchain_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    tx_hash: Mapped[str | None] = mapped_column(String(66), nullable=True)
    reporter_address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    status: Mapped[str] = mapped_column(String(16))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class DisputeReasonRow(Base):
    """Off-chain text of a dispute reason; only its keccak256 goes on-chain."""

    __tablename__ = "dispute_reasons"

    reason_hash: Mapped[str] = mapped_column(String(66), primary_key=True)
    report_id: Mapped[str] = mapped_column(ForeignKey("reports.report_id", ondelete="CASCADE"), index=True)
    text: Mapped[str] = mapped_column(String(4000))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class OwnershipRow(Base):
    """An ownership challenge and, once proven, its grant (see app/ownership.py)."""

    __tablename__ = "ownership"

    challenge: Mapped[str] = mapped_column(String(32), primary_key=True)
    domain: Mapped[str] = mapped_column(String(253), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    grant: Mapped[str | None] = mapped_column(String(32), nullable=True, unique=True)
    method: Mapped[str | None] = mapped_column(String(8), nullable=True)
    grant_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class WatchRow(Base):
    """A domain on the CT watchlist (app/watch.py). The id is a random token: whoever has it can read the alerts."""

    __tablename__ = "ct_watches"

    watch_id: Mapped[str] = mapped_column(String(24), primary_key=True)
    domain: Mapped[str] = mapped_column(String(253), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_checked: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    known_certs: Mapped[list | None] = mapped_column(JSON, nullable=True)
    known_issuers: Mapped[list | None] = mapped_column(JSON, nullable=True)


class WatchAlertRow(Base):
    __tablename__ = "ct_watch_alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    watch_id: Mapped[str] = mapped_column(ForeignKey("ct_watches.watch_id", ondelete="CASCADE"), index=True)
    cert_sha256: Mapped[str] = mapped_column(String(64))
    dns_names: Mapped[list | None] = mapped_column(JSON, nullable=True)
    issuer: Mapped[str] = mapped_column(String(256))
    not_before: Mapped[str | None] = mapped_column(String(40), nullable=True)
    new_issuer: Mapped[bool] = mapped_column(Boolean, default=False)
    seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class IntelCacheRow(Base):
    """Threat-intel response cache. The key is a SHA-256 of the lookup, so URLs aren't duplicated here."""

    __tablename__ = "intel_cache"

    source: Mapped[str] = mapped_column(String(32), primary_key=True)
    key_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    payload: Mapped[dict | list | None] = mapped_column(JSON, nullable=True)
    expires_at: Mapped[int] = mapped_column(BigInteger, index=True)  # unix seconds


class Database:
    def __init__(self, url: str | None = None, *, engine: AsyncEngine | None = None) -> None:
        url = url or os.environ.get("DATABASE_URL")
        if engine is None:
            if not url:
                raise RuntimeError("DATABASE_URL is not set")
            engine = create_async_engine(url, pool_pre_ping=True)
        self.engine = engine
        self.sessionmaker = async_sessionmaker(engine, expire_on_commit=False)

    def session(self) -> AsyncSession:
        return self.sessionmaker()

    async def create_all(self) -> None:
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def aclose(self) -> None:
        await self.engine.dispose()
