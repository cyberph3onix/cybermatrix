"""SQLAlchemy models and engine. Postgres in production; tests use aiosqlite.

`reports.canonical` holds the exact RFC 8785 bytes that were hashed. Never re-serialise it: the on-chain hash
commits to these bytes. Raw URLs, messages and PII live only here (CLAUDE.md rule 7).
"""
from __future__ import annotations

import os
from datetime import datetime

from sqlalchemy import JSON, BigInteger, DateTime, ForeignKey, Index, Integer, LargeBinary, String
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
