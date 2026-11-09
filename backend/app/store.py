"""Persistence helpers. The canonical bytes are written once and are what gets hashed and registered."""
from __future__ import annotations

from datetime import UTC, datetime

from eth_hash.auto import keccak
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import IndicatorRow, RegistryRow, ReportRow
from app.schemas import AssessmentReport, RegistryRecord, RegistryStatus, canonical_bytes, utcnow


def _val(x) -> str:
    """Plain string of an enum-or-str field. model_copy(update=...) skips validation, so a field can hold an Enum
    member, and str(Enum) is 'RiskClass.X', not the value that was hashed and that queries filter on."""
    return str(getattr(x, "value", x))


def hash_bytes(canonical: bytes) -> str:
    return "0x" + keccak(canonical).hex()


async def save_report(session: AsyncSession, report: AssessmentReport) -> str:
    """Store the report with its exact canonical bytes and indicators. Returns the 0x report hash."""
    canonical = canonical_bytes(report)
    h = hash_bytes(canonical)
    session.add(ReportRow(
        report_id=report.report_id, subject_type=_val(report.subject_type),
        normalized_subject=report.normalized_subject[:2048], classification=_val(report.classification),
        score=report.score, created_at=report.created_at, report_hash=h, canonical=canonical))
    await session.flush()  # the FK target must exist before indicators
    seen: set[tuple[str, str]] = set()
    for ind in report.indicators:
        if (ind.type, ind.normalized) in seen:
            continue
        seen.add((ind.type, ind.normalized))
        session.add(IndicatorRow(report_id=report.report_id, type=ind.type, value=ind.value[:2048],
                                 normalized=ind.normalized[:2048]))
    await session.commit()
    return h


async def get_report_row(session: AsyncSession, report_id: str) -> ReportRow | None:
    return await session.get(ReportRow, report_id)


def parse_report(row: ReportRow) -> AssessmentReport:
    return AssessmentReport.model_validate_json(row.canonical)


def record(row: RegistryRow) -> RegistryRecord:
    return RegistryRecord(
        report_id=row.report_id, report_hash=row.report_hash, parent_hash=row.parent_hash, chain_id=row.chain_id,
        contract_address=row.contract_address, onchain_id=row.onchain_id, tx_hash=row.tx_hash,
        reporter_address=row.reporter_address, status=RegistryStatus(row.status))


async def get_registry(session: AsyncSession, report_id: str) -> RegistryRecord | None:
    row = await session.get(RegistryRow, report_id)
    return record(row) if row else None


async def save_registry(session: AsyncSession, rec: RegistryRecord) -> None:
    status = rec.status.value if isinstance(rec.status, RegistryStatus) else str(rec.status)
    await session.merge(RegistryRow(
        report_id=rec.report_id, report_hash=rec.report_hash, parent_hash=rec.parent_hash, chain_id=rec.chain_id,
        contract_address=rec.contract_address, onchain_id=rec.onchain_id, tx_hash=rec.tx_hash,
        reporter_address=rec.reporter_address, status=status, updated_at=utcnow()))
    await session.commit()


async def indicator_rows(session: AsyncSession) -> list[tuple[str, str, str, str, datetime]]:
    """(report_id, type, normalized, classification, created_at) for reports at suspicious or worse."""
    q = (select(IndicatorRow.report_id, IndicatorRow.type, IndicatorRow.normalized, ReportRow.classification,
                ReportRow.created_at)
         .join(ReportRow, ReportRow.report_id == IndicatorRow.report_id)
         .where(ReportRow.classification.in_(["suspicious", "high_risk", "confirmed_malicious"])))
    out = []
    for rid, typ, norm, cls, created in (await session.execute(q)).all():
        out.append((rid, typ, norm, cls, created if created.tzinfo else created.replace(tzinfo=UTC)))
    return out
