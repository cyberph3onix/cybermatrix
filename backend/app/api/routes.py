"""HTTP routes. Thin: validation, rate limits and persistence; the work happens in pipeline/ and registry/."""
from __future__ import annotations

import logging
import re
from collections.abc import AsyncIterator
from typing import Annotated, Any

import rfc8785
from fastapi import APIRouter, Body, Depends, File, HTTPException, Request, Response, UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import store
from app.ai.cluster_summary import add_summaries
from app.ai.explain import explain
from app.ai.llm import LlmUnavailable
from app.ai.redact import redact
from app.api.state import AppState
from app.correlation.checks import apply_correlation
from app.correlation.clusters import build_clusters
from app.db import DisputeReasonRow, RegistryRow
from app.detect import detect_subject
from app.pipeline import assess_url
from app.pipeline_message import assess_email, assess_message
from app.pipeline_upi import UpiError, assess_upi, is_upi
from app.pipeline_upi import finalize as finalize_upi
from app.qr import QrError, decode_qr
from app.ratelimit import client_ip, limit_dependency
from app.registry.chain import ZERO_HASH, ChainClient, ChainError, ChainUnavailable
from app.schemas import (
    AssessmentReport,
    AssessRequest,
    AssessResponse,
    Cluster,
    DisputeInfo,
    DisputePrepared,
    DisputeReasonRequest,
    RegistryRecord,
    RegistryStatus,
    ReportHistory,
    ReportVersion,
    SubjectType,
    VerificationResult,
    utcnow,
)
from app.urlutil import URLParseError, parse_url

log = logging.getLogger(__name__)
router = APIRouter()

REPORT_ID = re.compile(r"^[0-9a-fA-F-]{36}$")
MAX_URL_CHARS = 2048
_EMAIL_ONLY = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]{2,}$")
MAX_UPLOAD_JSON_BYTES = 2 * 1024 * 1024


def state(request: Request) -> AppState:
    return request.app.state.cm


async def session(st: Annotated[AppState, Depends(state)]) -> AsyncIterator[AsyncSession]:
    async with st.db.session() as s:
        yield s


St = Annotated[AppState, Depends(state)]
Db = Annotated[AsyncSession, Depends(session)]


def _limit(name: str):
    async def dep(request: Request) -> None:
        await limit_dependency(getattr(request.app.state.cm, name))(request)
    return dep


def _throttle(limiter, key: str) -> None:
    wait = limiter.check(key)
    if wait is not None:
        raise HTTPException(429, f"Too many requests. Try again in {wait} s.", headers={"Retry-After": str(wait)})


async def _row_or_404(db: AsyncSession, report_id: str):
    row = await store.get_report_row(db, report_id) if REPORT_ID.match(report_id) else None
    if row is None:
        raise HTTPException(404, "No report with this ID.")
    return row


def _chain_error(e: Exception) -> HTTPException:
    if isinstance(e, ChainUnavailable):
        return HTTPException(503, "The blockchain network is unreachable right now. Try again shortly.")
    if isinstance(e, ChainError) and e.reason == "NotConfigured":
        return HTTPException(503, "The on-chain registry is not configured on this server.")
    if isinstance(e, ChainError):
        return HTTPException(502, f"The registry contract rejected the request ({e.reason}).")
    raise e


def _get_chain(st: AppState) -> ChainClient:
    try:
        return st.get_chain()
    except ChainError as e:
        raise _chain_error(e) from None


# ---------- assessment ----------

async def _explain(st: AppState, report: AssessmentReport, untrusted: str | None = None) -> AssessmentReport:
    """Attach the AI explanation if an LLM is available. Failure just leaves `ai` empty (the verdict is unaffected)."""
    llm = st.llm
    if llm is None:
        return report
    try:
        ai = await explain(llm, report, untrusted)
    except LlmUnavailable:
        return report
    return report.model_copy(update={"ai": ai, "limitations": [x for x in report.limitations if "AI explanation not" not in x]})


async def _assess_and_store(st: AppState, db: AsyncSession, url_input: str, *, qr: bool = False,
                            owns_site: bool = False) -> AssessResponse:
    try:
        parsed = parse_url(url_input)
    except URLParseError as e:
        raise HTTPException(422, f"That doesn't look like a valid link ({e}).") from None
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(422, "Only http and https links can be assessed.")
    async with st.assess_slots:
        report = await assess_url(url_input, deps=st.deps, owns_site=owns_site)
    report = await _explain(st, await apply_correlation(db, report))
    if qr:
        report = report.model_copy(update={"subject_type": SubjectType.QR.value})
    await store.save_report(db, report)
    return AssessResponse(report_id=report.report_id)


@router.post("/assess", response_model=AssessResponse, dependencies=[Depends(_limit("assess_limiter"))])
async def assess(req: AssessRequest, request: Request, st: St, db: Db) -> AssessResponse:
    if req.owns_site:  # ownership is not verified, so the extra probe gets its own tighter limit
        _throttle(st.owns_limiter, client_ip(request))
    text = req.input.strip()
    kind = req.subject_type or detect_subject(text)
    if kind in (SubjectType.URL, SubjectType.DOMAIN):
        if len(text) > MAX_URL_CHARS:
            raise HTTPException(422, f"Links longer than {MAX_URL_CHARS} characters aren't supported.")
        return await _assess_and_store(st, db, text, owns_site=req.owns_site)
    if kind == SubjectType.EMAIL:
        if not _EMAIL_ONLY.match(text):
            raise HTTPException(422, "That doesn't look like a single email address.")
        async with st.assess_slots:
            report = await assess_email(text, deps=st.deps)
        report = await _explain(st, await apply_correlation(db, report))
    elif kind == SubjectType.MESSAGE:
        async with st.assess_slots:
            report = await assess_message(req.input, deps=st.deps, llm=st.llm)
        report = await apply_correlation(db, report)
        report = await _explain(st, report, report.subject)  # report.subject is the redacted text
    else:
        raise HTTPException(422, "Submit a link, domain, email address or message text.")
    await store.save_report(db, report)
    return AssessResponse(report_id=report.report_id)


@router.post("/assess/qr", response_model=AssessResponse, dependencies=[Depends(_limit("assess_limiter"))])
async def assess_qr(st: St, db: Db, file: Annotated[UploadFile, File(description="PNG/JPEG/WebP image of a QR code")]
                    ) -> AssessResponse:
    data = await file.read(5 * 1024 * 1024 + 1)
    try:
        link = decode_qr(data)
    except QrError as e:
        raise HTTPException(422, str(e)) from None
    if is_upi(link):
        try:
            report = assess_upi(link)
        except UpiError as e:
            raise HTTPException(422, str(e)) from None
        # No AI explanation here: the model sees only findings, so for a QR with no website it invents a story
        # (it claimed nothing was compared). The deterministic reason and advice are already accurate.
        report = finalize_upi(await apply_correlation(db, report))
        await store.save_report(db, report)
        return AssessResponse(report_id=report.report_id)
    if len(link) > MAX_URL_CHARS or not re.match(r"^https?://", link, re.IGNORECASE):
        raise HTTPException(422, "This QR code contains neither a web link nor a UPI payment request, so there is nothing to assess.")
    return await _assess_and_store(st, db, link, qr=True)


# ---------- reports ----------

@router.get("/reports/{report_id}", response_class=Response, responses={
    200: {"model": AssessmentReport, "description": "The stored canonical report, byte for byte."},
    404: {"description": "Unknown report"}})
async def get_report(report_id: str, db: Db) -> Response:
    row = await _row_or_404(db, report_id)
    # Serve the stored bytes: re-serialising could change them and break hash verification.
    return Response(content=row.canonical, media_type="application/json")


@router.get("/reports/{report_id}/registration", response_model=RegistryRecord | None)
async def get_registration(report_id: str, st: St, db: Db) -> RegistryRecord | None:
    await _row_or_404(db, report_id)
    rec = await store.get_registry(db, report_id)
    if rec is None or rec.onchain_id is None:
        return rec
    try:  # status can change on-chain (validated / disputed); refresh best-effort
        onchain = await _get_chain(st).get_report(rec.onchain_id)
        if onchain.status != rec.status:
            rec = rec.model_copy(update={"status": onchain.status})
            await store.save_registry(db, rec)
    except (HTTPException, ChainError, ChainUnavailable):
        pass
    return rec


@router.post("/reports/{report_id}/register", response_model=RegistryRecord,
             dependencies=[Depends(_limit("register_limiter"))])
async def register(report_id: str, st: St, db: Db) -> RegistryRecord:
    row = await _row_or_404(db, report_id)
    async with st.register_lock:
        existing = await store.get_registry(db, report_id)
        if existing is not None and existing.onchain_id is not None:
            return existing
        _throttle(st.register_global, "all")  # only new on-chain writes count against the server-wide cap
        chain = _get_chain(st)
        report = store.parse_report(row)
        try:
            rec = await chain.submit_report(report)
        except (ChainError, ChainUnavailable) as e:
            raise _chain_error(e) from None
        if rec.report_hash != row.report_hash:  # would mean the stored bytes don't round-trip
            log.error("registry hash mismatch for report %s", report_id)
            raise HTTPException(500, "Internal error: report hash mismatch.")
        await store.save_registry(db, rec)
        return rec


# ---------- history, disputes, revisions ----------

MAX_VERSIONS = 20
REASSESSABLE = {SubjectType.URL.value, SubjectType.DOMAIN.value, SubjectType.QR.value}


async def _registry_by(db: AsyncSession, column, value: str) -> RegistryRow | None:
    q = select(RegistryRow).where(column == value).order_by(RegistryRow.updated_at.desc())
    return (await db.execute(q)).scalars().first()


async def _lineage(db: AsyncSession, row: RegistryRow) -> list[tuple[str | None, str, RegistryRow | None]]:
    """[(report_id, report_hash, row)] oldest first, following parent_hash back and child links forward."""
    back: list[tuple[str | None, str, RegistryRow | None]] = []
    cur = row
    while cur.parent_hash != ZERO_HASH and len(back) < MAX_VERSIONS:
        parent = await _registry_by(db, RegistryRow.report_hash, cur.parent_hash)
        if parent is None:  # registered elsewhere, or by another server: still part of the on-chain lineage
            back.append((None, cur.parent_hash, None))
            break
        back.append((parent.report_id, parent.report_hash, parent))
        cur = parent
    out = list(reversed(back)) + [(row.report_id, row.report_hash, row)]
    cur = row
    while len(out) < MAX_VERSIONS and (child := await _registry_by(db, RegistryRow.parent_hash, cur.report_hash)):
        out.append((child.report_id, child.report_hash, child))
        cur = child
    return out


@router.get("/reports/{report_id}/history", response_model=ReportHistory)
async def history(report_id: str, st: St, db: Db) -> ReportHistory:
    row = await _row_or_404(db, report_id)
    reg = await db.get(RegistryRow, report_id)
    if reg is None or reg.onchain_id is None:
        return ReportHistory(report_id=report_id, registered=False)
    chain = _get_chain(st)
    try:
        versions: list[ReportVersion] = []
        for rid, h, vrow in await _lineage(db, reg):
            onchain = await chain.find_by_hash(h)
            status = onchain.status if onchain else RegistryStatus(vrow.status if vrow else "submitted")
            if vrow is not None and onchain is not None and vrow.status != status.value:
                await store.save_registry(db, store.record(vrow).model_copy(update={"status": status}))
            tx = vrow.tx_hash if vrow else None
            versions.append(ReportVersion(report_id=rid, report_hash=h, onchain_id=onchain.id if onchain else None,
                                          status=status, tx_hash=tx, explorer_url=await chain.explorer_url(tx) if tx else None,
                                          is_current=rid == report_id))
        bond = await chain.dispute_bond()
        dispute = await chain.get_dispute(reg.onchain_id)
    except (ChainError, ChainUnavailable) as e:
        raise _chain_error(e) from None
    current = next(v for v in versions if v.is_current)
    info = None
    if dispute is not None:
        reason = (await db.execute(select(DisputeReasonRow).where(DisputeReasonRow.report_id == report_id)
                                   .order_by(DisputeReasonRow.created_at.desc()))).scalars().first()
        info = DisputeInfo(disputer=dispute[0], bond_wei=dispute[1], reason_hash=reason.reason_hash if reason else None,
                           reason=reason.text if reason else None)
    live = current.status in (RegistryStatus.SUBMITTED, RegistryStatus.DISPUTED, RegistryStatus.VALIDATED)
    return ReportHistory(
        report_id=report_id, registered=True, chain_id=reg.chain_id, contract_address=reg.contract_address,
        dispute_bond_wei=bond, versions=versions, open_dispute=info,
        can_reassess=live and row.subject_type in REASSESSABLE,
        can_dispute=current.status in (RegistryStatus.SUBMITTED, RegistryStatus.VALIDATED))


@router.post("/reports/{report_id}/dispute-reason", response_model=DisputePrepared,
             dependencies=[Depends(_limit("register_limiter"))])
async def dispute_reason(report_id: str, req: DisputeReasonRequest, st: St, db: Db) -> DisputePrepared:
    """Store the (redacted) reason off-chain and return what the user's wallet needs to send the bonded dispute.
    The server never sends the dispute itself: the bond must come from the person disputing."""
    await _row_or_404(db, report_id)
    reg = await db.get(RegistryRow, report_id)
    if reg is None or reg.onchain_id is None:
        raise HTTPException(409, "Only reports registered on-chain can be disputed.")
    chain = _get_chain(st)
    text = redact(req.reason.strip()).text
    reason_hash = store.hash_bytes(text.encode())
    try:
        onchain = await chain.get_report(reg.onchain_id)
        if onchain.status not in (RegistryStatus.SUBMITTED, RegistryStatus.VALIDATED):
            raise HTTPException(409, f"This report is {onchain.status.value} and can't be disputed.")
        bond = await chain.dispute_bond()
        chain_id = await chain.chain_id()
    except (ChainError, ChainUnavailable) as e:
        raise _chain_error(e) from None
    if await db.get(DisputeReasonRow, reason_hash) is None:
        db.add(DisputeReasonRow(reason_hash=reason_hash, report_id=report_id, text=text, created_at=utcnow()))
        await db.commit()
    return DisputePrepared(reason_hash=reason_hash, onchain_id=reg.onchain_id, chain_id=chain_id,
                           contract_address=chain.address, bond_wei=bond,
                           calldata=chain.dispute_calldata(reg.onchain_id, reason_hash))


@router.post("/reports/{report_id}/reassess", response_model=AssessResponse,
             dependencies=[Depends(_limit("register_limiter"))])
async def reassess(report_id: str, st: St, db: Db) -> AssessResponse:
    """Assess the same link again and register the result as a revision (parentHash = this report's hash).
    The old version becomes Superseded on-chain; both stay verifiable."""
    row = await _row_or_404(db, report_id)
    if row.subject_type not in REASSESSABLE:
        raise HTTPException(422, "Only links can be re-assessed. Messages are stored redacted, so submit the message again.")
    reg = await db.get(RegistryRow, report_id)
    if reg is None or reg.onchain_id is None:
        raise HTTPException(409, "Register this report on-chain first; a revision links to the registered version.")
    chain = _get_chain(st)
    try:
        status = (await chain.get_report(reg.onchain_id)).status
    except (ChainError, ChainUnavailable) as e:
        raise _chain_error(e) from None
    if status in (RegistryStatus.SUPERSEDED, RegistryStatus.REJECTED):
        raise HTTPException(409, f"This report is already {status.value}; open its latest version instead.")
    _throttle(st.register_global, "all")
    old = store.parse_report(row)
    new = await _assess_and_store(st, db, old.subject, qr=row.subject_type == SubjectType.QR.value)
    new_row = await store.get_report_row(db, new.report_id)
    async with st.register_lock:
        try:
            rec = await chain.submit_report(store.parse_report(new_row), parent_hash=reg.report_hash)
        except (ChainError, ChainUnavailable) as e:
            raise _chain_error(e) from None
        await store.save_registry(db, rec)
        await store.save_registry(db, store.record(reg).model_copy(update={"status": RegistryStatus.SUPERSEDED}))
    return new


async def _verify(st: AppState, db: AsyncSession, report_id: str, canonical: bytes) -> VerificationResult:
    chain = _get_chain(st)
    computed = store.hash_bytes(canonical)
    try:
        onchain = await chain.find_by_hash(computed)
        reg = (await db.execute(select(RegistryRow).where(RegistryRow.report_hash == computed))).scalars().first()
        tx = reg.tx_hash if reg else None
        explorer = await chain.explorer_url(tx)
    except (ChainError, ChainUnavailable) as e:
        raise _chain_error(e) from None
    return VerificationResult(
        report_id=report_id, computed_hash=computed, onchain_hash=onchain.report_hash if onchain else None,
        match=onchain is not None, onchain_status=onchain.status if onchain else None,
        onchain_created_at=onchain.created_at if onchain else None, tx_hash=tx, explorer_url=explorer)


@router.get("/reports/{report_id}/verify", response_model=VerificationResult,
            dependencies=[Depends(_limit("verify_limiter"))])
async def verify_report(report_id: str, st: St, db: Db) -> VerificationResult:
    row = await _row_or_404(db, report_id)
    return await _verify(st, db, report_id, row.canonical)


@router.post("/verify", response_model=VerificationResult, dependencies=[Depends(_limit("verify_limiter"))])
async def verify_uploaded(request: Request, st: St, db: Db,
                          report: Annotated[dict[str, Any], Body(description="A report.json file, as downloaded")]
                          ) -> VerificationResult:
    """Hash an uploaded report.json exactly as verify/verify.py does (RFC 8785 → keccak256) and look it up."""
    if int(request.headers.get("content-length") or 0) > MAX_UPLOAD_JSON_BYTES:
        raise HTTPException(413, "File too large.")
    try:
        canonical = rfc8785.dumps(report)
    except (TypeError, ValueError, OverflowError, rfc8785.CanonicalizationError):
        raise HTTPException(422, "This file can't be canonicalised as JSON.") from None
    rid = report.get("report_id")
    return await _verify(st, db, rid if isinstance(rid, str) else "unknown", canonical)


# ---------- correlation ----------

@router.get("/clusters", response_model=list[Cluster])
async def clusters(st: St, db: Db) -> list[Cluster]:
    built = build_clusters(await store.indicator_rows(db))
    return await add_summaries(st.llm, built, st.cluster_summaries)


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}



