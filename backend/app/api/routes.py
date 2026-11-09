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
from app.ai.explain import explain
from app.ai.llm import LlmUnavailable
from app.api.state import AppState
from app.correlation.clusters import build_clusters
from app.db import RegistryRow
from app.detect import detect_subject
from app.pipeline import assess_url
from app.pipeline_message import assess_email, assess_message
from app.qr import QrError, decode_qr
from app.ratelimit import limit_dependency
from app.registry.chain import ChainClient, ChainError, ChainUnavailable
from app.schemas import (
    AssessmentReport,
    AssessRequest,
    AssessResponse,
    Cluster,
    RegistryRecord,
    SubjectType,
    VerificationResult,
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
    report = await _explain(st, report)
    if qr:
        report = report.model_copy(update={"subject_type": SubjectType.QR})
    await store.save_report(db, report)
    return AssessResponse(report_id=report.report_id)


@router.post("/assess", response_model=AssessResponse, dependencies=[Depends(_limit("assess_limiter"))])
async def assess(req: AssessRequest, st: St, db: Db) -> AssessResponse:
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
        report = await _explain(st, report)
    elif kind == SubjectType.MESSAGE:
        async with st.assess_slots:
            report = await assess_message(req.input, deps=st.deps, llm=st.llm)
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
    if len(link) > MAX_URL_CHARS or not re.match(r"^https?://", link, re.IGNORECASE):
        raise HTTPException(422, "This QR code doesn't contain a web link, so there is nothing to assess.")
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
async def clusters(db: Db) -> list[Cluster]:
    return build_clusters(await store.indicator_rows(db))


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}



