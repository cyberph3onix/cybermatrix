"""HTTP routes. Thin: validation, rate limits and persistence; the work happens in pipeline/ and registry/."""
from __future__ import annotations

import asyncio
import logging
import re
import time
from collections.abc import AsyncIterator
from datetime import UTC
from typing import Annotated, Any

import rfc8785
from fastapi import APIRouter, Body, Depends, File, Form, HTTPException, Query, Request, Response, UploadFile
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import feed, ownership, quick, screenshot, store, watch
from app import org as orgs
from app.ai.cluster_summary import add_summaries
from app.ai.explain import explain
from app.ai.llm import LlmUnavailable
from app.ai.redact import redact
from app.api.state import AppState
from app.brands import get_index
from app.correlation.checks import apply_correlation
from app.correlation.clusters import build_clusters, impersonation_trends
from app.db import DisputeReasonRow, OrgRow, OwnershipRow, RegistryRow, WatchAlertRow, WatchRow
from app.detect import detect_subject
from app.pipeline import assess_url
from app.pipeline_message import assess_email, assess_message
from app.pipeline_upi import UpiError, assess_upi, is_upi
from app.pipeline_upi import finalize as finalize_upi
from app.qr import QrError, decode_qr
from app.ratelimit import client_ip, limit_dependency
from app.registry.chain import ZERO_HASH, ChainClient, ChainError, ChainUnavailable, reporter_trusted
from app.registry.sync import on_contract
from app.schemas import (
    AssessmentReport,
    AssessRequest,
    AssessResponse,
    CheckStatus,
    Cluster,
    DisputeInfo,
    DisputePrepared,
    DisputeReasonRequest,
    ImpersonationTrend,
    OrgDashboard,
    OrgRequest,
    OwnershipChallenge,
    OwnershipChallengeRequest,
    OwnershipGrant,
    OwnershipVerifyRequest,
    QuickCheck,
    QuickCheckRequest,
    RegistryRecord,
    RegistryStatus,
    ReportHistory,
    ReportVersion,
    SubjectType,
    VerificationResult,
    Watch,
    WatchAlert,
    WatchRequest,
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
                            owns_site: bool = False, post=None) -> AssessResponse:
    """`post` (optional) transforms the report after the checks and before correlation, explanation and storage."""
    try:
        parsed = parse_url(url_input)
    except URLParseError as e:
        raise HTTPException(422, f"That doesn't look like a valid link ({e}).") from None
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(422, "Only http and https links can be assessed.")
    async with st.assess_slots:
        report = await assess_url(url_input, deps=st.deps, owns_site=owns_site)
    if post is not None:
        report = await post(report)
    report = await _explain(st, await apply_correlation(db, report))
    if qr:
        report = report.model_copy(update={"subject_type": SubjectType.QR.value})
    await store.save_report(db, report)
    return AssessResponse(report_id=report.report_id)


@router.post("/assess", response_model=AssessResponse, dependencies=[Depends(_limit("assess_limiter"))])
async def assess(req: AssessRequest, request: Request, st: St, db: Db) -> AssessResponse:
    text = req.input.strip()
    kind = req.subject_type or detect_subject(text)
    if req.owns_site:
        _throttle(st.owns_limiter, client_ip(request))
        await _require_ownership(db, text, req.ownership_token)
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


# ---------- site ownership (gate for the exposed-file probe) ----------

def _as_utc(dt):
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)  # SQLite returns naive datetimes


async def _require_ownership(db: AsyncSession, target: str, token: str | None) -> None:
    try:
        domain = ownership.domain_of(target)
    except ownership.OwnershipError as e:
        raise HTTPException(422, str(e)) from None
    row = (await db.execute(select(OwnershipRow).where(OwnershipRow.grant == token))).scalars().first() if token else None
    if (row is None or not ownership.same(row.domain, domain) or row.grant_expires_at is None
            or _as_utc(row.grant_expires_at) < utcnow()):
        raise HTTPException(403, f"Prove you own {domain} first (POST /ownership/challenge, then /ownership/verify). "
                                 "Checking a site's /.env and /.git needs the owner's permission.")


@router.post("/ownership/challenge", response_model=OwnershipChallenge, dependencies=[Depends(_limit("assess_limiter"))])
async def ownership_challenge(req: OwnershipChallengeRequest, db: Db) -> OwnershipChallenge:
    try:
        domain = ownership.domain_of(req.target)
    except ownership.OwnershipError as e:
        raise HTTPException(422, str(e)) from None
    challenge, now = ownership.new_token(), utcnow()
    db.add(OwnershipRow(challenge=challenge, domain=domain, created_at=now))
    await db.commit()
    return OwnershipChallenge(domain=domain, challenge=challenge, expires_at=now + ownership.CHALLENGE_TTL,
                              **ownership.instructions(domain, challenge))


@router.post("/ownership/verify", response_model=OwnershipGrant, dependencies=[Depends(_limit("assess_limiter"))])
async def ownership_verify(req: OwnershipVerifyRequest, st: St, db: Db) -> OwnershipGrant:
    row = await db.get(OwnershipRow, req.challenge)
    if row is None or _as_utc(row.created_at) + ownership.CHALLENGE_TTL < utcnow():
        raise HTTPException(404, "Unknown or expired challenge. Request a new one.")
    check = st.ownership_checker or ownership.make_checker(st.api, st.deps.fetcher or ownership.safe_fetch)
    method = await check(row.domain, row.challenge)
    if method is None:
        i = ownership.instructions(row.domain, row.challenge)
        raise HTTPException(409, f"Not found yet. Add a TXT record {i['txt_name']} with value {i['txt_value']}, or serve "
                                 f"{i['file_url']} containing the challenge. DNS changes can take a few minutes.")
    row.grant, row.method, row.grant_expires_at = ownership.new_token(), method, utcnow() + ownership.GRANT_TTL
    await db.commit()
    return OwnershipGrant(domain=row.domain, ownership_token=row.grant, method=method, expires_at=row.grant_expires_at)


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
        chain = _get_chain(st)
        if not on_contract(rec.contract_address, chain):
            return rec  # registered on an earlier deployment: its id means something else on this contract
        onchain = await chain.get_report(rec.onchain_id)
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
    if not on_contract(reg.contract_address, chain):
        return ReportHistory(report_id=report_id, registered=True, chain_id=reg.chain_id,
                             contract_address=reg.contract_address,
                             versions=[ReportVersion(report_id=report_id, report_hash=reg.report_hash,
                                                     onchain_id=reg.onchain_id, status=RegistryStatus(reg.status),
                                                     tx_hash=reg.tx_hash, is_current=True)],
                             note="Registered on an earlier registry contract. Its record stays verifiable there; "
                                  "disputes and revisions use the current contract.")
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
    if not on_contract(reg.contract_address, chain):
        raise HTTPException(409, "This report is on an earlier registry contract, which no longer takes disputes.")
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
    if not on_contract(reg.contract_address, chain):
        raise HTTPException(409, "This report is on an earlier registry contract; assess the link again instead.")
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
    # Anyone can call submitReport with the hash of a forged report.json. It only verifies as a CyberMatrix report
    # if our relayer registered it.
    return VerificationResult(
        report_id=report_id, computed_hash=computed, onchain_hash=onchain.report_hash if onchain else None,
        match=onchain is not None and reporter_trusted(chain, onchain.reporter),
        onchain_status=onchain.status if onchain else None,
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


@router.get("/trends/impersonation", response_model=list[ImpersonationTrend])
async def trends(db: Db) -> list[ImpersonationTrend]:
    """Recurring impersonation: which brands suspicious reports on this server pretend to be."""
    from app.db import ReportRow
    rows = await store.indicator_rows(db)
    ids = {r[0] for r in rows if r[1] == "brand_claimed"}
    kinds = dict((await db.execute(select(ReportRow.report_id, ReportRow.subject_type)
                                   .where(ReportRow.report_id.in_(ids)))).all()) if ids else {}
    return impersonation_trends(rows, kinds)


# ---------- CT watchlist ----------

async def _watch_view(db: AsyncSession, w: WatchRow) -> Watch:
    alerts = (await db.execute(select(WatchAlertRow).where(WatchAlertRow.watch_id == w.watch_id)
                               .order_by(WatchAlertRow.seen_at.desc(), WatchAlertRow.id.desc()).limit(100))).scalars()
    return Watch(watch_id=w.watch_id, domain=w.domain, created_at=w.created_at, last_checked=w.last_checked,
                 known_certificates=len(w.known_certs or []), known_issuers=sorted(w.known_issuers or []),
                 alerts=[WatchAlert(cert_sha256=a.cert_sha256, dns_names=a.dns_names or [], issuer=a.issuer,
                                    not_before=a.not_before, new_issuer=a.new_issuer, seen_at=a.seen_at) for a in alerts])


@router.post("/watch", response_model=Watch, dependencies=[Depends(_limit("register_limiter"))])
async def create_watch(req: WatchRequest, st: St, db: Db) -> Watch:
    try:
        domain = ownership.domain_of(req.domain)
    except ownership.OwnershipError as e:
        raise HTTPException(422, str(e)) from None
    if await watch.count(st.db) >= watch.MAX_WATCHES:
        raise HTTPException(429, "The watchlist is full on this server.")
    wid = watch.new_token()
    db.add(WatchRow(watch_id=wid, domain=domain, created_at=utcnow(), known_certs=[], known_issuers=[]))
    await db.commit()
    try:
        await watch.poll_one(st.db, st.api, wid)  # baseline: certificates that exist today are not alerts
    except watch.ApiUnavailable:
        pass  # the background poll takes the baseline later
    db.expire_all()
    return await _watch_view(db, await db.get(WatchRow, wid))


@router.get("/watch/{watch_id}", response_model=Watch)
async def get_watch(watch_id: str, db: Db) -> Watch:
    w = await db.get(WatchRow, watch_id) if re.fullmatch(r"[0-9a-f]{24}", watch_id) else None
    if w is None:
        raise HTTPException(404, "No watch with this ID.")
    return await _watch_view(db, w)


# ---------- real-time protection (browser extension) ----------

@router.post("/quick-check", response_model=QuickCheck, dependencies=[Depends(_limit("quick_limiter"))])
async def quick_check(req: QuickCheckRequest, st: St, db: Db) -> QuickCheck:
    """Fast check for every page the extension opens. The page is not fetched and nothing is stored or logged."""
    try:
        parsed = parse_url(req.url)
    except URLParseError as e:
        raise HTTPException(422, f"That doesn't look like a valid link ({e}).") from None
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(422, "Only http and https links can be checked.")
    return await quick.quick_check(db, parsed, deps=st.deps)


# ---------- screenshot impersonation ----------

@router.post("/assess/screenshot", response_model=AssessResponse, dependencies=[Depends(_limit("assess_limiter"))])
async def assess_screenshot(st: St, db: Db,
                            file: Annotated[UploadFile, File(description="PNG/JPEG/WebP screenshot of the page")],
                            url: Annotated[str, Form(description="Address the page was shown at", max_length=MAX_URL_CHARS)],
                            consent: Annotated[bool, Form(description="The user agreed the image goes to the AI provider")] = False,
                            ) -> AssessResponse:
    """Full assessment of `url` plus PAGE.SCREENSHOT_BRAND_MISMATCH: a vision model reads which brand the screenshot
    shows; code compares it with the page's domain. The image is never stored."""
    if not consent:
        raise HTTPException(422, "A screenshot can show personal details and is sent to the AI provider. "
                                 "Confirm consent (and crop out anything personal) to continue.")
    llm = st.llm
    if llm is None:
        raise HTTPException(503, "Screenshot analysis needs an AI model, and none is configured on this server.")
    try:
        jpeg = screenshot.prepare_image(await file.read(screenshot.MAX_BYTES + 1))
    except screenshot.ScreenshotError as e:
        raise HTTPException(422, str(e)) from None
    t0 = time.monotonic()
    claim_task = asyncio.ensure_future(screenshot.extract(llm, jpeg))

    async def post(report: AssessmentReport) -> AssessmentReport:
        shown_at = report.redirect_chain[-1].url if report.redirect_chain else report.normalized_subject
        try:
            claim = await claim_task
        except LlmUnavailable as e:
            return screenshot.merge(report, screenshot.run_record(CheckStatus.UNAVAILABLE, llm.model, t0, str(e)), [])
        findings = screenshot.decide(claim, shown_at, st.deps.brands or get_index(), model=llm.model)
        return screenshot.merge(report, screenshot.run_record(CheckStatus.COMPLETED, llm.model, t0), findings)

    try:
        return await _assess_and_store(st, db, url.strip(), post=post)
    finally:
        claim_task.cancel()


# ---------- threat-intel sharing ----------

FeedLevel = Query("high_risk", pattern="^(suspicious|high_risk|confirmed_malicious)$",
                  description="Lowest class to include")


@router.get("/feeds/stix", dependencies=[Depends(_limit("feed_limiter"))],
            responses={200: {"description": "STIX 2.1 bundle of indicator objects", "content": {"application/json": {}}}})
async def feed_stix(st: St, db: Db, level: str = FeedLevel) -> JSONResponse:
    items = await feed.collect(db, st.deps.brands or get_index(), level=level)
    return JSONResponse(feed.stix_bundle(items), media_type="application/stix+json;version=2.1")


@router.get("/feeds/blocklist.txt", response_class=PlainTextResponse, dependencies=[Depends(_limit("feed_limiter"))])
async def feed_blocklist(st: St, db: Db, level: str = FeedLevel) -> PlainTextResponse:
    items = await feed.collect(db, st.deps.brands or get_index(), level=level)
    return PlainTextResponse(feed.blocklist(items))


# ---------- organisation dashboard ----------

async def _org_or_404(db: AsyncSession, org_id: str) -> OrgRow:
    o = await db.get(OrgRow, org_id) if re.fullmatch(r"[0-9a-f]{24}", org_id) else None
    if o is None:
        raise HTTPException(404, "No organisation with this ID.")
    return o


@router.post("/orgs", response_model=OrgDashboard, dependencies=[Depends(_limit("register_limiter"))])
async def create_org(req: OrgRequest, st: St, db: Db) -> OrgDashboard:
    try:
        domains = orgs.normalize_domains(req.domains)
    except orgs.OrgError as e:
        raise HTTPException(422, str(e)) from None
    if await watch.count(st.db) + len(domains) > watch.MAX_WATCHES:
        raise HTTPException(429, "The certificate watchlist on this server is full.")
    now = utcnow()
    watch_ids = {d: watch.new_token() for d in domains}
    for d, wid in watch_ids.items():
        db.add(WatchRow(watch_id=wid, domain=d, created_at=now, known_certs=[], known_issuers=[]))
    oid = orgs.new_token()
    db.add(OrgRow(org_id=oid, name=req.name.strip(), domains=domains, watch_ids=watch_ids, created_at=now))
    await db.commit()
    for wid in watch_ids.values():  # baseline: today's certificates are not alerts
        try:
            await watch.poll_one(st.db, st.api, wid)
        except watch.ApiUnavailable:
            break  # the background poll takes the remaining baselines
    db.expire_all()
    return await orgs.dashboard(db, st.deps.brands or get_index(), await _org_or_404(db, oid))


@router.get("/orgs/{org_id}", response_model=OrgDashboard)
async def get_org(org_id: str, st: St, db: Db) -> OrgDashboard:
    return await orgs.dashboard(db, st.deps.brands or get_index(), await _org_or_404(db, org_id))


@router.post("/orgs/{org_id}/scan", response_model=OrgDashboard, dependencies=[Depends(_limit("assess_limiter"))])
async def scan_org(org_id: str, st: St, db: Db) -> OrgDashboard:
    """Assess every domain's home page again (the normal passive assessment) and return the refreshed dashboard."""
    o = await _org_or_404(db, org_id)
    wait = orgs.scan_wait(o)
    if wait is not None:
        raise HTTPException(429, f"This organisation was scanned recently. Try again in {wait} s.",
                            headers={"Retry-After": str(wait)})
    o.last_scan = utcnow()
    await db.commit()

    async def one(domain: str) -> None:
        async with st.db.session() as s:
            await _assess_and_store(st, s, f"https://{domain}/")

    await asyncio.gather(*(one(d) for d in o.domains), return_exceptions=True)
    db.expire_all()
    return await orgs.dashboard(db, st.deps.brands or get_index(), await _org_or_404(db, org_id))


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}



