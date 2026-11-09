"""CORR.* findings against a real (sqlite) database."""
import pytest

from app import store
from app.correlation.checks import apply_correlation
from app.db import Database
from app.engine import coverage as cov
from app.schemas import AssessmentReport, CheckRun, Indicator, RegistryRecord, RegistryStatus, RiskClass, SubjectType

SCAM = "kyc-verify-now.top"


def mk(classification="suspicious", inds=(("domain", SCAM),), score=20):
    runs = [CheckRun(check_group=g, status="completed", source="t", duration_ms=1, weight=w) for g, w in cov.WEIGHTS.items()]
    return AssessmentReport(
        subject_type=SubjectType.URL, subject="https://x", normalized_subject="https://x",
        classification=classification, classification_reason="test", score=score, confidence="medium",
        coverage=cov.compute(runs), check_runs=runs, limitations=["l"],
        indicators=[Indicator(type=t, value=v, normalized=v) for t, v in inds])


@pytest.fixture
async def db(tmp_path):
    d = Database(f"sqlite+aiosqlite:///{tmp_path / 'c.db'}")
    await d.create_all()
    yield d
    await d.aclose()


async def put(db, report, status=None):
    async with db.session() as s:
        await store.save_report(s, report)
        if status:
            await store.save_registry(s, RegistryRecord(
                report_id=report.report_id, report_hash="0x" + "11" * 32, chain_id=1, contract_address="0x" + "22" * 20,
                status=RegistryStatus(status)))


async def corr(db, report):
    async with db.session() as s:
        return await apply_correlation(s, report)


async def test_two_prior_suspicious_reports_raise_prior_reports(db):
    for _ in range(2):
        await put(db, mk())
    out = await corr(db, mk("low_risk", score=0))
    ids = [f.check_id for f in out.findings]
    assert ids == ["CORR.PRIOR_REPORTS"] and out.classification == RiskClass.SUSPICIOUS
    assert out.related_report_ids and out.limitations[-1].startswith("Correlation compares")
    assert out.findings[0].evidence[0].source == "local:correlation"


async def test_one_prior_report_is_not_enough(db):
    await put(db, mk())
    out = await corr(db, mk("low_risk", score=0))
    assert out.findings == [] and out.classification == "low_risk"


async def test_prior_reports_that_were_low_risk_do_not_count(db):
    for _ in range(3):
        await put(db, mk("low_risk", score=0))
    assert (await corr(db, mk("low_risk", score=0))).findings == []


async def test_validated_report_makes_confirmed_malicious(db):
    await put(db, mk(), status="validated")
    out = await corr(db, mk("low_risk", score=0))
    assert [f.check_id for f in out.findings] == ["CORR.VALIDATED_MATCH"]
    assert out.classification == RiskClass.CONFIRMED_MALICIOUS and out.classification_reason.startswith("R1")


async def test_disputed_or_submitted_registry_status_is_not_validated(db):
    await put(db, mk("low_risk", score=0), status="submitted")
    await put(db, mk("low_risk", score=0), status="disputed")
    assert (await corr(db, mk("low_risk", score=0))).findings == []


async def test_allowlisted_domain_never_correlates(db):
    for _ in range(3):
        await put(db, mk(inds=(("domain", "google.com"),)), status="validated")
    assert (await corr(db, mk("low_risk", inds=(("domain", "google.com"),), score=0))).findings == []


async def test_shared_infra_is_low_and_does_not_move_a_low_risk_site_to_suspicious(db):
    await put(db, mk(inds=(("ip", "198.51.100.7"), ("nameserver", "ns1.cheap-dns.net"))))
    out = await corr(db, mk("low_risk", inds=(("domain", "other-shop.com"), ("ip", "198.51.100.7")), score=0))
    assert [(f.check_id, f.severity) for f in out.findings] == [("CORR.SHARED_INFRA", "low")]
    assert out.classification == RiskClass.LOW_RISK


async def test_personal_values_stay_out_of_evidence(db):
    for _ in range(2):
        await put(db, mk(inds=(("phone", "+919876543210"), ("email", "a@evil.top"))))
    out = await corr(db, mk("low_risk", inds=(("phone", "+919876543210"),), score=0))
    blob = "".join(f.model_dump_json() for f in out.findings)  # indicators[] holds the report's own values
    assert "+919876543210" not in blob and "a@evil.top" not in blob
    assert out.findings[0].evidence[0].data["indicator_type"] == "phone"


async def test_a_report_never_matches_itself(db):
    r = mk()
    await put(db, r)
    assert (await corr(db, r)).findings == []


async def test_stored_columns_hold_plain_values_not_enum_reprs(db):
    """Regression (found on Postgres): model_copy left Enum members in fields, so the row stored
    'RiskClass.CONFIRMED_MALICIOUS' (overflowing varchar(24)) and clusters never matched it."""
    from sqlalchemy import select

    from app.db import ReportRow
    await put(db, mk(), status="validated")
    out = await corr(db, mk("low_risk", score=0))
    assert out.classification == "confirmed_malicious" and not hasattr(out.classification, "value")
    qr = out.model_copy(update={"subject_type": SubjectType.QR.value})
    await put(db, qr)
    async with db.session() as s:
        row = (await s.execute(select(ReportRow).where(ReportRow.report_id == qr.report_id))).scalar_one()
    assert (row.classification, row.subject_type) == ("confirmed_malicious", "qr")
    from app.store import _val
    assert _val(RiskClass.HIGH_RISK) == "high_risk" and _val("qr") == "qr"
