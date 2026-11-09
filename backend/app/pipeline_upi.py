"""UPI payment QR (upi://pay?pa=payee@bank&...): extract the payee and compare it with earlier reports.

There is no website to inspect, so nothing here can say a payee is genuine; the only evidence is whether the same
UPI ID already appeared in stored reports (CORR.* findings, added by the route). Only the payee ID is kept: the
free-text fields of the QR (name, note) are dropped.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qs, urlsplit

from app.engine import coverage as cov
from app.pipeline import FIXED_LIMITATIONS
from app.schemas import (
    AssessmentReport,
    CheckRun,
    CheckStatus,
    Indicator,
    RiskClass,
    SubjectType,
    utcnow,
)

VPA = re.compile(r"^[A-Za-z0-9._-]{2,64}@[A-Za-z][A-Za-z0-9.]{1,40}$")
UPI_REASON = "R4: a payment QR has no website to inspect; only earlier reports could be compared"
UPI_ACTIONS = [
    "Check that the payee name your UPI app shows is who you mean to pay before you confirm.",
    "Never scan a QR code or approve a request in order to receive money: receiving money never needs your PIN.",
]
UPI_LIMITATIONS = [
    "This QR is a payment request. We fetched no website and cannot confirm who the payee really is.",
    "The only check made was whether this UPI ID appears in earlier reports stored on this server.",
]


class UpiError(ValueError):
    """Not a usable UPI payment QR. The message is safe to show."""


def is_upi(text: str) -> bool:
    return text.strip().lower().startswith("upi:")


def parse_upi(text: str) -> str:
    parts = urlsplit(text.strip())
    pa = (parse_qs(parts.query).get("pa") or [""])[0].strip()
    if not VPA.match(pa):
        raise UpiError("This UPI QR code doesn't contain a valid payee ID.")
    return pa.lower()


def assess_upi(text: str) -> AssessmentReport:
    payee = parse_upi(text)
    runs = [CheckRun(check_group="upi.payee", status=CheckStatus.COMPLETED, source="local:upi_parser",
                     duration_ms=0, weight=0)]
    coverage = cov.compute(runs)
    return AssessmentReport(
        created_at=utcnow(), subject_type=SubjectType.QR, subject=f"upi://pay?pa={payee}", normalized_subject=payee,
        classification=RiskClass.INCONCLUSIVE, classification_reason=UPI_REASON, score=0, confidence="low",
        coverage=coverage, check_runs=runs, indicators=[Indicator(type="upi_id", value=payee, normalized=payee)],
        recommended_actions=list(UPI_ACTIONS),
        limitations=UPI_LIMITATIONS + FIXED_LIMITATIONS[:1])


def finalize(report: AssessmentReport) -> AssessmentReport:
    """After correlation: keep the UPI advice, and keep the honest reason when nothing was found."""
    if report.classification == RiskClass.INCONCLUSIVE:
        return report.model_copy(update={"classification_reason": UPI_REASON,
                                         "recommended_actions": UPI_ACTIONS})
    return report.model_copy(update={"recommended_actions": UPI_ACTIONS + report.recommended_actions})
