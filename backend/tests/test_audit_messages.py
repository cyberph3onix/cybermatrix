"""Compliance audit, Module 3: one fixture message per scam pattern in the brief (M3-1), wording alone is never
high_risk (M3-5), and real-format benign messages stay unflagged (M3-6). Offline: regex signals only, no LLM."""
import pytest

from app.brands import get_index
from app.checks import message
from app.engine import risk
from app.pipeline import Deps
from app.pipeline_message import assess_message


def _ids(text: str) -> set[str]:
    return {f.check_id for f in message.regex_signals(text, get_index())}


# (pattern from the brief, message, check_ids that must fire)
PATTERNS = [
    ("fake job / internship with fee",
     "Congratulations! You have been selected for a work from home internship with Infosys. Pay the registration fee "
     "of Rs 1,499 today to confirm: infosys-careers-hr.in",
     {"MSG.REWARD_LURE", "MSG.PAYMENT_REQUEST", "MSG.SCAM_PATTERN"}),
    ("investment / crypto (guaranteed returns, wallet address)",
     "Join our crypto investment plan: guaranteed returns of 5% daily. Send USDT to "
     "0x52908400098527886E0F7030069857D2E4169EE7 and double your money in 20 days.",
     {"MSG.INVESTMENT_LURE", "MSG.REWARD_LURE"}),
    ("giveaway / prize",
     "Congratulations! You have won Rs 25,00,000 in the KBC lucky draw. Claim now: kbc-claim.com",
     {"MSG.REWARD_LURE", "MSG.SCAM_PATTERN"}),
    ("refund / cashback",
     "Your income tax refund of Rs 15,490 is approved. Claim your refund within 24 hours at itr-refund-portal.in",
     {"MSG.REWARD_LURE", "MSG.URGENCY"}),
    ("bank impersonation",
     "Dear customer, your SBI account will be blocked today. Update your KYC at sbi-help.xyz",
     {"MSG.AUTHORITY_IMPERSONATION", "MSG.URGENCY", "MSG.CREDENTIAL_REQUEST", "MSG.SCAM_PATTERN"}),
    ("university impersonation",
     "WBJEE 2026: your admission is cancelled. Pay the verification fee of Rs 2,000 immediately at wbjee-verify.in",
     {"MSG.AUTHORITY_IMPERSONATION", "MSG.PAYMENT_REQUEST", "MSG.URGENCY"}),
    ("fake customer support",
     "Amazon customer care: your order refund is on hold. Call now on +91 98765 43210 to process it.",
     {"MSG.AUTHORITY_IMPERSONATION", "MSG.REWARD_LURE", "MSG.SCAM_PATTERN"}),
    ("OTP / password / payment credential request",
     "Please share the OTP sent to your phone and your card number to verify this transaction.",
     {"MSG.CREDENTIAL_REQUEST"}),
    ("fake KYC",
     "Your Paytm KYC will expire today. Complete your KYC now or your wallet will be blocked: paytm-kyc.in",
     {"MSG.CREDENTIAL_REQUEST", "MSG.URGENCY", "MSG.SCAM_PATTERN"}),
    ("fake tech support / remote access",
     "Microsoft support: your computer is infected. Download AnyDesk and share the 9-digit code with our technician.",
     {"MSG.REMOTE_ACCESS_REQUEST", "MSG.AUTHORITY_IMPERSONATION"}),
    ("remote access via 'install this app'",
     "Bank refund team: to receive your refund install this app sbi-refund.apk and keep it open.",
     {"MSG.REMOTE_ACCESS_REQUEST", "MSG.REWARD_LURE"}),
]


@pytest.mark.parametrize("name,text,expected", PATTERNS, ids=[p[0] for p in PATTERNS])
def test_scam_pattern_fixture_fires(name, text, expected):
    got = _ids(text)
    assert expected <= got, f"{name}: missing {expected - got}, got {got}"


def test_new_message_checks_are_heuristic_with_spec_severity():
    from app.checks.catalogue import CATALOGUE
    assert CATALOGUE["MSG.REMOTE_ACCESS_REQUEST"].severity == "medium"
    assert CATALOGUE["MSG.INVESTMENT_LURE"].severity == "low"
    assert CATALOGUE["MSG.REMOTE_ACCESS_REQUEST"].strength == CATALOGUE["MSG.INVESTMENT_LURE"].strength == "heuristic"


@pytest.mark.parametrize("text", [
    "AnyDesk 8.1 release notes: faster file transfer.",           # product news, no request
    "Our support team will never ask you to install AnyDesk.",    # negated: still a mention, tolerated below
])
def test_remote_access_mention_without_request_is_not_high_risk(text):
    # Whatever wording fires, a message with no technical finding can never pass suspicious (heuristic cap)
    assert risk.classify(message.regex_signals(text, get_index()), 100).classification in ("low_risk", "suspicious")


# ---------- M3-5: persuasive wording alone is never high_risk ----------

PRESSURE_ONLY = [
    "URGENT!!! Your account will be blocked within 24 hours. Final notice. Act immediately.",
    "Congratulations, you have won a lottery prize! Claim now, last chance, offer expires today!",
    "RBI and cyber crime cell notice: FIR registered, digital arrest warrant issued, reply YES immediately.",
    "Guaranteed returns 10% daily, double your money, risk-free trading signals, limited seats tonight!",
    "Share your OTP and PIN now, pay Rs 5000 processing fee, install AnyDesk, your KYC will expire today.",
    "Dear customer your SBI HDFC ICICI Paytm account will be suspended. Update KYC. Urgent. Call now. Claim refund.",
]


@pytest.mark.parametrize("text", PRESSURE_ONLY)
async def test_wording_alone_never_high_risk(text):
    rep = await assess_message(text, deps=Deps(checks=[]))
    assert rep.classification in ("low_risk", "inconclusive", "suspicious"), rep.classification_reason
    assert all(f.strength == "heuristic" for f in rep.findings)
    # the same signals at full coverage cannot pass suspicious either
    assert risk.classify(rep.findings, 100).classification in ("low_risk", "suspicious")


# ---------- M3-6: real-format benign messages ----------

BENIGN = [
    ("bank OTP", "Your OTP is 482913. Do not share it with anyone."),
    ("bank OTP, long form", "482913 is your OTP for txn of INR 1,250.00 at AMAZON on HDFC Bank card xx1234. Valid for 5 "
                            "mins. Do not share this OTP with anyone. -HDFC Bank"),
    ("debit alert", "Rs.500.00 debited from A/c XX1234 on 09-11-26 to VPA swiggy@icici (UPI Ref 431298765412). "
                    "Not you? Call 18002586161 to report. -SBI"),
    ("delivery update", "Your Amazon order #408-1234567-1234567 has been shipped and will arrive by Thursday. "
                        "Track it in the Amazon app."),
]


@pytest.mark.parametrize("name,text", BENIGN, ids=[b[0] for b in BENIGN])
async def test_benign_real_format_messages_not_flagged(name, text):
    ids = _ids(text)
    assert "MSG.CREDENTIAL_REQUEST" not in ids, name  # containing an OTP is not asking for one
    assert not ids & {"MSG.PAYMENT_REQUEST", "MSG.REMOTE_ACCESS_REQUEST", "MSG.INVESTMENT_LURE", "MSG.SCAM_PATTERN"}
    rep = await assess_message(text, deps=Deps(checks=[]))
    assert rep.classification in ("low_risk", "inconclusive"), (name, rep.classification_reason)


# ---------- M1-9: the brief's example targets, one lookalike each ----------

SECTOR_LOOKALIKES = [
    ("bank", "https://sbi-yono-kyc.top/login"),
    ("payment gateway", "https://paytm-kyc-update.xyz/verify"),
    ("university admission / exam portal", "https://wbjee-admission-portal.in/result"),
    ("university (IEM)", "https://iem-admission-fee.top/pay"),
    ("government / tax", "https://incometax-refund-status.top/claim"),
    ("parcel delivery (India Post)", "https://indiapost-redelivery.xyz/track"),
    ("job portal", "https://naukri-hr-offer.top/apply"),
    ("social login", "https://accounts.google.com.signin-verify.top/"),
    ("customer support / account recovery", "https://microsoft-account-recovery.top/support"),
]


@pytest.mark.parametrize("sector,url", SECTOR_LOOKALIKES, ids=[s for s, _ in SECTOR_LOOKALIKES])
def test_each_brief_sector_lookalike_is_flagged(sector, url):
    from tests.test_url_checks import ids as url_ids
    got = url_ids(url)
    assert got & {"URL.LOOKALIKE.TYPOSQUAT", "URL.LOOKALIKE.HOMOGLYPH", "URL.BRAND_IN_SUBDOMAIN"}, (sector, got)
