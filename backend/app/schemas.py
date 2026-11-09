"""Canonical data contract for TrustLens.

- The frontend's TypeScript types are generated from the FastAPI OpenAPI spec built on these models.
- The on-chain commitment is keccak256(RFC8785-JCS(report.model_dump(mode="json"))).
- No floats anywhere: integers only, so canonical JSON is identical across Python/JS/Solidity tooling.
"""
from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

SCHEMA_VERSION = "1.0.0"


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


class Strict(BaseModel):
    # json_schema_serialization_defaults_required only shapes the OpenAPI *response* schema (fields with defaults
    # are always present in what we send), so the generated TypeScript types need no `?`. Data and hash unaffected.
    model_config = ConfigDict(extra="forbid", use_enum_values=True, json_schema_serialization_defaults_required=True)


# ---------- enums ----------

class RiskClass(str, Enum):
    LOW_RISK = "low_risk"
    SUSPICIOUS = "suspicious"
    HIGH_RISK = "high_risk"
    CONFIRMED_MALICIOUS = "confirmed_malicious"
    INCONCLUSIVE = "inconclusive"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EvidenceStrength(str, Enum):
    AUTHORITATIVE = "authoritative"
    TECHNICAL = "technical"
    HEURISTIC = "heuristic"


class FindingCategory(str, Enum):
    PHISHING = "phishing"
    IMPERSONATION = "impersonation"
    REDIRECT = "redirect"
    THREAT_INTEL = "threat_intel"
    DOMAIN = "domain"
    TLS_TRUST = "tls_trust"
    TLS_CONFIG = "tls_config"
    SOCIAL_ENGINEERING = "social_engineering"
    CORRELATION = "correlation"
    SECURITY_POSTURE = "security_posture"


class CheckStatus(str, Enum):
    COMPLETED = "completed"
    FAILED = "failed"            # we tried and errored (timeout, parse error)
    UNAVAILABLE = "unavailable"  # source down, no API key, rate-limited
    SKIPPED = "skipped"          # not applicable (e.g. TLS for http://)


class SubjectType(str, Enum):
    URL = "url"
    DOMAIN = "domain"
    MESSAGE = "message"
    EMAIL = "email"
    QR = "qr"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RegistryStatus(str, Enum):  # mirrors ThreatRegistry.Status
    SUBMITTED = "submitted"
    DISPUTED = "disputed"
    VALIDATED = "validated"
    REJECTED = "rejected"
    SUPERSEDED = "superseded"


IndicatorType = Literal[
    "url", "domain", "ip", "asn", "nameserver", "cert_sha256",
    "email", "phone", "upi_id", "crypto_address",
    "message_family", "brand_claimed",
]


# ---------- building blocks ----------

class Evidence(Strict):
    kind: str = Field(description="certificate_field | http_redirect | ti_match | dns_record | rdap | html_element | text_span | ct_entry")
    description: str
    data: dict[str, Any] = Field(default_factory=dict, description="Small raw observed values. No floats.")
    source: str = Field(description="local:tls_inspector | google_safe_browsing | urlhaus | openphish | virustotal | crt.sh | rdap | llm:claude-haiku-5-5 ...")
    observed_at: datetime


class Finding(Strict):
    check_id: str = Field(description="Stable ID from docs/RISK_ENGINE.md, e.g. TLS.EXPIRED")
    title: str
    category: FindingCategory
    severity: Severity
    strength: EvidenceStrength
    evidence: list[Evidence] = Field(min_length=1)
    impact: str
    recommendation: str
    limitation: str | None = None
    indicator_ref: str | None = Field(default=None, description="Normalized indicator this finding is about (for message sub-assessments)")


class CheckRun(Strict):
    check_group: str = Field(description="url.structure | intel.gsb | fetch.redirects | tls.chain | ...")
    status: CheckStatus
    source: str
    duration_ms: int
    weight: int = Field(ge=0, le=100)
    detail: str | None = None


class Indicator(Strict):
    type: IndicatorType
    value: str
    normalized: str


class RedirectHop(Strict):
    url: str
    status_code: int
    resolved_ip: str | None = None
    cross_domain: bool = False


class CertificateSummary(Strict):
    subject_cn: str | None = None
    san: list[str] = Field(default_factory=list)
    issuer: str
    chain_issuers: list[str] = Field(default_factory=list)
    not_before: datetime
    not_after: datetime
    days_remaining: int
    key_type: Literal["RSA", "EC", "Ed25519", "other"]
    key_bits: int
    signature_algorithm: str
    sha256_fingerprint: str
    ocsp_status: Literal["good", "revoked", "unknown", "unchecked"] = "unchecked"
    ct_sct_count: int = 0
    ct_logged_in_crtsh: bool | None = None
    chain_valid: bool
    tls_version: str | None = None


class Coverage(Strict):
    percent: int = Field(ge=0, le=100)
    completed: list[str] = Field(default_factory=list)
    unavailable: list[str] = Field(default_factory=list)
    failed: list[str] = Field(default_factory=list)
    skipped: list[str] = Field(default_factory=list)


class AIExplanation(Strict):
    model: str
    summary: str
    language_signals: list[str] = Field(default_factory=list, description="MSG.* check_ids the LLM supported")
    verified_evidence_refs: list[str] = Field(default_factory=list, description="check_ids from deterministic findings it relied on")
    injection_attempt_detected: bool = False
    disclaimer: str = "AI-generated explanation of the findings above. The classification is computed by deterministic rules, not by the AI."


# ---------- the report ----------

class AssessmentReport(Strict):
    schema_version: str = SCHEMA_VERSION
    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    salt: str = Field(default_factory=lambda: secrets.token_hex(32), description="Prevents brute-forcing the on-chain hash back to the URL")
    created_at: datetime = Field(default_factory=utcnow)

    subject_type: SubjectType
    subject: str = Field(description="Raw input as submitted (redacted for messages). OFF-CHAIN ONLY.")
    normalized_subject: str

    classification: RiskClass
    classification_reason: str = Field(description='Rule + triggering check_ids, e.g. "R1: URL.INTEL.GSB"')
    score: int = Field(ge=0, le=100)
    confidence: Confidence
    coverage: Coverage

    findings: list[Finding] = Field(default_factory=list)
    security_posture: list[Finding] = Field(default_factory=list, description="Module 5 hygiene findings. Never affect classification.")
    check_runs: list[CheckRun] = Field(default_factory=list)

    indicators: list[Indicator] = Field(default_factory=list)
    redirect_chain: list[RedirectHop] = Field(default_factory=list)
    certificate: CertificateSummary | None = None
    ai: AIExplanation | None = None

    recommended_actions: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list, description="Always non-empty. Includes unavailable checks and fixed caveats.")
    related_report_ids: list[str] = Field(default_factory=list)


# ---------- registry ----------

class RegistryRecord(Strict):
    report_id: str
    report_hash: str = Field(description="0x-prefixed keccak256 of the canonical report")
    parent_hash: str = "0x" + "00" * 32
    chain_id: int
    contract_address: str
    onchain_id: int | None = None
    tx_hash: str | None = None
    reporter_address: str | None = None
    status: RegistryStatus = RegistryStatus.SUBMITTED


class VerificationResult(Strict):
    report_id: str
    computed_hash: str
    onchain_hash: str | None
    match: bool
    onchain_status: RegistryStatus | None = None
    onchain_created_at: datetime | None = None
    tx_hash: str | None = None
    explorer_url: str | None = None
    note: str = "A matching hash proves this report is unchanged since it was registered. It does not prove the report's conclusions are true."


class DisputeInfo(Strict):
    disputer: str = Field(description="Address that posted the bond")
    bond_wei: int
    reason_hash: str | None = Field(default=None, description="keccak256 of the reason text, if this server stored it")
    reason: str | None = Field(default=None, description="Redacted reason text, kept off-chain")


class ReportVersion(Strict):
    report_id: str | None = Field(description="None if this server does not hold that version")
    report_hash: str
    onchain_id: int | None = None
    status: RegistryStatus
    tx_hash: str | None = None
    explorer_url: str | None = None
    is_current: bool = Field(description="The version whose history was requested")


class ReportHistory(Strict):
    report_id: str
    registered: bool
    chain_id: int | None = None
    contract_address: str | None = None
    dispute_bond_wei: int | None = Field(default=None, description="Bond required to dispute, read from the contract")
    versions: list[ReportVersion] = Field(default_factory=list, description="Oldest first, following parentHash links")
    open_dispute: DisputeInfo | None = None
    can_reassess: bool = False
    can_dispute: bool = False
    note: str = ("Statuses are read from the contract. Disputes are sent from your own wallet with a bond, which is "
                 "returned if a validator agrees with you and kept if not. The reason text stays off-chain; only its "
                 "hash is recorded.")


class DisputeReasonRequest(Strict):
    reason: str = Field(min_length=10, max_length=2000, description="Why this report is wrong. Personal details are masked.")


class DisputePrepared(Strict):
    """What a wallet needs to call disputeReport(onchain_id, reason_hash) with value = bond_wei."""
    reason_hash: str
    onchain_id: int
    chain_id: int
    contract_address: str
    bond_wei: int
    calldata: str = Field(description="ABI-encoded disputeReport call, ready for eth_sendTransaction")


class OwnershipChallengeRequest(Strict):
    target: str = Field(min_length=1, max_length=2048, description="Domain or link of the site you own")


class OwnershipChallenge(Strict):
    domain: str
    challenge: str
    txt_name: str
    txt_value: str
    file_url: str
    file_body: str
    expires_at: datetime


class OwnershipVerifyRequest(Strict):
    challenge: str = Field(min_length=32, max_length=32)


class OwnershipGrant(Strict):
    domain: str
    ownership_token: str = Field(description="Send as ownership_token with owns_site=true on POST /assess")
    method: Literal["dns", "file"]
    expires_at: datetime


class WatchRequest(Strict):
    domain: str = Field(min_length=3, max_length=253, description="Domain to monitor in Certificate Transparency")


class WatchAlert(Strict):
    cert_sha256: str
    dns_names: list[str]
    issuer: str
    not_before: str | None = None
    new_issuer: bool = Field(description="Issued by a CA this domain had not used before")
    seen_at: datetime


class Watch(Strict):
    watch_id: str = Field(description="Keep this: it is the only way to read the alerts")
    domain: str
    created_at: datetime
    last_checked: datetime | None = None
    known_certificates: int
    known_issuers: list[str]
    alerts: list[WatchAlert] = Field(default_factory=list, description="Newest first")
    note: str = ("New certificates found in Certificate Transparency logs since the watch started. A new certificate is "
                 "usually routine renewal; one from a CA you don't use, or for a name you don't recognise, is worth checking.")


# ---------- API requests ----------

class AssessRequest(Strict):
    input: str = Field(min_length=1, max_length=20_000)
    subject_type: SubjectType | None = Field(default=None, description="Auto-detected if omitted")
    owns_site: bool = Field(default=False, description="Run the exposed-file posture probe. Needs ownership_token")
    ownership_token: str | None = Field(default=None, max_length=64,
                                        description="Grant from POST /ownership/verify for this site's domain")

    @field_validator("input")
    @classmethod
    def _strip_nul(cls, v: str) -> str:
        return v.replace("\x00", "")  # Postgres text columns reject NUL, and it has no meaning in a link or message


# ---------- canonical hashing (registry/canonical.py imports this) ----------

def canonical_bytes(report: AssessmentReport) -> bytes:
    import rfc8785
    return rfc8785.dumps(report.model_dump(mode="json"))


def report_hash(report: AssessmentReport) -> str:
    from eth_hash.auto import keccak
    return "0x" + keccak(canonical_bytes(report)).hex()


# ---------- correlation (GET /clusters) ----------

class ClusterIndicator(Strict):
    type: IndicatorType
    value: str
    report_count: int = Field(description="How many member reports contain this indicator")


class Cluster(Strict):
    cluster_id: str
    label: str
    first_seen: datetime
    last_seen: datetime
    report_ids: list[str]
    top_classification: RiskClass
    shared_indicators: list[ClusterIndicator]
    member_domains: list[str]
    summary: str | None = Field(default=None, description="Two-sentence AI-written description; null when no LLM is configured")
    summary_model: str | None = None


class ImpersonationTrend(Strict):
    brand_id: str
    brand: str
    reports: int = Field(description="Stored reports at suspicious or worse that impersonate this brand")
    messages: int
    links: int
    first_seen: datetime
    last_seen: datetime
    report_ids: list[str] = Field(description="Most recent first, at most 10")


# ---------- API responses ----------

class AssessResponse(Strict):
    report_id: str
