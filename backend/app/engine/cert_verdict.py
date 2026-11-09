"""Certificate security verdict (Module 2): valid / suspicious / potentially_compromised.

A pure function of the report's TLS findings, so it is not stored in (or hashed with) the report: anyone holding
report.json can recompute it. It describes the certificate only and never changes the phishing classification.
"""
from __future__ import annotations

from app.schemas import AssessmentReport, CertificateVerdict, Finding

SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _is_tls(f: Finding) -> bool:
    return f.check_id.startswith("TLS.") or f.category in ("tls_trust", "tls_config")


def certificate_verdict(report: AssessmentReport) -> CertificateVerdict:
    tls = [f for f in report.findings if _is_tls(f)]
    compromised = [f.check_id for f in tls if f.category == "tls_trust" and f.strength == "authoritative"]
    concerning = [f.check_id for f in tls if f.check_id not in compromised and SEV_RANK[f.severity] >= SEV_RANK["medium"]]
    if compromised:
        verdict, reasons = "potentially_compromised", compromised
    elif concerning:
        verdict, reasons = "suspicious", concerning
    else:
        verdict, reasons = "valid", []
    return CertificateVerdict(
        report_id=report.report_id,
        verdict=verdict,
        reasons=list(dict.fromkeys(reasons)),
        trust_findings=[f.check_id for f in tls if f.category == "tls_trust"],
        config_findings=[f.check_id for f in tls if f.category == "tls_config"],
        certificate_checked=report.certificate is not None,
    )
