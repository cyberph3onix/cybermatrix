"""Check metadata mirrored from docs/RISK_ENGINE.md §6 (the single source of truth).

tests/test_catalogue.py parses the doc and fails if this table drifts from it.
"""
from __future__ import annotations

from typing import NamedTuple


class Meta(NamedTuple):
    category: str
    severity: str
    strength: str


CATALOGUE: dict[str, Meta] = {
    "URL.INTEL.GSB": Meta("threat_intel", "critical", "authoritative"),
    "URL.INTEL.URLHAUS": Meta("threat_intel", "critical", "authoritative"),
    "URL.INTEL.OPENPHISH": Meta("threat_intel", "critical", "authoritative"),
    "URL.INTEL.VT_MAJORITY": Meta("threat_intel", "critical", "authoritative"),
    "URL.INTEL.VT_MINORITY": Meta("threat_intel", "medium", "heuristic"),
    "URL.LOOKALIKE.HOMOGLYPH": Meta("impersonation", "high", "technical"),
    "URL.LOOKALIKE.TYPOSQUAT": Meta("impersonation", "medium", "technical"),
    "URL.BRAND_IN_SUBDOMAIN": Meta("impersonation", "high", "technical"),
    "URL.PUNYCODE_MIXED_SCRIPT": Meta("impersonation", "high", "technical"),
    "URL.USERINFO_TRICK": Meta("phishing", "high", "technical"),
    "URL.IP_HOST": Meta("phishing", "medium", "technical"),
    "URL.EMBEDDED_REDIRECT_PARAM": Meta("redirect", "medium", "technical"),
    "URL.SHORTENER": Meta("redirect", "low", "heuristic"),
    "URL.KEYWORDS": Meta("phishing", "low", "heuristic"),
    "REDIRECT.CROSS_DOMAIN": Meta("redirect", "medium", "technical"),
    "REDIRECT.LONG_CHAIN": Meta("redirect", "high", "technical"),
    "DOMAIN.YOUNG": Meta("domain", "medium", "heuristic"),
    "DOMAIN.SUSPICIOUS_TLD": Meta("domain", "low", "heuristic"),
    "PAGE.CREDENTIAL_FORM": Meta("phishing", "high", "technical"),
    "PAGE.FORM_ACTION_CROSS_DOMAIN": Meta("phishing", "high", "technical"),
    "PAGE.BRAND_MISMATCH": Meta("impersonation", "medium", "technical"),
    "PAGE.LLM_CLAIMED_BRAND": Meta("impersonation", "medium", "heuristic"),
    "TLS.DISTRUSTED_CA": Meta("tls_trust", "critical", "authoritative"),
    "TLS.REMOVED_ROOT": Meta("tls_trust", "high", "authoritative"),
    "TLS.REVOKED": Meta("tls_trust", "critical", "authoritative"),
    "TLS.UNTRUSTED_ROOT": Meta("tls_trust", "high", "technical"),
    "TLS.SELF_SIGNED": Meta("tls_trust", "high", "technical"),
    "TLS.EXPIRED": Meta("tls_config", "high", "technical"),
    "TLS.NOT_YET_VALID": Meta("tls_config", "high", "technical"),
    "TLS.HOSTNAME_MISMATCH": Meta("tls_trust", "high", "technical"),
    "TLS.WEAK_KEY": Meta("tls_config", "high", "technical"),
    "TLS.WEAK_SIGNATURE": Meta("tls_config", "high", "technical"),
    "TLS.NO_HTTPS": Meta("phishing", "medium", "technical"),
    "TLS.CT_NOT_LOGGED": Meta("tls_trust", "medium", "technical"),
    "TLS.CT_UNEXPECTED_ISSUER": Meta("tls_trust", "medium", "heuristic"),
    "TLS.CERT_VERY_NEW": Meta("tls_trust", "low", "heuristic"),
    "TLS.INCOMPLETE_CHAIN": Meta("tls_config", "low", "technical"),
    "MSG.CREDENTIAL_REQUEST": Meta("social_engineering", "medium", "heuristic"),
    "MSG.PAYMENT_REQUEST": Meta("social_engineering", "medium", "heuristic"),
    "MSG.URGENCY": Meta("social_engineering", "low", "heuristic"),
    "MSG.AUTHORITY_IMPERSONATION": Meta("social_engineering", "low", "heuristic"),
    "MSG.REWARD_LURE": Meta("social_engineering", "low", "heuristic"),
    "MSG.SENDER_DOMAIN_MISMATCH": Meta("impersonation", "high", "technical"),
    "MSG.LINK_TEXT_MISMATCH": Meta("phishing", "high", "technical"),
    "CORR.VALIDATED_MATCH": Meta("correlation", "critical", "authoritative"),
    "CORR.PRIOR_REPORTS": Meta("correlation", "medium", "heuristic"),
    "CORR.SHARED_INFRA": Meta("correlation", "low", "heuristic"),
}

POSTURE_IDS = frozenset({
    "POSTURE.NO_HSTS", "POSTURE.NO_CSP", "POSTURE.NO_XFO", "POSTURE.NO_XCTO", "POSTURE.MIXED_CONTENT",
    "POSTURE.OLD_TLS_VERSION", "POSTURE.SERVER_BANNER_VERSION", "POSTURE.EXPOSED_FILE",
})

# Posture findings never score (RISK_ENGINE.md §2) and are reported in `security_posture`. Severity is only
# a display hint: low for a missing defence, info for observations.
POSTURE_META: dict[str, Meta] = {
    "POSTURE.NO_HSTS": Meta("security_posture", "low", "technical"),
    "POSTURE.NO_CSP": Meta("security_posture", "low", "technical"),
    "POSTURE.NO_XFO": Meta("security_posture", "low", "technical"),
    "POSTURE.NO_XCTO": Meta("security_posture", "low", "technical"),
    "POSTURE.MIXED_CONTENT": Meta("security_posture", "low", "technical"),
    "POSTURE.OLD_TLS_VERSION": Meta("security_posture", "low", "technical"),
    "POSTURE.SERVER_BANNER_VERSION": Meta("security_posture", "info", "technical"),
    "POSTURE.EXPOSED_FILE": Meta("security_posture", "medium", "technical"),
}
assert set(POSTURE_META) == POSTURE_IDS
