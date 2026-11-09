"""Risk classification per docs/RISK_ENGINE.md §2-§5. Deterministic; the LLM never decides a verdict."""
from __future__ import annotations

from dataclasses import dataclass, field

from app.brands import BrandIndex
from app.schemas import Confidence, Finding, RiskClass
from app.urlutil import URLParseError, parse_url

POINTS = {"critical": 50, "high": 25, "medium": 10, "low": 3, "info": 0}
HEURISTIC_CAP = 30
SCORE_CAP = 100
SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
R5_TEXT = "No significant malicious indicators within the checks performed."
IMPERSONATION_IDS = ("URL.LOOKALIKE.HOMOGLYPH", "URL.BRAND_IN_SUBDOMAIN")
FRESHNESS_IDS = ("DOMAIN.YOUNG", "TLS.CERT_VERY_NEW")


@dataclass
class Verdict:
    classification: RiskClass
    reason: str
    score: int
    confidence: Confidence


@dataclass
class Dampening:
    kept: list[Finding]
    dropped: list[Finding] = field(default_factory=list)

    @property
    def dropped_ids(self) -> list[str]:
        return [f.check_id for f in self.dropped]


def _is_posture(f: Finding) -> bool:
    return f.category == "security_posture" or f.check_id.startswith("POSTURE.")


def _host_path(f: Finding, key_host: str = "url") -> tuple[str, str] | None:
    data = f.evidence[0].data if f.evidence else {}
    if key_host == "final":
        h = data.get("final_host")
        return (h, data.get("final_path") or "/") if h else None
    u = data.get("url")
    if not u:
        return None
    try:
        p = parse_url(u)
    except URLParseError:
        return None
    return p.host, p.path or "/"


def dampen(findings: list[Finding], idx: BrandIndex, submitted_host: str, submitted_path: str = "/") -> Dampening:
    """Allowlist dampening (§5). Gate: official brand domain or Tranco top 10k, and NOT an abusable host.

    Dropped on allowlisted hosts: URL.LOOKALIKE.*, DOMAIN.*, URL.KEYWORDS, path-only URL.BRAND_IN_SUBDOMAIN, and
    REDIRECT.CROSS_DOMAIN when the *final* host is allowlisted. Never dropped: threat intel, TLS, subdomain brand
    matches, page findings.
    """
    out = Dampening(kept=[])
    for f in findings:
        cid = f.check_id
        if ".INTEL." in cid or cid.startswith(("TLS.", "CORR.")):
            out.kept.append(f)
            continue
        drop = False
        if cid == "REDIRECT.CROSS_DOMAIN":
            hp = _host_path(f, "final")
            drop = hp is not None and idx.allowlisted(*hp)
        elif cid.startswith(("URL.LOOKALIKE.", "DOMAIN.")) or cid == "URL.KEYWORDS" or (
                cid == "URL.BRAND_IN_SUBDOMAIN" and f.evidence[0].data.get("match_location") == "path"):
            hp = _host_path(f) or (submitted_host, submitted_path)
            drop = idx.allowlisted(*hp)
        (out.dropped if drop else out.kept).append(f)
    return out


def score(findings: list[Finding]) -> int:
    heur = tech = 0
    for f in findings:
        if _is_posture(f):
            continue
        pts = POINTS[f.severity]
        if f.strength == "heuristic":
            heur += pts
        else:
            tech += pts
    return min(SCORE_CAP, tech + min(HEURISTIC_CAP, heur))


def _fmt(rule: str, ids: list[str]) -> str:
    seen = list(dict.fromkeys(ids))
    return f"{rule}: {' + '.join(seen)}" if seen else rule


def classify(findings: list[Finding], coverage_percent: int) -> Verdict:
    fs = [f for f in findings if not _is_posture(f)]
    s = score(fs)
    ids = {f.check_id for f in fs}

    def conf(cls: RiskClass) -> Confidence:
        if coverage_percent >= 80 and (
                any(f.strength == "authoritative" for f in fs)
                or sum(f.strength == "technical" for f in fs) >= 2
                or cls == RiskClass.LOW_RISK):
            return Confidence.HIGH
        if coverage_percent >= 50:
            return Confidence.MEDIUM
        return Confidence.LOW

    def v(cls: RiskClass, reason: str) -> Verdict:
        return Verdict(cls, reason, s, conf(cls))

    r1 = [f.check_id for f in fs if f.strength == "authoritative" and f.severity == "critical"]
    if r1:
        return v(RiskClass.CONFIRMED_MALICIOUS, _fmt("R1", r1))

    imp = [i for i in IMPERSONATION_IDS if i in ids]
    fresh = [i for i in FRESHNESS_IDS if i in ids]
    if imp and "PAGE.CREDENTIAL_FORM" in ids and fresh:
        return v(RiskClass.CONFIRMED_MALICIOUS, _fmt("R1b", [imp[0], "PAGE.CREDENTIAL_FORM", fresh[0]]))

    crit_tech = [f.check_id for f in fs if f.strength == "technical" and f.severity == "critical"]
    # strength >= technical: an authoritative high finding (TLS.REMOVED_ROOT) counts as at least technical
    high_tech = [f.check_id for f in fs if f.strength in ("technical", "authoritative") and f.severity == "high"]
    if s >= 60 or crit_tech or len(high_tech) >= 2:
        if crit_tech:
            return v(RiskClass.HIGH_RISK, _fmt("R2", crit_tech))
        if len(high_tech) >= 2:
            return v(RiskClass.HIGH_RISK, _fmt("R2", high_tech))
        return v(RiskClass.HIGH_RISK, _fmt(f"R2 (score {s})", _by_severity(fs)))

    medium_up = [f.check_id for f in fs if SEV_RANK[f.severity] >= SEV_RANK["medium"]]
    if s >= 20 or medium_up:
        return v(RiskClass.SUSPICIOUS, _fmt("R3", medium_up or _by_severity(fs)))

    if coverage_percent < 50:
        return v(RiskClass.INCONCLUSIVE, f"R4: coverage {coverage_percent}% is below 50%")

    return v(RiskClass.LOW_RISK, f"R5: {R5_TEXT}")


def _by_severity(fs: list[Finding]) -> list[str]:
    return [f.check_id for f in sorted(fs, key=lambda f: -SEV_RANK[f.severity]) if f.severity != "info"]
