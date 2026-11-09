"""Table-driven tests for every rule in docs/RISK_ENGINE.md §2-§5."""
import json
from pathlib import Path

import pytest

from app.checks.base import evidence, make_finding
from app.checks.catalogue import CATALOGUE
from app.engine import coverage as cov
from app.engine import risk
from app.schemas import AssessmentReport, CheckRun, Finding
from tests.conftest import fetch_result

FIX = Path(__file__).parent / "fixtures"


def F(check_id: str, **data) -> Finding:
    return make_finding(check_id, check_id, [evidence("test", "t", "test", data)], "i", "r")


def P(name="POSTURE.NO_HSTS") -> Finding:
    return Finding(check_id=name, title="p", category="security_posture", severity="high", strength="technical",
                   evidence=[evidence("http_header", "x", "local:headers")], impact="i", recommendation="r")


CASES = [
    # (name, findings, coverage, class, rule prefix, score)
    ("R1 intel", ["URL.INTEL.GSB"], 90, "confirmed_malicious", "R1: URL.INTEL.GSB", 50),
    ("R1 distrusted CA", ["TLS.DISTRUSTED_CA"], 30, "confirmed_malicious", "R1: TLS.DISTRUSTED_CA", 50),
    ("R1 revoked", ["TLS.REVOKED"], 60, "confirmed_malicious", "R1: TLS.REVOKED", 50),
    ("R1 VT majority", ["URL.INTEL.VT_MAJORITY"], 90, "confirmed_malicious", "R1", 50),
    ("R1 near-miss: removed root is high, not critical", ["TLS.REMOVED_ROOT"], 90, "suspicious", "R3", 25),
    ("R1b homoglyph", ["URL.LOOKALIKE.HOMOGLYPH", "PAGE.CREDENTIAL_FORM", "TLS.CERT_VERY_NEW"], 90,
     "confirmed_malicious", "R1b: URL.LOOKALIKE.HOMOGLYPH + PAGE.CREDENTIAL_FORM + TLS.CERT_VERY_NEW", 53),
    ("R1b subdomain", ["URL.BRAND_IN_SUBDOMAIN", "PAGE.CREDENTIAL_FORM", "DOMAIN.YOUNG"], 90,
     "confirmed_malicious", "R1b: URL.BRAND_IN_SUBDOMAIN + PAGE.CREDENTIAL_FORM + DOMAIN.YOUNG", 60),
    ("R1b near-miss: no freshness", ["URL.BRAND_IN_SUBDOMAIN", "PAGE.CREDENTIAL_FORM"], 90, "high_risk", "R2", 50),
    ("R1b near-miss: typosquat is not enough", ["URL.LOOKALIKE.TYPOSQUAT", "PAGE.CREDENTIAL_FORM", "DOMAIN.YOUNG"],
     90, "suspicious", "R3", 45),
    ("R2 two high technical", ["TLS.EXPIRED", "TLS.HOSTNAME_MISMATCH"], 90, "high_risk",
     "R2: TLS.EXPIRED + TLS.HOSTNAME_MISMATCH", 50),
    ("R2 score >= 60", ["PAGE.CREDENTIAL_FORM", "URL.IP_HOST", "URL.EMBEDDED_REDIRECT_PARAM", "REDIRECT.CROSS_DOMAIN",
                        "TLS.NO_HTTPS", "PAGE.BRAND_MISMATCH"], 90, "high_risk", "R2", 75),
    ("R2 authoritative high counts as >= technical (RC-4)", ["TLS.REMOVED_ROOT", "TLS.HOSTNAME_MISMATCH"], 90,
     "high_risk", "R2: TLS.REMOVED_ROOT + TLS.HOSTNAME_MISMATCH", 50),
    ("R2 near-miss: one high technical", ["TLS.SELF_SIGNED"], 90, "suspicious", "R3: TLS.SELF_SIGNED", 25),
    ("R3 one medium", ["URL.IP_HOST"], 90, "suspicious", "R3: URL.IP_HOST", 10),
    ("R3 medium heuristic", ["URL.INTEL.VT_MINORITY"], 90, "suspicious", "R3: URL.INTEL.VT_MINORITY", 10),
    ("R3 near-miss: lows only", ["URL.KEYWORDS", "URL.SHORTENER", "TLS.INCOMPLETE_CHAIN"], 90, "low_risk", "R5", 9),
    ("R4 low coverage, no findings", [], 40, "inconclusive", "R4", 0),
    ("R4 low coverage, low findings", ["URL.KEYWORDS"], 49, "inconclusive", "R4", 3),
    ("R3 beats R4: medium on low coverage", ["URL.LOOKALIKE.TYPOSQUAT"], 20, "suspicious", "R3", 10),
    ("R5 boundary coverage 50", [], 50, "low_risk", "R5: No significant malicious indicators", 0),
]


@pytest.mark.parametrize("name,ids,coverage,cls,reason,score", CASES, ids=[c[0] for c in CASES])
def test_rules(name, ids, coverage, cls, reason, score):
    v = risk.classify([F(i) for i in ids], coverage)
    assert v.classification == cls
    assert v.reason.startswith(reason), v.reason
    assert v.score == score


def test_heuristics_alone_never_exceed_suspicious():
    heuristic_ids = [k for k, m in CATALOGUE.items() if m.strength == "heuristic"]
    many = [F(i) for i in heuristic_ids] * 5
    v = risk.classify(many, 100)
    assert v.classification == "suspicious"
    assert v.score == risk.HEURISTIC_CAP


def test_heuristic_cap_does_not_cap_technical():
    v = risk.classify([F("URL.INTEL.VT_MINORITY")] * 5 + [F("TLS.EXPIRED")], 90)
    assert v.score == 30 + 25


def test_score_capped_at_100():
    assert risk.classify([F("URL.INTEL.GSB")] * 3, 90).score == 100


def test_security_posture_ignored():
    v = risk.classify([P(), P("POSTURE.NO_CSP")], 90)
    assert v.classification == "low_risk" and v.score == 0


@pytest.mark.parametrize("coverage,ids,expected", [
    (90, ["URL.INTEL.GSB"], "high"),
    (90, ["TLS.EXPIRED", "TLS.HOSTNAME_MISMATCH"], "high"),
    (90, [], "high"),  # low_risk with high coverage
    (90, ["URL.IP_HOST"], "medium"),  # one technical
    (79, ["URL.INTEL.GSB"], "medium"),
    (50, [], "medium"),
    (49, ["URL.IP_HOST"], "low"),
    (20, ["URL.LOOKALIKE.TYPOSQUAT"], "low"),
])
def test_confidence(coverage, ids, expected):
    assert risk.classify([F(i) for i in ids], coverage).confidence == expected


def test_sample_report_reclassifies():
    rep = AssessmentReport.model_validate(json.loads((FIX / "sample_report.json").read_text()))
    v = risk.classify(rep.findings + rep.security_posture, rep.coverage.percent)
    assert (v.classification, v.reason, v.score, v.confidence) == (
        rep.classification, rep.classification_reason, rep.score, rep.confidence)


# ---------------- dampening ----------------

def test_dampening_on_official_drops_heuristics_keeps_ti_and_tls(idx):
    fs = [F("URL.KEYWORDS", url="https://retail.sbi.bank.in/login"), F("DOMAIN.YOUNG"),
          F("URL.LOOKALIKE.TYPOSQUAT"), F("URL.INTEL.GSB"), F("TLS.EXPIRED"), F("PAGE.FORM_ACTION_CROSS_DOMAIN")]
    d = risk.dampen(fs, idx, "retail.sbi.bank.in")
    assert set(d.dropped_ids) == {"URL.KEYWORDS", "DOMAIN.YOUNG", "URL.LOOKALIKE.TYPOSQUAT"}
    assert {f.check_id for f in d.kept} == {"URL.INTEL.GSB", "TLS.EXPIRED", "PAGE.FORM_ACTION_CROSS_DOMAIN"}


def test_dampening_on_tranco(idx):
    d = risk.dampen([F("URL.KEYWORDS"), F("DOMAIN.SUSPICIOUS_TLD")], idx, "www.amazon.in")
    assert d.kept == []


def test_abusable_host_never_dampened(idx):
    fs = [F("URL.KEYWORDS"), F("DOMAIN.YOUNG")]
    assert risk.dampen(fs, idx, "sites.google.com", "/view/sbi-kyc").dropped == []
    assert risk.dampen(fs, idx, "evil.github.io").dropped == []
    assert risk.dampen(fs, idx, "docs.google.com", "/forms/d/e/x").dropped == []


def test_no_dampening_on_unknown(idx):
    assert risk.dampen([F("URL.KEYWORDS")], idx, "kyc-verify-now.top").dropped == []


def test_brand_in_path_dampened_on_allowlisted_but_subdomain_never(idx):
    path = F("URL.BRAND_IN_SUBDOMAIN", match_location="path",
             url="https://web.archive.org/web/2024/https://sbi.co.in/")
    sub = F("URL.BRAND_IN_SUBDOMAIN", match_location="subdomain", url="https://sbi.co.in.archive.org/")
    assert risk.dampen([path], idx, "web.archive.org").dropped_ids == ["URL.BRAND_IN_SUBDOMAIN"]
    assert risk.dampen([sub], idx, "sbi.co.in.archive.org").dropped == []
    evil_path = F("URL.BRAND_IN_SUBDOMAIN", match_location="path", url="https://evil.xyz/sbi.co.in/login")
    assert risk.dampen([evil_path], idx, "evil.xyz").dropped == []


def _cross(final_url, idx):
    from app.checks import redirects
    fs = redirects.analyze("bit.ly", fetch_result(["https://bit.ly/x", final_url]), idx)
    return risk.dampen(fs, idx, "bit.ly", "/x")


def test_redirect_same_brand_official_no_finding(idx):
    from app.checks import redirects
    assert redirects.analyze("sbi.co.in", fetch_result(["https://sbi.co.in/", "https://sbi.bank.in/"]), idx) == []


def test_redirect_shortener_to_amazon_dampened(idx):
    d = _cross("https://www.amazon.in/dp/B0", idx)
    assert d.dropped_ids == ["REDIRECT.CROSS_DOMAIN"] and d.kept == []


def test_redirect_shortener_to_evil_fires(idx):
    d = _cross("https://evil.xyz/login", idx)
    assert [f.check_id for f in d.kept] == ["REDIRECT.CROSS_DOMAIN"]


def test_redirect_to_abusable_host_not_dampened(idx):
    d = _cross("https://sites.google.com/view/sbi-kyc", idx)
    assert [f.check_id for f in d.kept] == ["REDIRECT.CROSS_DOMAIN"]


# ---------------- coverage ----------------

def run(group, status):
    return CheckRun(check_group=group, status=status, source="t", duration_ms=0, weight=cov.weight(group))


def test_coverage_full():
    runs = [run(g, "completed") for g in cov.WEIGHTS]
    c = cov.compute(runs)
    assert c.percent == 100 and sorted(c.completed) == sorted(cov.WEIGHTS)


def test_coverage_table_totals():
    w = cov.WEIGHTS
    assert w["url.structure"] + w["url.lookalike"] == 10
    assert w["tls.chain"] + w["tls.revocation"] + w["tls.ct"] == 20
    assert sum(w[g] for g in w if g.startswith("intel.")) == 40
    assert sum(w.values()) == 100


def test_coverage_skipped_not_applicable():
    runs = [run("url.structure", "completed"), run("url.lookalike", "completed"), run("tls.chain", "skipped"),
            run("intel.gsb", "unavailable")]
    c = cov.compute(runs)
    assert c.percent == 50 and c.skipped == ["tls.chain"] and c.unavailable == ["intel.gsb"]


def test_coverage_duplicate_group_counts_once():
    runs = [run("url.structure", "completed"), run("url.structure", "completed"), run("intel.gsb", "failed")]
    assert cov.compute(runs).percent == 33


def test_coverage_empty():
    assert cov.compute([]).percent == 0
