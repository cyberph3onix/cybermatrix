"""AI explanation of a finished report. The model only explains: it cannot change class, score or findings."""
from __future__ import annotations

import json
import re

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.ai.injection import has_injection
from app.ai.llm import INJECTION_RULES, LlmClient, LlmUnavailable, untrusted
from app.schemas import AIExplanation, AssessmentReport

SYSTEM = (
    "You explain a security assessment to a non-technical person in 2-4 plain sentences. " + INJECTION_RULES + " "
    "The classification and findings were computed by deterministic rules; do not contradict or re-decide them. "
    "List in verified_evidence_refs only check_ids you relied on from the findings JSON."
)
_SAFE = re.compile(r"(?<!un)\bsafe(?:ly|ty)?\b", re.IGNORECASE)
_PRODUCT = re.compile(r"\bsafe\s+browsing\b", re.IGNORECASE)  # "Google Safe Browsing" is a name, not a verdict
# Reassurance the explainer must never give: the deterministic class is the only verdict, and even low_risk is
# "no significant indicators within the checks performed", not a clean bill of health.
_REASSURE = re.compile(
    r"\b(?:legit(?:imate)?|trust(?:worthy|ed)|genuine|authentic|harmless|benign|no (?:real )?(?:risk|threat|danger)|"
    r"(?:nothing|no need) to worry|not (?:a )?(?:scam|phishing|risky|dangerous|malicious)|fine to (?:use|visit|open)|"
    r"go ahead|you can (?:log ?in|sign ?in|proceed|continue|trust|enter))\b", re.IGNORECASE)
INJECTION_NOTE = " This content contained instructions directed at automated systems; they were ignored."


def reassures(text: str) -> bool:
    t = _PRODUCT.sub("", text)
    return bool(_SAFE.search(t) or _REASSURE.search(t))


class ExplainOut(BaseModel):
    model_config = ConfigDict(extra="ignore")
    summary: str = Field(max_length=1200)
    verified_evidence_refs: list[str] = Field(default_factory=list, max_length=30)


def fallback_summary(report: AssessmentReport) -> str:
    n = len(report.findings)
    return (f"Rule-based result: {str(report.classification).replace('_', ' ')} "
            f"({n} finding{'s' if n != 1 else ''}, {report.coverage.percent}% of checks completed).")


async def explain(llm: LlmClient, report: AssessmentReport, untrusted_text: str | None = None) -> AIExplanation:
    injected = has_injection(untrusted_text or "") or any(
        has_injection(e.description) for f in report.findings for e in f.evidence)
    # Trusted part: only values our code chose (IDs and enums). Titles interpolate page titles, LLM-extracted brand
    # names and domains, so they travel with the submitted text inside the untrusted block.
    facts = {"classification": str(getattr(report.classification, "value", report.classification)),
             "reason": report.classification_reason, "coverage_percent": report.coverage.percent,
             "findings": [{"check_id": f.check_id, "category": str(getattr(f.category, "value", f.category)),
                           "severity": str(getattr(f.severity, "value", f.severity)),
                           "strength": str(getattr(f.strength, "value", f.strength))} for f in report.findings]}
    data = "Finding titles:\n" + "\n".join(f"- {f.check_id}: {f.title[:200]}" for f in report.findings)
    if untrusted_text:
        data += f"\n\nSubmitted text (redacted):\n{untrusted_text[:6000]}"
    user = f"Findings JSON:\n{json.dumps(facts)}\n\n{untrusted(data)}"
    raw = await llm.call_tool(system=SYSTEM, user=user, tool_name="explain", schema=ExplainOut.model_json_schema())
    try:
        out = ExplainOut.model_validate(raw)
    except ValidationError:
        raise LlmUnavailable("llm output failed schema validation") from None
    known = {f.check_id for f in report.findings}
    refs = [r for r in dict.fromkeys(out.verified_evidence_refs) if r in known]  # drop anything not in the report
    summary = out.summary.strip()
    # Rule 3, and: a model that has just read an injection attempt doesn't get to write prose for the user.
    if injected or not summary or reassures(summary):
        summary = fallback_summary(report)
    if injected:
        summary += INJECTION_NOTE
    return AIExplanation(model=llm.model, summary=summary, verified_evidence_refs=refs,
                         language_signals=[f.check_id for f in report.findings if f.check_id.startswith("MSG.")
                                           and f.evidence[0].source.startswith("llm:")],
                         injection_attempt_detected=injected)
