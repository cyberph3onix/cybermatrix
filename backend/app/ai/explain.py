"""AI explanation of a finished report. The model only explains: it cannot change class, score or findings."""
from __future__ import annotations

import json
import re

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.ai.injection import has_injection
from app.ai.llm import INJECTION_RULES, LlmClient, LlmUnavailable
from app.schemas import AIExplanation, AssessmentReport

SYSTEM = (
    "You explain a security assessment to a non-technical person in 2-4 plain sentences. " + INJECTION_RULES + " "
    "The classification and findings were computed by deterministic rules; do not contradict or re-decide them. "
    "List in verified_evidence_refs only check_ids you relied on from the findings JSON."
)
_SAFE = re.compile(r"(?<!un)\bsafe(?:ly|ty)?\b", re.IGNORECASE)
_PRODUCT = re.compile(r"\bsafe\s+browsing\b", re.IGNORECASE)  # "Google Safe Browsing" is a name, not a verdict
INJECTION_NOTE = " This content contained instructions directed at automated systems; they were ignored."


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
    facts = {"classification": str(report.classification), "reason": report.classification_reason,
             "coverage_percent": report.coverage.percent,
             "findings": [{"check_id": f.check_id, "title": f.title, "severity": str(f.severity),
                           "strength": str(f.strength)} for f in report.findings]}
    user = f"Findings JSON:\n{json.dumps(facts)}"
    if untrusted_text:
        user += f"\n\nSubmitted text (redacted):\n<untrusted_input>\n{untrusted_text[:6000]}\n</untrusted_input>"
    raw = await llm.call_tool(system=SYSTEM, user=user, tool_name="explain", schema=ExplainOut.model_json_schema())
    try:
        out = ExplainOut.model_validate(raw)
    except ValidationError:
        raise LlmUnavailable("llm output failed schema validation") from None
    known = {f.check_id for f in report.findings}
    refs = [r for r in dict.fromkeys(out.verified_evidence_refs) if r in known]  # drop anything not in the report
    summary = out.summary.strip()
    if _SAFE.search(_PRODUCT.sub("", summary)):  # rule 3: never output "safe"
        summary = fallback_summary(report)
    if injected:
        summary += INJECTION_NOTE
    return AIExplanation(model=llm.model, summary=summary, verified_evidence_refs=refs,
                         language_signals=[f.check_id for f in report.findings if f.check_id.startswith("MSG.")
                                           and f.evidence[0].source.startswith("llm:")],
                         injection_attempt_detected=injected)
