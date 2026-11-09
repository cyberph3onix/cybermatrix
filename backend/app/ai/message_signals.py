"""LLM language signals for a message → heuristic MSG.* findings. The LLM may only choose from the allowed IDs."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.ai.llm import INJECTION_RULES, LlmClient, LlmUnavailable, untrusted
from app.checks.base import evidence, make_finding
from app.schemas import Finding, utcnow

ALLOWED = ("MSG.CREDENTIAL_REQUEST", "MSG.PAYMENT_REQUEST", "MSG.URGENCY", "MSG.AUTHORITY_IMPERSONATION",
           "MSG.REWARD_LURE")
TITLES = {
    "MSG.CREDENTIAL_REQUEST": ("Message asks for a code, PIN or password", "Legitimate organisations never ask for these in a message."),
    "MSG.PAYMENT_REQUEST": ("Message asks you to pay or approve a payment", "Scammers use payment requests to take money."),
    "MSG.URGENCY": ("Message pressures you with a deadline or threat", "Pressure is used to stop you thinking."),
    "MSG.AUTHORITY_IMPERSONATION": ("Message claims to come from an organisation", "Check the organisation through its official app or website."),
    "MSG.REWARD_LURE": ("Message offers a prize, refund or job", "Unexpected rewards are a common lure."),
}
SYSTEM = (
    "You label language signals in a possibly fraudulent message. " + INJECTION_RULES + " "
    "Only report a signal when the message text clearly shows it, and quote a short supporting phrase (max 80 chars). "
    "You do not decide whether the message is a scam."
)


class Signal(BaseModel):
    model_config = ConfigDict(extra="ignore")
    check_id: str
    quote: str = Field(max_length=200)


class SignalsOut(BaseModel):
    model_config = ConfigDict(extra="ignore")
    signals: list[Signal] = Field(default_factory=list, max_length=10)


async def llm_signals(llm: LlmClient, redacted: str) -> list[Finding]:
    """Raises LlmUnavailable on any LLM or validation failure. Unknown check_ids are dropped; strength is forced
    to heuristic by the catalogue (make_finding never takes strength from the caller)."""
    raw = await llm.call_tool(system=SYSTEM, user=untrusted(redacted[:6000]),
                              tool_name="report_signals", schema=SignalsOut.model_json_schema())
    try:
        out = SignalsOut.model_validate(raw)
    except ValidationError:
        raise LlmUnavailable("llm output failed schema validation") from None
    findings, seen = [], set()
    for s in out.signals:
        if s.check_id not in ALLOWED or s.check_id in seen:
            continue
        seen.add(s.check_id)
        title, advice = TITLES[s.check_id]
        findings.append(make_finding(
            s.check_id, title, [evidence("text_span", f"Model-identified phrase: “{s.quote[:80]}”", f"llm:{llm.model}",
                                         {"quote": s.quote[:80]}, observed_at=utcnow())],
            "Language like this is common in scams but also appears in genuine messages.", advice,
            limitation="Identified by an AI model from the redacted text; a weak signal on its own."))
    return findings
